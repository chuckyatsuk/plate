// Package store is Plate's data layer. There is exactly ONE real implementation
// (Postgres, in postgres.go) — deliberately no in-memory co-equal, because an
// in-memory store that also enforced account scoping would just duplicate the
// exact guard under test, pass the conformance test, and prove nothing about the
// SQL that ships. Cross-account leaks are overwhelmingly query bugs (a dropped
// `WHERE account = $1`, a join that widened scope), so the isolation guarantee
// must be proven against real SQL (spec §6, Q4).
//
// The interface exists so the service is testable and swappable, and so the
// read-path delivery logic (intent → URL, the clamps) can be exercised without a
// database — that logic does not touch the store.
package store

import (
	"context"
	"errors"
	"time"

	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// ErrNotFound is returned when no row matches for THIS account. The service maps
// it to a 404 whose body names nothing about any other account — the leak-safe
// answer for a resource the caller may not even know exists (spec: NotFound is
// "No such resource for this account"). Crucially, a resource owned by another
// account is indistinguishable from one that does not exist: both are NotFound.
var ErrNotFound = errors.New("store: not found for this account")

// ErrForeignAsset is returned when a write references an asset the caller does
// not own (e.g. creating a grant over another account's assets). The service
// maps it to a denial without echoing the foreign id.
var ErrForeignAsset = errors.New("store: asset not owned by this account")

// ErrUnknownAccount is returned when a write references an account that has no
// row yet (uploads.account's FK). It means the account was never provisioned
// (`plate accounts create`), NOT a server fault — the service maps it to a
// legible 4xx, never a 500 (spec Q2, account lifecycle is out-of-band).
var ErrUnknownAccount = errors.New("store: account has not been provisioned")

// Store is the account-scoped read path (Phase 1) plus the seams the isolation
// conformance test drives across every endpoint. EVERY method takes the caller's
// account as its first argument — the account the service derived from the token
// claim — and every query predicates on it. There is no method that can be
// called without an account, by construction.
type Store interface {
	// GetAsset returns the asset if it exists AND belongs to account; otherwise
	// ErrNotFound. A B-owned asset requested by A is ErrNotFound, not a 200.
	GetAsset(ctx context.Context, account, assetID string) (plate.Asset, error)

	// ListAssets returns a page of the account's own assets. Scoped to account;
	// there is no cross-account listing.
	ListAssets(ctx context.Context, account string, cursor string, limit int32) (plate.AssetPage, error)

	// MarkAssetDeleted marks an owned asset for async deletion (two-step, spec
	// Q2). ErrNotFound if not owned. Returns the marked asset.
	MarkAssetDeleted(ctx context.Context, account, assetID string) (plate.Asset, error)

	// GetJob returns a job if it belongs to account; otherwise ErrNotFound.
	GetJob(ctx context.Context, account, jobID string) (plate.Job, error)

	// GetGrant returns a grant if it belongs to account; otherwise ErrNotFound.
	GetGrant(ctx context.Context, account, grantID string) (plate.Grant, error)

	// RevokeGrant revokes an owned grant; ErrNotFound if not owned.
	RevokeGrant(ctx context.Context, account, grantID string) (plate.Grant, error)

	// CreateGrant creates a grant over a set of assets. It verifies EVERY asset
	// in the set belongs to account; any foreign asset → ErrForeignAsset (no
	// partial grant, and no leak of which asset was foreign).
	CreateGrant(ctx context.Context, account string, req plate.GrantRequest) (plate.Grant, error)

	// ResolveGrantForDelivery looks a grant up BY GRANT ID ALONE — deliberately
	// NOT account-scoped — because a grant IS the capability: it carries its own
	// account, and granted delivery is the share-link case where the resolving
	// caller need not be the grant's owner (spec Q3.B). It reports whether the
	// grant exists, is live (not revoked AND not expired), and covers assetID.
	// The grant's own account is returned so the caller can build the delivery
	// URL against the right key space; it is never taken from the request. This
	// is the one intentional exception to "every method takes account first", and
	// it grants no cross-account read: it returns only a verdict + the grant's
	// account, and the handler still resolves the asset under THAT account.
	ResolveGrantForDelivery(ctx context.Context, grantID, assetID string) (GrantVerdict, error)

	// AssetOwnedBy reports whether assetID exists and belongs to account. Used by
	// endpoints that key off an asset id in the path (delivery, requestRendition,
	// finalizeUpload) before doing their work.
	AssetOwnedBy(ctx context.Context, account, assetID string) (bool, error)

	// ── write path (Phase 2) ────────────────────────────────────────────────

	// CreateUpload records a brokered upload the caller is about to PUT (spec
	// §5.1). Account-scoped: the row carries the caller's account (its token
	// claim), and the key is {account}/{id} — the isolation boundary at ingest.
	CreateUpload(ctx context.Context, account string, u Upload) error

	// GetUpload returns a pending upload if it belongs to account; else ErrNotFound.
	// finalizeUpload uses it to recover the key/type/size to verify against R2.
	GetUpload(ctx context.Context, account, uploadID string) (Upload, error)

	// FinalizeUpload creates the asset + vault object from a finalized upload and
	// its probed metadata, and marks the upload finalized — in ONE transaction, so
	// there is no "asset created but upload not marked" split (spec §5.3). Scoped
	// to account. Returns the created asset.
	FinalizeUpload(ctx context.Context, account, uploadID string, v VaultRecord) (plate.Asset, error)

	// ReclaimableUploads returns uploads that were never finalized and are older
	// than the grace window — the orphans the reconciliation sweep cleans up (spec
	// §5.1). The sweep itself is Phase 2b (the worker); this read exists now so the
	// requirement is HELD by a test (decision D5), not just a table.
	ReclaimableUploads(ctx context.Context, olderThan time.Time, limit int32) ([]Upload, error)

	// EnqueueJob queues an A/V derivation job for an owned asset (spec §5.2).
	// Idempotent per (asset, intent). Account-scoped; the caller confirms
	// ownership before enqueue.
	EnqueueJob(ctx context.Context, account, assetID string, intent plate.Intent) (plate.Job, error)
}

// GrantVerdict is the outcome of resolving a grant for delivery. It exists to
// keep the reasons DISTINCT so the handler can answer honestly: an absent grant
// or one that does not cover the asset is a leak-safe not-found (a recipient
// must not be able to probe which grant ids or assets exist); a revoked or
// expired grant is a definite refusal with its own reason. Account is set only
// when the grant exists (regardless of liveness) — the delivery URL is built
// against it.
type GrantVerdict struct {
	Found   bool   // a grant with this id exists
	Covers  bool   // the grant's frozen set includes assetID
	Revoked bool   // revoked_at is set
	Expired bool   // expires <= now
	Account string // the grant's own account (empty if !Found)
}

// Live reports whether the grant may serve delivery right now: it must exist,
// cover the asset, and be neither revoked nor expired.
func (v GrantVerdict) Live() bool {
	return v.Found && v.Covers && !v.Revoked && !v.Expired
}

// Upload is a brokered upload record (spec §5.1). The account is derived from the
// caller's token, never a parameter.
type Upload struct {
	ID          string
	Account     string
	Key         string // {account}/{asset-id}
	ContentType string
	SizeBytes   int64
	Filename    string
}

// VaultRecord is the probed truth finalize writes onto the asset's vault object
// (spec §5.3): checksum + size from the stored object, dimensions/duration/codec/
// container from the probe.
type VaultRecord struct {
	Kind      plate.MediaKind
	Checksum  string // the verified checksum, or "" if not yet verified (never the raw client claim)
	SizeBytes int64
	Width     *int32
	Height    *int32
	DurationS *float64
	Codec     *string
	Container *string

	// ProbeStatus is "ready" (probed — images at finalize, documents trivially),
	// "pending" (A/V, probed later by the worker), or "failed". Empty defaults to
	// "ready" (review ruling 1).
	ProbeStatus string
	// ChecksumVerified is true only when the stored object's checksum was actually
	// confirmed (server-side at PUT, ETag compare, or worker hash) — never from an
	// unverified client claim (review ruling 2).
	ChecksumVerified bool
}
