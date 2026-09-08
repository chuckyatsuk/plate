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

	// AssetOwnedBy reports whether assetID exists and belongs to account. Used by
	// endpoints that key off an asset id in the path (delivery, requestRendition,
	// finalizeUpload) before doing their work.
	AssetOwnedBy(ctx context.Context, account, assetID string) (bool, error)
}
