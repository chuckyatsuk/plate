// Package storage is Plate's byte layer over R2 (spec §5.1, §5.3, Q5). R2 is
// S3-compatible, so this is an S3 client pointed at R2's endpoint — and a
// self-hoster points it at any S3 (spec Q5).
//
// The boundary this package enforces is the whole point of Plate's ingest model:
//   - Plate NEVER streams upload bytes (spec §5.1). It brokers a narrowly-scoped
//     presigned PUT (bound on key, content-type, and content-length range, spec
//     Q3.C) and the browser writes direct to R2. That preserves the
//     no-4.5MB-limit property a serverless request would break.
//   - Plate DOES hold credentials for the DERIVATIVE path only: the worker pulls
//     the vault original server-to-server and writes renditions. Small blast
//     radius (spec §5.1).
//   - Delivery returns URLs; Plate is not in the byte path for public/signed
//     modes (spec Q5).
//
// The account-isolation property lives in the KEY: a presigned PUT is bound to
// exactly `{account}/{asset-id}` (spec §3.2, §3.3), where account is the caller's
// TOKEN CLAIM. One account structurally cannot obtain a PUT into another's prefix
// — the worst bug this architecture can have (spec Q4), and why the MinIO test
// asserts the presign REJECTS a PUT to a different key/type/oversized body.
package storage

import (
	"context"
	"io"
	"time"
)

// PutConstraints are the bounds a presigned PUT is locked to (spec Q3.C). The
// browser can write EXACTLY one object matching these, and nothing else.
type PutConstraints struct {
	// Key is the exact object key, `{account}/{asset-id}`. The PUT is bound to it;
	// a PUT to any other key is rejected by the signature.
	Key string
	// ContentType the object must declare. Bound into the signature so a caller
	// cannot upload a different type than it asked for.
	ContentType string
	// ContentLength is the EXACT byte length the PUT must send, bound into the
	// signature. The browser must PUT exactly this many bytes; more OR fewer is
	// rejected (403). This is the honest shape of a presigned PUT: SigV4 signs an
	// exact content-length, not a range — a content-length *range* (spec Q3.C's
	// phrasing) is a presigned POST *policy* feature, not available on a PUT. So
	// the caller declares its exact size up front (the contract's
	// UploadRequest.size_bytes) and the PUT is locked to it, which bounds the
	// object just as tightly: it cannot be larger than declared. When 0, the
	// content-length is left unsigned (any size accepted) — used only where an
	// exact size is genuinely unknown.
	ContentLength int64
	// Expiry is how long the presigned URL is valid — generous for a studio's slow
	// connection (spec Q3.C: the current hour, learned the hard way).
	Expiry time.Duration
}

// PresignedPut is a URL the browser PUTs one object to, plus the headers it must
// send verbatim for the signature to validate.
type PresignedPut struct {
	URL     string
	Method  string // always "PUT"
	Headers map[string]string
	Expires time.Time
}

// ObjectInfo is what a HEAD reveals about a stored object — used by finalize to
// verify the upload actually landed and matches (spec §5.3).
type ObjectInfo struct {
	Size        int64
	ContentType string
	ETag        string
	Exists      bool
}

// Storage is the byte layer. Every method is server-to-server EXCEPT
// PresignPut/PresignGet, which mint URLs the browser uses directly.
type Storage interface {
	// PresignPut mints a narrowly-scoped presigned PUT (spec §5.1, Q3.C). The
	// caller passes the key already prefixed with its OWN account — this layer
	// does not know about accounts; the service builds the key from the token
	// claim (spec §3.3). Binding to the key/type/length is what makes the prefix
	// a real isolation boundary, not a naming convention.
	PresignPut(ctx context.Context, c PutConstraints) (PresignedPut, error)

	// PresignGet mints a short-lived authenticated download URL for a key — the
	// `intent=original` escape hatch (spec §4.1). Never a CDN URL.
	PresignGet(ctx context.Context, key string, expiry time.Duration) (string, error)

	// Head returns object metadata, or Exists=false if absent. Finalize uses it to
	// confirm the browser's PUT landed and to read the true size (spec §5.3).
	Head(ctx context.Context, key string) (ObjectInfo, error)

	// Get streams an object's bytes — the worker pulling a vault original.
	Get(ctx context.Context, key string) (ReadCloser, error)

	// GetRange streams only bytes [start, start+length) of an object — used by the
	// API's image probe to read just the header (~64KB) rather than downloading a
	// multi-hundred-MB original into a sub-100ms request (review ruling 1). Fewer
	// bytes than requested at EOF is normal.
	GetRange(ctx context.Context, key string, start, length int64) (ReadCloser, error)

	// Put writes bytes to a key — the worker writing a rendition. The reader
	// SHOULD be an io.ReadSeeker (e.g. an *os.File) so the SDK can sign and, if
	// needed, rewind the body; a non-seekable reader with a set ContentLength can
	// be sent as a zero-length body by the SDK (a silent empty write — the exact
	// bug the deployed smoke caught). Passing the concrete *os.File keeps Seek.
	Put(ctx context.Context, key, contentType string, r io.Reader, size int64) error

	// Delete removes an object — the reconciliation sweep and two-step delete
	// (spec §5.1, Q2).
	Delete(ctx context.Context, key string) error
}

// ReadCloser is the return type for Get/GetRange (io.ReadCloser under the hood).
type ReadCloser = io.ReadCloser
