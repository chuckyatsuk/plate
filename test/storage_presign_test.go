package plate_test

// The write path's storage boundary, verified against REAL S3 semantics on an
// ephemeral MinIO container (spec §5.1, Q3.C, Q5) — no live R2, no credentials.
//
// The house rule, applied to the credential-bearing path: don't assert "the
// presign was configured with bounds" — issue a REAL presigned PUT and prove the
// bounds are ENFORCED. A presign that constrains nothing would sail through its
// happy path and prove nothing; so this asserts the NEGATIVE (condition C2), the
// way the isolation test asserts B-absent:
//   - a PUT to a DIFFERENT key than signed is rejected
//   - a PUT declaring a DIFFERENT content-type than signed is rejected
//   - a PUT whose body size differs from the signed content-length is rejected
//
// Note on content-length (spec Q3.C, the R2/presign reality): a presigned PUT
// signs an EXACT content-length, not a range — a range is a presigned POST
// policy feature. So the caller declares its exact size up front and the PUT is
// locked to it; a body larger OR smaller than declared is rejected. That bounds
// the object exactly as tightly for the ceiling's purpose (it cannot exceed the
// declared size).
//
// The account-isolation stakes: the presigned key is `{account}/{asset-id}`. If a
// PUT to another key were accepted, one account could write into another's bucket
// prefix — the worst bug this architecture can have (spec Q4). This test is the
// storage-layer proof of the key-prefix property the conformance test asserts at
// the API layer.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/test/harness"
)

func TestPresignedPut_HappyPath_WritesExactlyTheSignedObject(t *testing.T) {
	m := harness.StartMinIO(t, "plate-test")
	ctx := context.Background()

	const key = "acct-a/01HAPPYPATHASSETID00000001"
	const ctype = "image/jpeg"
	body := []byte("not really a jpeg, but the bytes don't matter here")

	put, err := m.Storage.PresignPut(ctx, storage.PutConstraints{
		Key:           key,
		ContentType:   ctype,
		ContentLength: int64(len(body)), // exact declared size
		Expiry:        5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("presign: %v", err)
	}

	status := doPut(t, put.URL, ctype, body)
	if status < 200 || status >= 300 {
		t.Fatalf("signed PUT should succeed; got HTTP %d", status)
	}

	// It landed at exactly the signed key, with the right size.
	info, err := m.Storage.Head(ctx, key)
	if err != nil {
		t.Fatalf("head after put: %v", err)
	}
	if !info.Exists {
		t.Fatal("object not found at the signed key after a successful PUT")
	}
	if info.Size != int64(len(body)) {
		t.Fatalf("stored size %d != put size %d", info.Size, len(body))
	}
}

// The presign is bound to ONE key. A PUT to a different key with the same
// signature must be rejected — this is the isolation boundary at the byte layer.
func TestPresignedPut_RejectsDifferentKey(t *testing.T) {
	m := harness.StartMinIO(t, "plate-test")
	ctx := context.Background()

	body := []byte("hi")
	put, err := m.Storage.PresignPut(ctx, storage.PutConstraints{
		Key:           "acct-a/01ASSETAAAAAAAAAAAAAAAAAA",
		ContentType:   "image/jpeg",
		ContentLength: int64(len(body)), // exact, so KEY is the only violation under test
		Expiry:        5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("presign: %v", err)
	}

	// Rewrite the URL's path to point at account B's prefix — the cross-tenant
	// write attempt. The signature was computed for A's key, so it must fail.
	tampered := swapKeyInURL(put.URL, "acct-a/01ASSETAAAAAAAAAAAAAAAAAA", "acct-b/01ASSETBBBBBBBBBBBBBBBBBB")
	status := doPut(t, tampered, "image/jpeg", body)
	if status >= 200 && status < 300 {
		t.Fatalf("a PUT to a DIFFERENT key than signed succeeded (HTTP %d) — one account could write into another's prefix (spec Q4)", status)
	}

	// And B's key must NOT exist as a result.
	if info, _ := m.Storage.Head(ctx, "acct-b/01ASSETBBBBBBBBBBBBBBBBBB"); info.Exists {
		t.Fatal("cross-account object was written despite the presign binding")
	}
}

// The presign binds content-type. A PUT declaring a different type must fail.
func TestPresignedPut_RejectsDifferentContentType(t *testing.T) {
	m := harness.StartMinIO(t, "plate-test")
	ctx := context.Background()

	body := []byte("payload")
	put, err := m.Storage.PresignPut(ctx, storage.PutConstraints{
		Key:           "acct-a/01CTYPEASSET0000000000000",
		ContentType:   "image/jpeg",
		ContentLength: int64(len(body)), // exact, so TYPE is the only violation under test
		Expiry:        5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("presign: %v", err)
	}

	// Send a different Content-Type than was signed.
	status := doPut(t, put.URL, "application/x-evil", body)
	if status >= 200 && status < 300 {
		t.Fatalf("a PUT declaring a different content-type than signed succeeded (HTTP %d); the type bound is not enforced (spec Q3.C)", status)
	}
}

// The presign binds content-length. A body larger than the signed length must
// fail — the ceiling that stops a brokered upload from writing an unbounded
// object (spec Q3.C).
func TestPresignedPut_RejectsOversizedBody(t *testing.T) {
	m := harness.StartMinIO(t, "plate-test")
	ctx := context.Background()

	const declaredBytes = 16
	put, err := m.Storage.PresignPut(ctx, storage.PutConstraints{
		Key:           "acct-a/01SIZEASSET00000000000000",
		ContentType:   "application/octet-stream",
		ContentLength: declaredBytes, // exact declared size
		Expiry:        5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("presign: %v", err)
	}

	oversized := bytes.Repeat([]byte("A"), declaredBytes*4)
	status := doPut(t, put.URL, "application/octet-stream", oversized)
	if status >= 200 && status < 300 {
		t.Fatalf("a PUT whose body (%d B) exceeds the signed content-length (%d B) succeeded (HTTP %d); the length bound is not enforced (spec Q3.C)", len(oversized), declaredBytes, status)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// doPut issues a real HTTP PUT to a presigned URL — the browser's role in the
// broker model (Plate never streams the bytes, spec §5.1).
func doPut(t *testing.T, url, contentType string, body []byte) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build PUT: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = int64(len(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// swapKeyInURL replaces the object key in a presigned URL's path, to attempt a
// PUT to a different key than was signed.
func swapKeyInURL(url, oldKey, newKey string) string {
	return strings.Replace(url, oldKey, newKey, 1)
}
