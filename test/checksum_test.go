package plate_test

// Review ruling 2: a field named checksum must never hold an unverified value.
// finalize verifies the client's md5:… claim against the object's ETag (a single-
// part PUT's ETag is the MD5); a matching claim is stored verified, a mismatched
// or absent one leaves the asset unverified rather than trusting the client.
//
// This drives the real service end to end and reads back checksum_verified from
// the DB (the API does not expose it — it is internal integrity state).

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"testing"

	"github.com/chuckyatsuk/plate/test/harness"
)

func TestE2E_Checksum_VerifiedAgainstETag(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()

	img := harness.SynthImage(t, dir, "sum.png", 300, 200)
	data, err := readFile(img)
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(data)
	claim := "md5:" + hex.EncodeToString(sum[:])

	assetID := e.uploadAndFinalizeWithChecksum(img, "image/png", claim)

	var verified bool
	if err := e.st.Pool().QueryRow(ctx,
		`SELECT checksum_verified FROM assets WHERE id = $1`, assetID).Scan(&verified); err != nil {
		t.Fatalf("read checksum_verified: %v", err)
	}
	if !verified {
		t.Fatal("a correct md5 claim matching the ETag should be recorded verified")
	}
}

func TestE2E_Checksum_WrongClaimNotStoredVerified(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()

	img := harness.SynthImage(t, dir, "sum2.png", 300, 200)
	// A deliberately wrong md5 claim.
	assetID := e.uploadAndFinalizeWithChecksum(img, "image/png", "md5:00000000000000000000000000000000")

	var verified bool
	if err := e.st.Pool().QueryRow(ctx,
		`SELECT checksum_verified FROM assets WHERE id = $1`, assetID).Scan(&verified); err != nil {
		t.Fatalf("read checksum_verified: %v", err)
	}
	if verified {
		t.Fatal("a wrong checksum claim must NOT be recorded verified — the field must never hold an unverified value")
	}
}
