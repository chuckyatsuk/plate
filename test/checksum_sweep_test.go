package plate_test

// P3, the sweep half: every vault object that is not hashed by a derive job
// (images, documents, skip_derivations A/V, and every asset that predates the
// batch) gets its SHA-256 from the worker's checksum sweep — streamed from
// storage, recorded as the verified vault checksum. The same pass is the
// backfill (`plate checksums run`).

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/store"
	"github.com/chuckyatsuk/plate/internal/worker"
	"github.com/chuckyatsuk/plate/test/harness"
)

func TestE2E_Checksum_ImageHashedBySweep(t *testing.T) {
	e := newE2E(t, 720)
	img := harness.SynthImage(t, t.TempDir(), "s.png", 300, 200)
	want := sha256File(t, img)
	assetID := e.uploadAndFinalize(img, "image/png") // unverifiable claim → unverified at finalize

	if v := vaultOf(t, e.assetJSON(assetID)); v["checksum"] != "" || v["checksum_verified"] != false {
		t.Fatalf("before the sweep: %v / %v, want empty + false", v["checksum"], v["checksum_verified"])
	}
	if n := e.runChecksumSweep(t); n != 1 {
		t.Fatalf("sweep hashed %d objects, want 1", n)
	}
	v := vaultOf(t, e.assetJSON(assetID))
	if v["checksum"] != want || v["checksum_verified"] != true {
		t.Fatalf("after the sweep: checksum %v verified %v, want %s + true", v["checksum"], v["checksum_verified"], want)
	}
	// Idempotent: nothing left to do.
	if n := e.runChecksumSweep(t); n != 0 {
		t.Fatalf("a second sweep re-hashed %d objects", n)
	}
}

// Today's md5 behaviour is unchanged for a client that declares one: finalize
// verifies it against the single-part ETag and answers md5:<hex> verified. The
// sweep then records the server-computed sha256 over it (same object, the
// digest Plate records for every object).
func TestE2E_Checksum_MD5ClaimStillVerifiedAtFinalize_ThenSHA256(t *testing.T) {
	e := newE2E(t, 720)
	img := harness.SynthImage(t, t.TempDir(), "m.png", 300, 200)
	data, err := readFile(img)
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(data)
	claim := "md5:" + hex.EncodeToString(sum[:])
	assetID := e.uploadAndFinalizeWithChecksum(img, "image/png", claim)

	var fin map[string]any
	if err := json.Unmarshal(e.lastFinalizeBody, &fin); err != nil {
		t.Fatal(err)
	}
	if v := vaultOf(t, fin); v["checksum"] != claim || v["checksum_verified"] != true {
		t.Fatalf("finalize with a matching md5 = %v / %v, want %s verified (unchanged behaviour)", v["checksum"], v["checksum_verified"], claim)
	}
	if n := e.runChecksumSweep(t); n != 1 {
		t.Fatalf("an md5-verified asset still gets its sha256: sweep hashed %d, want 1", n)
	}
	if v := vaultOf(t, e.assetJSON(assetID)); v["checksum"] != sha256File(t, img) || v["checksum_verified"] != true {
		t.Fatalf("after the sweep: %v / %v, want the sha256 verified", v["checksum"], v["checksum_verified"])
	}
}

// The sweep leaves an A/V original with a pending derive job to that job (it
// reads the same bytes), and never hashes a deleted asset.
func TestE2E_Checksum_SweepSkipsPendingDeriveAndDeleted(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	vid := e.uploadAndFinalize(harness.SynthVideo(t, filepath.Join(dir, "v.mp4"), harness.Seconds(1), false), "video/mp4")
	gone := e.uploadAndFinalize(harness.SynthImage(t, dir, "g.png", 64, 48), "image/png")
	if resp := e.req("DELETE", "/v1/assets/"+gone, nil); resp.Code != http.StatusAccepted {
		t.Fatalf("delete: %d", resp.Code)
	}
	if n := e.runChecksumSweep(t); n != 0 {
		t.Fatalf("sweep hashed %d objects; want 0 (video has a queued derive job, image is deleted)", n)
	}
	e.drainWorker()
	if v := vaultOf(t, e.assetJSON(vid)); v["checksum_verified"] != true {
		t.Fatalf("the derive job did not record the video's sha256: %v", v)
	}
	if v := vaultOf(t, e.assetJSON(gone)); v["checksum_verified"] != false {
		t.Fatalf("a deleted asset was hashed: %v", v)
	}
}

// A skip_derivations video has no derive job, so the sweep hashes it.
func TestE2E_Checksum_SkipDerivationsVideoHashedBySweep(t *testing.T) {
	e := newE2E(t, 720)
	src := harness.SynthVideo(t, filepath.Join(t.TempDir(), "a.mp4"), harness.Seconds(1), false)
	vid := e.uploadAndFinalizeOpts(src, "video/mp4", "md5:unverified-in-test", true)
	if n := e.runChecksumSweep(t); n != 1 {
		t.Fatalf("sweep hashed %d, want the archive-only video (1)", n)
	}
	if v := vaultOf(t, e.assetJSON(vid)); v["checksum"] != sha256File(t, src) {
		t.Fatalf("skip_derivations video checksum = %v, want its sha256", v["checksum"])
	}
}

// The backfill is resumable and a missing object is not fatal: it is counted,
// stamped, retried only after the back-off, and the rest still get hashed.
func TestE2E_Checksum_BackfillResumableAndSurvivesMissingObject(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	dir := t.TempDir()
	var ids []string
	for _, n := range []string{"a.png", "b.png", "c.png"} {
		ids = append(ids, e.uploadAndFinalize(harness.SynthImage(t, dir, n, 64, 48), "image/png"))
	}
	missing := ids[1]
	if err := e.stor.Storage.Delete(ctx, "vault/"+e.account+"/"+missing); err != nil {
		t.Fatal(err)
	}

	before, err := e.st.ChecksumBacklogStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Pending != 3 || before.Verified != 0 || before.PendingBytes <= 0 {
		t.Fatalf("backlog before = %+v, want 3 pending with bytes", before)
	}

	// A pass stopped after one object...
	cs := newTestChecksummer(e)
	res, err := cs.RunPass(ctx, 1)
	if err != nil || res.Hashed+res.Failed != 1 {
		t.Fatalf("bounded pass = %+v, %v; want exactly one object claimed", res, err)
	}
	// ...resumes where it stopped.
	res2, err := cs.RunPass(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Hashed+res2.Hashed != 2 || res.Failed+res2.Failed != 1 {
		t.Fatalf("passes = %+v then %+v; want 2 hashed and the missing object failed once", res, res2)
	}
	// The missing one is backing off, not retried on every pass.
	if res3, _ := cs.RunPass(ctx, 0); res3.Hashed+res3.Failed != 0 {
		t.Fatalf("an immediate third pass retried %+v; a failed object must back off", res3)
	}
	after, err := e.st.ChecksumBacklogStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Verified != 2 || after.Pending != 1 || after.Attempted != 1 {
		t.Fatalf("backlog after = %+v, want 2 verified, 1 pending (attempted)", after)
	}
	if v := vaultOf(t, e.assetJSON(missing)); v["checksum_verified"] != false {
		t.Fatalf("an unreadable object was recorded verified: %v", v)
	}
}

// An interrupted read (shutdown, an operator's Ctrl-C) is not a failed object:
// the claim is handed back, so the next pass hashes it at once rather than
// after the failure back-off.
func TestE2E_Checksum_InterruptedClaimIsReleased(t *testing.T) {
	e := newE2E(t, 720)
	id := e.uploadAndFinalize(harness.SynthImage(t, t.TempDir(), "i.png", 300, 200), "image/png")

	slow := worker.NewChecksummer(e.st, e.stor.Storage, slog.Default(), worker.ChecksumConfig{RateBytesPerSec: 64})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := slow.RunPass(ctx, 0); err == nil {
		t.Fatal("a pass cut off mid-object must report the interruption")
	}
	b, err := e.st.ChecksumBacklogStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b.Pending != 1 || b.Attempted != 0 {
		t.Fatalf("after an interrupted pass: %+v; want 1 pending and its claim released (attempted 0)", b)
	}
	if n := e.runChecksumSweep(t); n != 1 {
		t.Fatalf("the next pass hashed %d, want the interrupted object (1)", n)
	}
	if v := vaultOf(t, e.assetJSON(id)); v["checksum_verified"] != true {
		t.Fatalf("not verified after the resumed pass: %v", v)
	}
}

// A vault object is immutable: a different sha256 than the verified one on
// record is never written over it (it means the bytes changed or a read was
// corrupt), and the caller is told.
func TestE2E_Checksum_VerifiedSHA256NeverOverwritten(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	img := harness.SynthImage(t, t.TempDir(), "k.png", 64, 48)
	id := e.uploadAndFinalize(img, "image/png")
	if n := e.runChecksumSweep(t); n != 1 {
		t.Fatalf("sweep hashed %d", n)
	}
	real := sha256File(t, img)
	other := "sha256:" + strings.Repeat("0", 64)
	if err := e.st.MarkChecksumVerified(ctx, id, other); !errors.Is(err, store.ErrChecksumMismatch) {
		t.Fatalf("overwriting a verified sha256 with a different one = %v, want ErrChecksumMismatch", err)
	}
	if err := e.st.MarkChecksumVerified(ctx, id, real); err != nil {
		t.Fatalf("re-recording the same sha256 must be idempotent: %v", err)
	}
	if err := e.st.MarkChecksumVerified(ctx, id, "md5:abc"); err == nil {
		t.Fatal("MarkChecksumVerified must refuse anything but sha256:<64 hex>")
	}
	if v := vaultOf(t, e.assetJSON(id)); v["checksum"] != real {
		t.Fatalf("recorded checksum changed to %v", v["checksum"])
	}
}
