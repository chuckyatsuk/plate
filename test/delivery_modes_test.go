package plate_test

// Granted-mode delivery ENFORCEMENT, proven end to end in the REAL service
// (HTTP handler + Postgres grants + signer + cache + the /v1/download byte edge
// + MinIO). Building on the decision layer, this proves the WALL:
//
//   - a live grant over an A/V asset yields a signed /v1/download URL that,
//     fetched WITHOUT a token (the signature is the authorization), 302s to a
//     presigned R2 GET that actually serves the transcoded bytes;
//   - REVOCATION stops an ALREADY-ISSUED A/V URL at the edge, within one cache
//     window (spec Q3.B guarantee ii — the non-negotiable test);
//   - a grant signature can NEVER mint an `original` raw-bytes download (the
//     owner/recipient boundary — the second non-negotiable test);
//   - a granted IMAGE URL is imgproxy-SIGNED (not /unsafe/), with exp in the path;
//   - `original` for the OWNER now resolves to a real signed /v1/download URL
//     (the former known-forgeable ?sig=… placeholder is gone) and that URL is
//     fetchable and 302s to bytes.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/test/harness"
)

// grantedAV finalizes a short A/V asset, drains the worker so its detail
// rendition exists, and returns (assetID). Helper for the A/V granted tests.
func (e *e2e) grantedAVAsset(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := harness.SynthVideo(t, filepath.Join(dir, "clip.mp4"), harness.Seconds(2), true)
	assetID := e.uploadAndFinalize(src, "video/mp4")
	e.drainWorker() // produce the detail rendition
	return assetID
}

func TestE2E_GrantedAV_LiveGrant_ServesBytesThroughDownloadEdge(t *testing.T) {
	e := newE2E(t, 720)
	assetID := e.grantedAVAsset(t)
	grantID := e.createGrant(time.Now().Add(time.Hour), assetID)

	res := e.resolveGrant(assetID, "detail", grantID)
	if res.Delivery == nil {
		t.Fatalf("live grant over ready A/V must resolve; got refusal %v", res.Reason)
	}
	if res.Delivery.Mode != "granted" {
		t.Fatalf("expected mode=granted; got %q", res.Delivery.Mode)
	}
	if !strings.Contains(res.Delivery.URL, "/v1/download/") || !strings.Contains(res.Delivery.URL, "sig=") {
		t.Fatalf("granted A/V URL must be a signed /v1/download URL; got %q", res.Delivery.URL)
	}

	// Fetch it WITHOUT a token — the signature is the authorization.
	status, loc := e.fetchDownload(downloadPath(res.Delivery.URL))
	if status != 302 {
		t.Fatalf("valid signed download must 302; got %d", status)
	}
	// And the redirect target actually serves the transcoded bytes.
	bstatus, body := e.getBytes(loc)
	if bstatus != 200 || len(body) == 0 {
		t.Fatalf("presigned target must serve bytes; got HTTP %d, %d bytes", bstatus, len(body))
	}
}

// The non-negotiable test #1: revocation kills an ALREADY-ISSUED A/V URL.
func TestE2E_GrantedAV_RevocationKillsIssuedURL(t *testing.T) {
	e := newE2E(t, 720)
	assetID := e.grantedAVAsset(t)
	grantID := e.createGrant(time.Now().Add(time.Hour), assetID)

	res := e.resolveGrant(assetID, "detail", grantID)
	if res.Delivery == nil {
		t.Fatalf("grant should resolve before revocation")
	}
	dl := downloadPath(res.Delivery.URL)

	// The issued URL works now.
	if status, _ := e.fetchDownload(dl); status != 302 {
		t.Fatalf("issued URL should 302 before revocation; got %d", status)
	}

	e.revokeGrant(grantID)
	// Grant cache TTL is 50ms in the e2e; wait past one window (revocation is
	// eventually-consistent within one window, Q3.B — not instant).
	time.Sleep(120 * time.Millisecond)

	// The SAME already-issued URL must now be refused at the edge — this is the
	// whole point: revocation reaches links already handed out.
	if status, loc := e.fetchDownload(dl); status != 403 {
		t.Fatalf("revoked grant must kill the issued URL (403); got %d, loc=%q", status, loc)
	}
}

// The non-negotiable test #2: a grant signature never yields raw bytes.
func TestE2E_GrantedMode_NeverYieldsOriginal(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	img := harness.SynthImage(t, dir, "pic.png", 400, 300)
	assetID := e.uploadAndFinalize(img, "image/png")
	grantID := e.createGrant(time.Now().Add(time.Hour), assetID)

	// Resolving `original` under a grant is refused (leak-safe), never a download.
	res := e.resolveGrant(assetID, "original", grantID)
	if res.Delivery != nil {
		t.Fatalf("a grant must never mint an original download; got %q", res.Delivery.URL)
	}
	if res.Reason == nil || *res.Reason != "unauthorized" {
		t.Fatalf("granted original must refuse with reason=unauthorized; got %v", res.Reason)
	}
}

func TestE2E_GrantedImage_IsImgproxySigned(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	img := harness.SynthImage(t, dir, "pic.png", 800, 600)
	assetID := e.uploadAndFinalize(img, "image/png")
	grantID := e.createGrant(time.Now().Add(time.Hour), assetID)

	res := e.resolveGrant(assetID, "lightbox", grantID)
	if res.Delivery == nil {
		t.Fatalf("live grant over image must resolve; got %v", res.Reason)
	}
	if res.Delivery.Mode != "granted" {
		t.Fatalf("expected mode=granted; got %q", res.Delivery.Mode)
	}
	// imgproxy-signed: NOT the /unsafe/ path, and exp is inside the signed path so
	// imgproxy enforces expiry at the byte edge.
	if strings.Contains(res.Delivery.URL, "/unsafe/") {
		t.Fatalf("granted image must be imgproxy-SIGNED, not /unsafe/; got %q", res.Delivery.URL)
	}
	if !strings.Contains(res.Delivery.URL, "/exp:") || !strings.Contains(res.Delivery.URL, "/plain/") {
		t.Fatalf("granted image must carry exp+plain in the signed path; got %q", res.Delivery.URL)
	}
}

func TestE2E_GrantedMode_ExpiredGrantRefuses(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	img := harness.SynthImage(t, dir, "pic.png", 800, 600)
	assetID := e.uploadAndFinalize(img, "image/png")
	grantID := e.createGrant(time.Now().Add(-time.Minute), assetID) // already expired

	res := e.resolveGrant(assetID, "lightbox", grantID)
	if res.Delivery != nil {
		t.Fatalf("expired grant must refuse; got %q", res.Delivery.URL)
	}
	if res.Reason == nil || *res.Reason != "unauthorized" {
		t.Fatalf("expired grant must refuse with reason=unauthorized; got %v", res.Reason)
	}
}

func TestE2E_GrantedMode_GrantNotCoveringAssetRefuses(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	covered := e.uploadAndFinalize(harness.SynthImage(t, dir, "a.png", 400, 300), "image/png")
	other := e.uploadAndFinalize(harness.SynthImage(t, dir, "b.png", 400, 300), "image/png")
	grantID := e.createGrant(time.Now().Add(time.Hour), covered)

	notCovered := e.resolveGrant(other, "lightbox", grantID)
	if notCovered.Delivery != nil {
		t.Fatalf("grant not covering the asset must refuse; got %q", notCovered.Delivery.URL)
	}
	if notCovered.Reason == nil || *notCovered.Reason != "unauthorized" {
		t.Fatalf("not-covered must refuse with reason=unauthorized; got %v", notCovered.Reason)
	}
	// Indistinguishable from a bogus grant id (no probing which assets a grant covers).
	bogus := e.resolveGrant(other, "lightbox", "01BOGUSGRANTIDDOESNOTEXIST")
	if bogus.Reason == nil || *bogus.Reason != "unauthorized" {
		t.Fatalf("missing grant must be indistinguishable (unauthorized); got %v", bogus.Reason)
	}
}

func TestE2E_OriginalNowSignedAndFetchable(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	img := harness.SynthImage(t, dir, "orig.png", 400, 300)
	assetID := e.uploadAndFinalize(img, "image/png")

	// original for the OWNER (token-authed resolve) is now a real signed
	// /v1/download URL — the former forgeable ?sig=… placeholder is gone.
	res := e.resolve(assetID, "original")
	if res.Delivery == nil {
		t.Fatalf("original must resolve for the owner; got %v", res.Reason)
	}
	if !strings.Contains(res.Delivery.URL, "/v1/download/") || !strings.Contains(res.Delivery.URL, "sig=") {
		t.Fatalf("original must now be a signed /v1/download URL; got %q", res.Delivery.URL)
	}
	// It is a genuine capability: fetch (no token) → 302 → bytes.
	status, loc := e.fetchDownload(downloadPath(res.Delivery.URL))
	if status != 302 {
		t.Fatalf("signed original download must 302; got %d", status)
	}
	if bstatus, body := e.getBytes(loc); bstatus != 200 || len(body) == 0 {
		t.Fatalf("original presigned target must serve bytes; got HTTP %d, %d bytes", bstatus, len(body))
	}
}

// A forged download — right shape, wrong/no signature — is refused at the edge.
func TestE2E_Download_ForgedSignatureRefused(t *testing.T) {
	e := newE2E(t, 720)
	assetID := e.grantedAVAsset(t)
	grantID := e.createGrant(time.Now().Add(time.Hour), assetID)
	res := e.resolveGrant(assetID, "detail", grantID)
	dl := downloadPath(res.Delivery.URL)

	// Tamper: flip the sig value. Must 403.
	forged := strings.Replace(dl, "sig=", "sig=deadbeef", 1)
	if status, _ := e.fetchDownload(forged); status != 403 {
		t.Fatalf("forged signature must be refused (403); got %d", status)
	}
	// Strip the signature entirely. Must 403.
	i := strings.Index(dl, "?")
	if status, _ := e.fetchDownload(dl[:i]); status != 403 {
		t.Fatalf("unsigned download must be refused (403); got %d", status)
	}
}
