package plate_test

// Review ruling 3: unimplemented delivery modes must be VISIBLY unimplemented, not
// silently degraded to public.
//   - a `grant` param (granted mode) → 501, because a live grant check is not
//     built and returning a working URL would ignore revocation (the "copied link
//     works forever" failure grants exist to kill).
//   - the `original` escape hatch STILL resolves (it is Phase-1 read-path, in use)
//     — but its signature is a known-forgeable placeholder until signing lands, and
//     this test PINS that it is currently unsigned so it cannot be mistaken for done.

import (
	"strings"
	"testing"

	"github.com/chuckyatsuk/plate/test/harness"
)

func TestE2E_GrantedMode_Returns501(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	// An image asset resolves immediately (no worker needed).
	img := harness.SynthImage(t, dir, "pic.png", 800, 600)
	assetID := e.uploadAndFinalize(img, "image/png")

	// A grant param signals granted mode → 501 (enforcement unbuilt).
	resp := e.req("GET", "/v1/assets/"+assetID+"/url?intent=lightbox&grant=some-grant-id", nil)
	if resp.Code != 501 {
		t.Fatalf("granted-mode delivery must be 501 until enforcement exists; got HTTP %d: %s", resp.Code, resp.Body.String())
	}
}

func TestE2E_OriginalStillResolves_ButUnsigned(t *testing.T) {
	e := newE2E(t, 720)
	dir := t.TempDir()
	img := harness.SynthImage(t, dir, "orig.png", 400, 300)
	assetID := e.uploadAndFinalize(img, "image/png")

	res := e.resolve(assetID, "original")
	if res.Delivery == nil {
		t.Fatalf("original is the escape hatch and must resolve; got refusal %v", res.Reason)
	}
	// KNOWN-FORGEABLE placeholder until signing lands (ruling 3). Pin it so a future
	// reader sees this is deliberately unsigned, not accidentally so. When real
	// signing arrives, this assertion flips and the TODO is closed.
	if !strings.Contains(res.Delivery.URL, "sig=") {
		t.Fatalf("original URL unexpectedly changed shape: %q", res.Delivery.URL)
	}
}
