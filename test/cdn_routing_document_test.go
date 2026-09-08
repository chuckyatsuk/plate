package plate_test

// Incident (spec §7): "a document/PDF never routes to ImageKit."
//
// The dated failure (spec §1, 2026-09-08): `document` was missing from the CDN
// bypass allowlist for as long as the type existed. Every PDF routed through the
// metered image CDN with no error and nothing in any log — discovered only when
// a press release turned up on an `ik.imagekit.io` URL. The rule: images go to
// the transforming CDN (it transforms them); everything the CDN would merely
// pass through goes to R2.
//
// This is the reason to centralise routing in Plate: the decision lives in ONE
// place that knows every media kind (spec §4.1), instead of an afterRead hook
// where a new kind silently falls through to a metered path.

import (
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/support"
)

func TestDocument_RoutesToR2_NotImageCDN(t *testing.T) {
	host, err := support.RouteDelivery(plate.Document)
	if err != nil {
		t.Fatalf("document is unroutable: %v", err)
	}
	if host == support.HostImageCDN {
		t.Fatal("a document routed to the metered image CDN — this is the exact 2026-09-08 incident (a PDF served from ik.imagekit.io)")
	}
	if host != support.HostR2 {
		t.Fatalf("document routed to %s, want r2", host)
	}
}

// Video and audio are the other passthrough kinds — the 528-VPU incident was
// ImageKit auto-transcoding AV on first delivery (spec §1). They must serve from
// R2, never through a processing CDN.
func TestAV_RoutesToR2_NotImageCDN(t *testing.T) {
	for _, kind := range []plate.MediaKind{plate.Video, plate.Audio} {
		host, err := support.RouteDelivery(kind)
		if err != nil {
			t.Fatalf("%s is unroutable: %v", kind, err)
		}
		if host != support.HostR2 {
			t.Errorf("%s routed to %s, want r2 — AV must never serve through a metered/transcoding CDN (spec meter-verification doctrine)", kind, host)
		}
	}
}

// The positive complement: images DO belong on the transforming CDN — that is
// what it is for. Guards a router that sends everything to R2 (which would pass
// the tests above for the wrong reason and lose image transforms).
func TestImage_RoutesToImageCDN(t *testing.T) {
	host, err := support.RouteDelivery(plate.Image)
	if err != nil {
		t.Fatalf("image is unroutable: %v", err)
	}
	if host != support.HostImageCDN {
		t.Fatalf("image routed to %s, want the transforming image CDN", host)
	}
}
