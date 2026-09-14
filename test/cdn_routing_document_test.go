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
//
// These drive the REAL routing table in internal/service (V2.1). They used to
// drive a reference stub in test/support, which meant production could have
// drifted onto a metered path with these tests still green — the very drift the
// incident is about.

import (
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/service"
)

func TestDocument_RoutesToR2_NotImageCDN(t *testing.T) {
	host, err := service.RouteDelivery(plate.Document, plate.Original)
	if err != nil {
		t.Fatalf("document is unroutable: %v", err)
	}
	if host == service.HostImageCDN {
		t.Fatal("a document routed to the metered image CDN — this is the exact 2026-09-08 incident (a PDF served from ik.imagekit.io)")
	}
	if host != service.HostR2 {
		t.Fatalf("document routed to %v, want r2", host)
	}
}

// Video and audio are the passthrough kinds for their A/V bytes — the 528-VPU
// incident was ImageKit auto-transcoding AV on first delivery (spec §1). Their
// A/V intents must serve from R2, never through a processing CDN.
//
// NOTE the scope: this asserts the A/V intents specifically. Since V2.1 a
// video's IMAGE intents (thumbnail/grid/lightbox) legitimately route to the
// image engine, because those serve its bounded POSTER — a still image — not
// video bytes. The 528-VPU rule is about A/V bytes reaching a transcoding CDN,
// and that remains absolutely forbidden below.
func TestAV_RoutesToR2_NotImageCDN(t *testing.T) {
	avIntents := []plate.Intent{plate.Poster, plate.Loop, plate.Detail}
	for _, intent := range avIntents {
		host, err := service.RouteDelivery(plate.Video, intent)
		if err != nil {
			t.Fatalf("(video, %s) is unroutable: %v", intent, err)
		}
		if host != service.HostR2 {
			t.Errorf("(video, %s) routed to %v, want r2 — AV bytes must never serve through a metered/transcoding CDN (spec meter-verification doctrine)", intent, host)
		}
	}
	// Audio's transcode likewise.
	host, err := service.RouteDelivery(plate.Audio, plate.Detail)
	if err != nil {
		t.Fatalf("(audio, detail) is unroutable: %v", err)
	}
	if host != service.HostR2 {
		t.Errorf("(audio, detail) routed to %v, want r2", host)
	}
}

// The positive complement: images DO belong on the transforming CDN — that is
// what it is for. Guards a router that sends everything to R2 (which would pass
// the tests above for the wrong reason and lose image transforms).
func TestImage_RoutesToImageCDN(t *testing.T) {
	for _, intent := range []plate.Intent{plate.Thumbnail, plate.Grid, plate.Lightbox} {
		host, err := service.RouteDelivery(plate.Image, intent)
		if err != nil {
			t.Fatalf("(image, %s) is unroutable: %v", intent, err)
		}
		if host != service.HostImageCDN {
			t.Fatalf("(image, %s) routed to %v, want the transforming image CDN", intent, host)
		}
	}
}

// A VIDEO's image intents serve its bounded POSTER through the image engine
// (V2.1). This is the one place a non-image kind legitimately reaches the
// metered host, and it is safe precisely because what it transforms is a still
// JPEG — the poster rendition — never the video bytes.
func TestVideoImageIntents_RouteToImageCDN_ForTheBoundedPoster(t *testing.T) {
	for _, intent := range []plate.Intent{plate.Thumbnail, plate.Grid, plate.Lightbox} {
		host, err := service.RouteDelivery(plate.Video, intent)
		if err != nil {
			t.Fatalf("(video, %s) is unroutable: %v", intent, err)
		}
		if host != service.HostImageCDN {
			t.Fatalf("(video, %s) routed to %v, want the image CDN — a video still must go through the bounded ladder, not be served raw", intent, host)
		}
	}
}

// Zoom rungs on a video refuse: a deep-zoom ladder over a video still is not
// something Plate offers, and the refusal must come from the table (unmapped)
// rather than from a handler afterthought.
func TestVideoZoomIntents_Refuse(t *testing.T) {
	for _, intent := range []plate.Intent{plate.Zoom1, plate.Zoom2, plate.Zoom3} {
		if _, err := service.RouteDelivery(plate.Video, intent); err == nil {
			t.Errorf("(video, %s) routed somewhere — zoom on a video must be unmapped and refuse", intent)
		}
	}
}
