package plate_test

// Phase 3 A2 (device wiring): the `device` query param on the resolve endpoint
// selects the decoded-memory-clamped imgproxy PRESET for image intents (spec §4.2).
//
// image_decoded_memory_test.go proves the PRESETS themselves clamp (it decodes the
// real imgproxy output of each preset). device_budget_safari_test.go proves how a
// device class is DERIVED from client hints. This test closes the gap between them:
// it drives the REAL resolve HANDLER end-to-end and asserts that `device` actually
// SELECTS the right preset — the wiring the handler was previously missing (the
// param was declared + engine-tested but never read).
//
// House rule: this asserts the resolved URL names the correct preset (the handler's
// decision), not that a clamp function was called. The preset's EFFECT on decoded
// pixels is verified against the real engine elsewhere; here the artifact under
// inspection is the resolved URL the handler returns.

import (
	"strings"
	"testing"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
	"github.com/chuckyatsuk/plate/test/harness"
)

// resolveDevice resolves a delivery URL with an explicit device class, driving the
// real GET /v1/assets/{id}/url?intent=…&device=… handler.
func (e *e2e) resolveDevice(assetID, intent, device string) plateDeliveryResolution {
	e.t.Helper()
	q := "/v1/assets/" + assetID + "/url?intent=" + intent
	if device != "" {
		q += "&device=" + device
	}
	resp := e.req("GET", q, nil)
	if resp.Code != 200 {
		e.t.Fatalf("resolve %s (device=%q): HTTP %d: %s", intent, device, resp.Code, resp.Body.String())
	}
	var out plateDeliveryResolution
	mustDecode(e.t, resp.Body.Bytes(), &out)
	return out
}

// presetOf extracts the imgproxy preset segment from a signed image URL of the
// shape {base}/{sig}/{preset}/plain/{source}. Returns "" if the shape is not
// recognized (so a wrong-shaped URL fails the assertion loudly).
func presetOf(imageURL string) string {
	i := strings.Index(imageURL, "/plain/")
	if i < 0 {
		return ""
	}
	before := imageURL[:i]          // {base}/{sig}/{preset}
	seg := before[strings.LastIndex(before, "/")+1:] // {preset}
	return seg
}

// TestDeviceClamp_ImagePresetSelection drives the real resolve handler with an
// actual image asset and asserts the `device` param selects the right preset for
// each image intent — including the A2 ruling that a MOBILE device asking for a
// zoom intent is DOWNGRADED to the mobile-budget rendition (never handed the
// desktop zoom rung, which would blow the mobile decoded-memory budget).
func TestDeviceClamp_ImagePresetSelection(t *testing.T) {
	e := newE2E(t, 720.0)
	dir := t.TempDir()

	// A real image asset. Its bytes don't matter for URL-shape assertions (the
	// resolve path is imgproxy-signed synchronously and never fetches here), only
	// that a ready image asset exists to resolve.
	src := harness.SynthImage(t, dir, "art.png", 4000, 3000)
	assetID := e.uploadAndFinalize(src, "image/png")

	cases := []struct {
		name       string
		intent     string
		device     string
		wantPreset string
	}{
		// lightbox: desktop keeps the 2048 preset; mobile gets the tighter 1400 one.
		{"lightbox_desktop", "lightbox", "desktop", mediaspec.PresetLightbox},
		{"lightbox_mobile", "lightbox", "mobile", mediaspec.PresetLightboxMobile},

		// The A2 ruling: mobile + a zoom intent → downgrade to lightbox_mobile, the
		// safe rendition — NOT the desktop zoom rung (that is the budget violation the
		// clamp exists to prevent). Desktop gets the real zoom rung.
		{"zoom_2_desktop", "zoom_2", "desktop", mediaspec.PresetZoom2},
		{"zoom_2_mobile_downgrades", "zoom_2", "mobile", mediaspec.PresetLightboxMobile},
		{"zoom_3_mobile_downgrades", "zoom_3", "mobile", mediaspec.PresetLightboxMobile},

		// zoom_3 on desktop fans out to an ASPECT BUCKET by the asset's probed dims
		// (imgproxy caps the long edge, so one cap can't hold ≤24MP across aspects).
		// This asset is 4000×3000, r=1.33 → the STANDARD band. Proves the aspect
		// resolution runs end-to-end through the real handler.
		{"zoom_3_desktop_aspect_bucket", "zoom_3", "desktop", mediaspec.Zoom3PresetForAspect(4000, 3000)},

		// grid/thumbnail are already small — device does not change their preset.
		{"grid_mobile_unchanged", "grid", "mobile", mediaspec.PresetGrid},
		{"thumbnail_mobile_unchanged", "thumbnail", "mobile", mediaspec.PresetThumbnail},

		// Default (no device param) is mobile — the safe budget — so an unspecified
		// device on a lightbox must take the mobile preset, never the desktop one.
		{"lightbox_default_is_mobile", "lightbox", "", mediaspec.PresetLightboxMobile},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.resolveDevice(assetID, tc.intent, tc.device)
			if res.Delivery == nil {
				t.Fatalf("expected a delivery URL, got refusal reason %v", res.Reason)
			}
			got := presetOf(res.Delivery.URL)
			if got != tc.wantPreset {
				t.Fatalf("intent=%s device=%q resolved to preset %q, want %q\nURL: %s",
					tc.intent, tc.device, got, tc.wantPreset, res.Delivery.URL)
			}
		})
	}
}

// TestDeviceClamp_UnknownDeviceIsBadRequest: an unrecognized device value is a 400,
// not a silent fallback — a typo must not quietly serve the wrong (larger) budget.
func TestDeviceClamp_UnknownDeviceIsBadRequest(t *testing.T) {
	e := newE2E(t, 720.0)
	dir := t.TempDir()
	src := harness.SynthImage(t, dir, "art2.png", 1200, 900)
	assetID := e.uploadAndFinalize(src, "image/png")

	resp := e.req("GET", "/v1/assets/"+assetID+"/url?intent=lightbox&device=phone", nil)
	if resp.Code != 400 {
		t.Fatalf("device=phone should be a 400 bad_request; got HTTP %d: %s", resp.Code, resp.Body.String())
	}
}
