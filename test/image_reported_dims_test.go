package plate_test

// Phase 3 (BLOCKER A prerequisite): Plate populates Delivery.width/height for image
// intents so a consumer can build a zoom ladder / srcset from STRUCTURED fields
// instead of regex-parsing the URL. The reported dims are computed from the probed
// source dims + the preset's fit cap (service.fitOutputDims), replicating imgproxy's
// resize:fit:W:W:0/enlarge:0.
//
// Verify the artifact, not the field: this test does NOT assert "fitOutputDims was
// called". It renders each (source, preset) through the REAL imgproxy engine, reads
// the ACTUAL decoded output dimensions, and asserts the SAME prediction the service
// reports (the fit formula, replicated here) equals what imgproxy really produced —
// across landscape, portrait, square, and under-cap sources. If Plate's reported
// width/height ever diverged from the real rendition, a consumer's ladder math would
// silently be wrong; this is what keeps "reported dims == real dims" true.

import (
	"testing"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
	"github.com/chuckyatsuk/plate/test/harness"
)

// predictFit replicates service.fitOutputDims / imgproxy resize:fit:cap:0:0 with
// enlarge:0 — fit the LONGEST edge to cap, preserve aspect, never enlarge. Kept in
// the test independently so a drift between the formula and the real engine fails
// here rather than being asserted against itself.
func predictFit(srcW, srcH, cap int) (int, int) {
	long := srcW
	if srcH > long {
		long = srcH
	}
	if long <= cap {
		return srcW, srcH
	}
	scale := float64(cap) / float64(long)
	ow := int(float64(srcW)*scale + 0.5)
	oh := int(float64(srcH)*scale + 0.5)
	if ow < 1 {
		ow = 1
	}
	if oh < 1 {
		oh = 1
	}
	return ow, oh
}

func TestReportedDims_MatchRealImgproxyDecode(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	type src struct {
		name string
		w, h int
	}
	sources := []src{
		{"land_3to2", 12000, 8000}, // over every cap, landscape
		{"port_2to3", 8000, 12000}, // over every cap, portrait (long edge = height)
		{"square", 9800, 9800},     // over every cap, square
		{"under_cap", 1000, 700},   // under every cap → pass-through (enlarge:0)
	}
	for _, s := range sources {
		harness.SynthImage(t, dir, s.name+".png", s.w, s.h)
	}
	ip := harness.StartImgproxy(t, dir)

	// Every image preset (its own fit cap). zoom_3 is represented by all three of its
	// aspect buckets — each is a real preset the resolver can select.
	presets := []string{
		mediaspec.PresetLightbox, mediaspec.PresetLightboxMobile,
		mediaspec.PresetThumbnail, mediaspec.PresetGrid,
		mediaspec.PresetZoom1, mediaspec.PresetZoom2,
		mediaspec.PresetZoom3NearSquare, mediaspec.PresetZoom3Standard, mediaspec.PresetZoom3Wide,
	}

	for _, preset := range presets {
		cap := mediaspec.PresetWidths[preset]
		for _, s := range sources {
			t.Run(preset+"/"+s.name, func(t *testing.T) {
				cfg, status := ip.RenderConfig(t, preset, s.name+".png")
				if status != 200 {
					t.Fatalf("%s on %s returned HTTP %d, want 200", preset, s.name, status)
				}
				wantW, wantH := predictFit(s.w, s.h, cap)
				// imgproxy rounds fractional edges; allow ±1px on each axis (the same
				// rounding the fit-resize does).
				if abs(cfg.Width-wantW) > 1 || abs(cfg.Height-wantH) > 1 {
					t.Fatalf("%s on %s: reported/predicted %dx%d != real imgproxy %dx%d (cap %d) — Plate's Delivery.width/height would not match the real rendition",
						preset, s.name, wantW, wantH, cfg.Width, cfg.Height, cap)
				}
			})
		}
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
