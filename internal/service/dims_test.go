package service

// White-box tests for the image output-dimension computation and the zoom_3 aspect
// bucketing wired into the resolve path. The REAL-imgproxy proof that these
// predictions match the engine lives in test/image_reported_dims_test.go; here we
// pin the pure logic (fit math, enlarge:0, aspect-bucket selection, the mobile
// downgrade) so a regression is caught without a container.

import (
	"testing"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
	plate "github.com/chuckyatsuk/plate/internal/plate"
)

func i32(n int32) *int32 { return &n }

func TestFitOutputDims(t *testing.T) {
	// lightbox cap = 2048.
	cases := []struct {
		name           string
		w, h           *int32
		preset         string
		wantW, wantH   int32
		wantOK         bool
	}{
		{"landscape over cap", i32(6000), i32(4000), mediaspec.PresetLightbox, 2048, 1365, true},
		{"portrait over cap (long edge = height)", i32(4000), i32(6000), mediaspec.PresetLightbox, 1365, 2048, true},
		{"square over cap", i32(6000), i32(6000), mediaspec.PresetLightbox, 2048, 2048, true},
		{"under cap → pass-through (enlarge:0)", i32(800), i32(600), mediaspec.PresetLightbox, 800, 600, true},
		{"zoom_3 standard band cap 5477", i32(12000), i32(8000), mediaspec.PresetZoom3Standard, 5477, 3651, true},
		{"unprobed → not ok", nil, nil, mediaspec.PresetLightbox, 0, 0, false},
		{"zero dims → not ok", i32(0), i32(100), mediaspec.PresetLightbox, 0, 0, false},
		{"unknown preset (A/V) → not ok", i32(6000), i32(4000), "loop", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, h, ok := fitOutputDims(tc.w, tc.h, tc.preset)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			// ±1px for rounding.
			if abs32(w-tc.wantW) > 1 || abs32(h-tc.wantH) > 1 {
				t.Fatalf("dims = %dx%d, want %dx%d", w, h, tc.wantW, tc.wantH)
			}
		})
	}
}

func abs32(n int32) int32 {
	if n < 0 {
		return -n
	}
	return n
}

// imagePreset must (a) downgrade any zoom intent on mobile to lightbox_mobile,
// (b) fan zoom_3 out to the aspect bucket from probed dims on desktop, (c) pass
// other intents through.
func TestImagePreset_ZoomAspectAndMobileDowngrade(t *testing.T) {
	// A 4000×3000 (r=1.33) source → standard band on desktop zoom_3.
	sw, sh := i32(4000), i32(3000)
	cases := []struct {
		intent plate.Intent
		device plate.DeviceClass
		want   string
	}{
		{plate.Lightbox, plate.Desktop, mediaspec.PresetLightbox},
		{plate.Lightbox, plate.Mobile, mediaspec.PresetLightboxMobile},
		{plate.Zoom3, plate.Mobile, mediaspec.PresetLightboxMobile},              // downgrade
		{plate.Zoom3, plate.Desktop, mediaspec.Zoom3PresetForAspect(4000, 3000)}, // aspect bucket
		{plate.Zoom1, plate.Desktop, string(plate.Zoom1)},
		{plate.Grid, plate.Mobile, string(plate.Grid)}, // small, no downgrade
	}
	for _, tc := range cases {
		got := imagePreset(tc.intent, tc.device, sw, sh)
		if got != tc.want {
			t.Errorf("imagePreset(%s, %s) = %q, want %q", tc.intent, tc.device, got, tc.want)
		}
	}
	// zoom_3 desktop with UNKNOWN dims must fall to the near-square (safest) bucket.
	if got := imagePreset(plate.Zoom3, plate.Desktop, nil, nil); got != mediaspec.PresetZoom3NearSquare {
		t.Errorf("zoom_3 desktop unknown dims = %q, want near-square (safest) bucket", got)
	}
}
