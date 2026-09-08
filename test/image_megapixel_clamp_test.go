package plate_test

// Incident (spec §7): "28MP input returns a clamped rendition, never a 400."
//
// Behind it (spec §4.2, §5.4): both delivery CDNs 400 above ~25MP; Uri's shots
// run to 96MP. A naive service passes the source width through and the CDN
// rejects it — a broken image on a public page. Plate clamps the OUTPUT to the
// megapixel wall so the request always succeeds with a smaller-but-valid image.
//
// Verify the artifact, not the flag: this renders a genuinely oversized source
// through the REAL imgproxy engine and DECODES the returned bytes. The
// assertions are (a) the request returns 200, not 400, and (b) the decoded
// output is at or under the ~24MP wall. Nothing here inspects whether a
// "clampWidthToOutputLimit" function was called — only what the engine actually
// produced.

import (
	"testing"

	"github.com/chuckyatsuk/plate/test/harness"
)

// megapixelWall mirrors PLATE_MAX_IMAGE_OUTPUT_MP=24 (spec §5.4). The output must
// land at or below it; a small tolerance absorbs rounding in aspect-preserving
// fit resizes.
const megapixelWall = 24_000_000
const megapixelTolerance = 1_000_000 // 1MP slack for fit rounding

func TestLightbox_OversizedSource_ReturnsClampedRendition_Not400(t *testing.T) {
	harness.RequireFFmpeg(t) // builds the oversized fixture
	dir := t.TempDir()

	// 6000x5000 = 30MP source — over the ~25MP wall, in the spirit of the "28MP"
	// incident and well within Uri's real 96MP range.
	harness.SynthImage(t, dir, "oversized.png", 6000, 5000)

	ip := harness.StartImgproxy(t, dir) // skips if Docker is unavailable

	// The lightbox preset. A source over the wall must not 400.
	status := ip.RenderStatus(t, harness.PresetLightbox, "oversized.png")
	if status != 200 {
		t.Fatalf("oversized source returned HTTP %d; the incident is it must be a clamped 200, never a 400", status)
	}

	// Decode the ACTUAL returned rendition and measure its real pixels.
	cfg, _ := ip.RenderConfig(t, harness.PresetLightbox, "oversized.png")
	outMP := cfg.Width * cfg.Height
	if outMP > megapixelWall+megapixelTolerance {
		t.Fatalf("clamped rendition still over the megapixel wall: %dx%d = %dMP > %dMP",
			cfg.Width, cfg.Height, outMP/1_000_000, megapixelWall/1_000_000)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		t.Fatalf("decoded rendition has non-positive dimensions: %dx%d", cfg.Width, cfg.Height)
	}
}

// A source already under the wall must pass through without being needlessly
// upscaled (the preset sets enlarge:0). Guards a "clamp always shrinks to the
// wall" bug that the test above would not catch.
func TestLightbox_UndersizedSource_NotEnlarged(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// 800x600 source — far under the lightbox 2048 fit width.
	harness.SynthImage(t, dir, "small.png", 800, 600)
	ip := harness.StartImgproxy(t, dir)

	cfg, status := ip.RenderConfig(t, harness.PresetLightbox, "small.png")
	if status != 200 {
		t.Fatalf("undersized source returned HTTP %d, want 200", status)
	}
	if cfg.Width > 800 || cfg.Height > 600 {
		t.Fatalf("undersized source was enlarged to %dx%d; enlarge:0 should preserve it", cfg.Width, cfg.Height)
	}
}
