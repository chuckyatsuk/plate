package plate_test

// Incident (spec §7): "a mobile-budget lightbox rendition never exceeds 24MB
// decoded."
//
// Behind it (spec §4.2, the industry gap): the megapixel wall guards the CDN,
// NOT the tab. 24MP still decodes to ~92MB of RGBA. iOS Safari counts decoded
// pixels, not file size, and it is the browser that actually dies. So a second,
// independent clamp bounds the DECODED footprint: bytes = width × height × 4.
// This clamp is confirmed unoccupied across 20+ image services — it is a reason
// Plate exists.
//
// Verify the artifact, not the flag: this renders through the REAL imgproxy
// engine and computes the decoded RGBA size from the ACTUAL output dimensions.
// The mobile budget is 24 MiB; three such slides preloaded stays under ~72MB
// (spec §4.2). Nothing here asserts "clampWidthToMemoryBudget was called" — it
// measures what a phone would actually have to decode.

import (
	"testing"

	"github.com/chuckyatsuk/plate/test/harness"
)

// mobileDecodedBudget mirrors PLATE_DECODED_BUDGET_MOBILE = 24 MiB (spec §5.4).
const mobileDecodedBudget = 24 * 1024 * 1024 // 25165824 bytes

func decodedRGBABytes(w, h int) int64 { return int64(w) * int64(h) * 4 }

func TestLightboxMobile_DecodedRGBA_UnderMobileBudget(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// A large source: even after the megapixel wall it would decode to ~92MB,
	// blowing the mobile tab. The mobile preset must clamp far tighter.
	harness.SynthImage(t, dir, "huge.png", 6000, 5000) // 30MP source
	ip := harness.StartImgproxy(t, dir)

	cfg, status := ip.RenderConfig(t, harness.PresetLightboxMobile, "huge.png")
	if status != 200 {
		t.Fatalf("mobile lightbox render returned HTTP %d, want 200", status)
	}

	decoded := decodedRGBABytes(cfg.Width, cfg.Height)
	if decoded > mobileDecodedBudget {
		t.Fatalf("mobile-budget rendition decodes to %d bytes (%dx%d × 4) — over the %d-byte (24 MiB) mobile budget; a phone tab dies here",
			decoded, cfg.Width, cfg.Height, mobileDecodedBudget)
	}
}

// The desktop budget (96 MiB) is looser, so the SAME source should be allowed a
// larger rendition on desktop than on mobile. This proves the budget actually
// varies by device class rather than a single hardcoded size — the whole point
// of a per-device clamp.
func TestLightbox_DesktopBudget_LargerThanMobile(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	harness.SynthImage(t, dir, "huge2.png", 6000, 5000)
	ip := harness.StartImgproxy(t, dir)

	mobileCfg, _ := ip.RenderConfig(t, harness.PresetLightboxMobile, "huge2.png")
	desktopCfg, _ := ip.RenderConfig(t, harness.PresetLightbox, "huge2.png") // desktop lightbox

	mobileDecoded := decodedRGBABytes(mobileCfg.Width, mobileCfg.Height)
	desktopDecoded := decodedRGBABytes(desktopCfg.Width, desktopCfg.Height)

	if !(desktopDecoded > mobileDecoded) {
		t.Fatalf("desktop rendition (%dx%d, %d B) is not larger than mobile (%dx%d, %d B); the clamp is not device-aware",
			desktopCfg.Width, desktopCfg.Height, desktopDecoded,
			mobileCfg.Width, mobileCfg.Height, mobileDecoded)
	}
	// And the desktop one must still fit its own (96 MiB) budget.
	if desktopDecoded > desktopDecodedBudget {
		t.Fatalf("desktop rendition decodes to %d B, over the %d B (96 MiB) desktop budget", desktopDecoded, desktopDecodedBudget)
	}
}

// desktopDecodedBudget mirrors PLATE_DECODED_BUDGET_DESKTOP = 96 MiB (spec §5.4).
const desktopDecodedBudget = 96 * 1024 * 1024 // 100663296 bytes

// megapixelWallPixels mirrors PLATE_MAX_IMAGE_OUTPUT_MP=24 with the same 1MP fit-
// rounding tolerance the megapixel-clamp test uses (spec §5.4).
const megapixelWallPixels = 24_000_000 + 1_000_000

// TestZoomLadder_EachRung_UnderDesktopBudgetAndMegapixelWall covers the Phase 3 A2
// zoom ladder (spec §4.2). The zoom rungs are a DESKTOP deep-zoom surface for Uri's
// 96MP artwork: each is its own closed-enum intent backed by its own imgproxy
// preset. This guards the guarantee A2's guardrail makes — EVERY reachable rung is
// clamped — by rendering a 96MP-class source through the REAL imgproxy engine and
// measuring the ACTUAL decoded footprint of each rung's output.
//
// The assertions are the TWO HARD CEILINGS, and only those:
//  1. decoded RGBA (width×height×4) <= the 96 MiB desktop budget, and
//  2. output pixels <= the 24MP megapixel wall.
//
// The deepest rung (zoom_3) is exactly where the 292MB-decode tab-killer lived
// before the ladder was bounded; it is held to the same two ceilings as every
// other rung — no separate soft "well below 292MB" assertion, because the desktop
// budget IS the binding ceiling and a soft restatement is not a test.
func TestZoomLadder_EachRung_UnderDesktopBudgetAndMegapixelWall(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// A genuine 96MP-class source (12000x8000 = 96MP), in Uri's real range. Every
	// rung must clamp its output down from this.
	harness.SynthImage(t, dir, "artwork96.png", 12000, 8000)
	ip := harness.StartImgproxy(t, dir)

	rungs := []struct {
		name   string
		preset string
	}{
		{"zoom_1", harness.PresetZoom1},
		{"zoom_2", harness.PresetZoom2},
		{"zoom_3", harness.PresetZoom3},
	}
	for _, rung := range rungs {
		t.Run(rung.name, func(t *testing.T) {
			cfg, status := ip.RenderConfig(t, rung.preset, "artwork96.png")
			if status != 200 {
				t.Fatalf("%s render returned HTTP %d, want 200 (a clamped rendition, never a 400)", rung.name, status)
			}

			outPixels := cfg.Width * cfg.Height
			if outPixels > megapixelWallPixels {
				t.Fatalf("%s output %dx%d = %dMP over the 24MP megapixel wall — the CDN would 400 this",
					rung.name, cfg.Width, cfg.Height, outPixels/1_000_000)
			}

			decoded := decodedRGBABytes(cfg.Width, cfg.Height)
			if decoded > desktopDecodedBudget {
				t.Fatalf("%s rendition decodes to %d bytes (%dx%d × 4) — over the %d-byte (96 MiB) desktop budget; a desktop tab is at risk here",
					rung.name, decoded, cfg.Width, cfg.Height, desktopDecodedBudget)
			}
		})
	}
}

// TestZoomLadder_Monotonic proves the ladder actually deepens: each rung's decoded
// footprint is strictly larger than the one below it (against a source large enough
// that none of them clamp to the same wall). A ladder whose rungs collapse to one
// size — the Blocker-A failure mode, a regex silently flattening the ladder — fails
// here even though each rung would independently pass the ceiling test above.
func TestZoomLadder_Monotonic(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// 8000px wide: wider than zoom_3's 5120 fit, so each rung resizes to its own
	// distinct width rather than all passing an undersized source through unchanged.
	harness.SynthImage(t, dir, "wide8000.png", 8000, 6000)
	ip := harness.StartImgproxy(t, dir)

	c1, _ := ip.RenderConfig(t, harness.PresetZoom1, "wide8000.png")
	c2, _ := ip.RenderConfig(t, harness.PresetZoom2, "wide8000.png")
	c3, _ := ip.RenderConfig(t, harness.PresetZoom3, "wide8000.png")

	d1 := decodedRGBABytes(c1.Width, c1.Height)
	d2 := decodedRGBABytes(c2.Width, c2.Height)
	d3 := decodedRGBABytes(c3.Width, c3.Height)

	if !(d1 < d2 && d2 < d3) {
		t.Fatalf("zoom ladder is not monotonic: zoom_1=%dx%d (%dB), zoom_2=%dx%d (%dB), zoom_3=%dx%d (%dB); the rungs must deepen, not collapse",
			c1.Width, c1.Height, d1, c2.Width, c2.Height, d2, c3.Width, c3.Height, d3)
	}
}
