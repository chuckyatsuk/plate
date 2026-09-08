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
	const desktopBudget = 96 * 1024 * 1024
	if desktopDecoded > desktopBudget {
		t.Fatalf("desktop rendition decodes to %d B, over the %d B (96 MiB) desktop budget", desktopDecoded, desktopBudget)
	}
}
