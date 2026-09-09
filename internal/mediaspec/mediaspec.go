// Package mediaspec is the SINGLE source of truth for how Plate invokes its
// media engines: the ffmpeg arguments for each A/V rendition, and the imgproxy
// preset definitions for each image intent.
//
// Why this package exists (Phase 2, decision D3 + condition C1): the test suite
// has two seam styles. The duration-ceiling test drives a service interface
// (support.DetailResolver). But the faststart and image-clamp tests are
// ENGINE-VERIFIED — they run a real engine with specific arguments and inspect
// the real artifact (walk the MP4 box order, decode the returned pixels). Those
// arguments and presets are therefore a CONTRACT, not scaffolding.
//
// If the test harness said `scale=-2:min(1080,ih)` / faststart-on-both-paths and
// the worker independently said something similar-but-different, there would be
// TWO contracts and the engine floor would stop meaning anything (chuck, C1). So
// both the harness AND the worker/service import these constants. Change a value
// here and both sides move together; the engine-floor tests keep proving the
// engine does what the worker asks, because they ask the same thing.
//
// This package holds NO logic and NO dependencies — just the values — so both a
// _test package and the production worker can import it without cycles.
package mediaspec

// ── A/V: ffmpeg arguments per rendition (spec §4.1, §5.4, §5.5) ──────────────
//
// These are argument *fragments* assembled into an ffmpeg invocation. The worker
// and the harness both build their command from these, so a faststart artifact
// the harness proves is the same faststart artifact the worker produces.

// DetailVideoFilter is the scale filter for the `detail` intent: fit within
// 1080p, never enlarge (spec §4.1: detail is ≤1080p, with audio). `-2` keeps the
// other dimension even (H.264 requires even dimensions) and preserves aspect.
const DetailVideoFilter = "scale=-2:min(1080\\,ih)"

// LoopVideoFilter is the scale filter for the `loop` intent: ~640px grid tile,
// never enlarge (spec §4.1, §5.4: loop is ≤30s, silent, ~640px).
const LoopVideoFilter = "scale=-2:min(640\\,ih)"

// FaststartFlag is the movflags value that puts `moov` before `mdat` so a browser
// can paint before the whole file downloads. It is applied UNCONDITIONALLY, on
// BOTH the re-encode path and the stream-copy (remux) path — the spec's §5.5
// requirement and the exact regression the faststart tests guard (faststart on
// encode but forgotten on copy). Never a per-call switch to forget.
const FaststartFlag = "+faststart"

// VideoCodec / AudioCodec are the delivery codecs. H.264 + AAC in an MP4 is the
// web-safe baseline every browser plays; the detail tier carries audio, the loop
// tier is silent (dropped, not muted).
const (
	VideoCodec = "libx264"
	AudioCodec = "aac"
	// EncodePreset trades encode speed for size. The worker uses a real preset in
	// production; the harness uses ultrafast for cheap fixtures. Kept here as the
	// default the worker applies (overridable via env in the worker if needed).
	EncodePreset = "medium"
)

// DetailArgs returns the ffmpeg argument list for a `detail` transcode from src
// to dst. Faststart is unconditional. The harness's TranscodeDetail and the
// worker both build from this so the produced artifact is identical in the ways
// the engine-floor test checks (box order) — differing only in -preset, which
// does not affect faststart.
func DetailArgs(src, dst, preset string) []string {
	if preset == "" {
		preset = EncodePreset
	}
	return []string{
		"-hide_banner", "-y", "-i", src,
		"-c:v", VideoCodec, "-preset", preset,
		"-vf", DetailVideoFilter,
		"-c:a", AudioCodec,
		"-movflags", FaststartFlag, // unconditional, preset layer (spec §5.5)
		dst,
	}
}

// LoopArgs returns the ffmpeg argument list for a `loop` transcode: ~640px,
// SILENT (audio dropped with -an, not muted), faststart. Duration clamping to
// ≤30s is enforced by the ceiling check before this runs, not here.
func LoopArgs(src, dst, preset string) []string {
	if preset == "" {
		preset = EncodePreset
	}
	return []string{
		"-hide_banner", "-y", "-i", src,
		"-an", // silent — the loop tier carries no audio (spec §5.4)
		"-c:v", VideoCodec, "-preset", preset,
		"-vf", LoopVideoFilter,
		"-movflags", FaststartFlag,
		dst,
	}
}

// RemuxCopyArgs returns the ffmpeg arguments for the stream-copy path: an
// already-web-safe source is remuxed, not re-encoded (spec §5.5, §3.1). Faststart
// is applied HERE TOO — the copy path is the one most likely to forget it.
func RemuxCopyArgs(src, dst string) []string {
	return []string{
		"-hide_banner", "-y", "-i", src,
		"-c", "copy",
		"-movflags", FaststartFlag,
		dst,
	}
}

// ── Images: imgproxy presets per intent (spec §2, §4.1, §4.2, §5.4) ──────────
//
// imgproxy runs with ONLY_PRESETS, so it REFUSES ad-hoc width/quality params: a
// caller can only name a purpose (spec §4.1). These preset definitions are the
// IMGPROXY_PRESETS value; the service builds delivery URLs that name a preset,
// and the image-clamp tests decode the real output to check the bounds.
//
// resize:fit:W:0:0/enlarge:0 fits within width W preserving aspect and never
// enlarges. The widths encode the intent bounds:
//   - lightbox: clamped to the megapixel wall (~24MP → 2048 longest edge)
//   - lightbox_mobile: clamped TIGHTER so a decoded RGBA frame fits the 24MiB
//     mobile budget (spec §4.2) — a wide desktop lightbox would blow a phone tab
//   - thumbnail: small grid/admin cell
const (
	PresetLightbox       = "lightbox"
	PresetLightboxMobile = "lightbox_mobile"
	PresetThumbnail      = "thumbnail"
	PresetGrid           = "grid"
)

// PresetWidths is the fit-width each preset clamps to, in CSS px of the longest
// edge. These are the numbers the decoded-pixel tests hold the output to. Chosen
// so lightbox_mobile stays under the 24MiB decoded budget even for a square
// output (1400²×4 ≈ 7.8MB, well under 24MiB, with headroom for 3 preloaded).
var PresetWidths = map[string]int{
	PresetLightbox:       2048,
	PresetLightboxMobile: 1400,
	PresetThumbnail:      400,
	PresetGrid:           800,
}

// PresetDefs returns the IMGPROXY_PRESETS environment value: each preset as
// `name=resize:fit:W:0:0/enlarge:0`, joined by commas. Both the test harness (to
// configure the imgproxy container) and the compose file / production config use
// this, so the presets the tests verify are the presets production serves.
func PresetDefs() string {
	// Deterministic order so the string is stable (tests may compare it).
	order := []string{PresetLightbox, PresetLightboxMobile, PresetThumbnail, PresetGrid}
	out := ""
	for i, name := range order {
		if i > 0 {
			out += ","
		}
		out += name + "=resize:fit:" + itoa(PresetWidths[name]) + ":0:0/enlarge:0"
	}
	return out
}

// itoa avoids importing strconv into this dependency-free package.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
