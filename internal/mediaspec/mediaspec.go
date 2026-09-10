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
// resize:fit:W:W:0/enlarge:0 fits within a W×W BOX preserving aspect and never
// enlarges — so the LONGEST edge is bounded to W regardless of orientation. (NOT
// fit:W:0, which bounds WIDTH only and lets a portrait's height run past W — the
// area-wall bug the cross-aspect test caught.) The widths encode the intent bounds:
//   - lightbox: clamped to the megapixel wall (~24MP → 2048 longest edge)
//   - lightbox_mobile: clamped TIGHTER so a decoded RGBA frame fits the 24MiB
//     mobile budget (spec §4.2) — a wide desktop lightbox would blow a phone tab
//   - thumbnail: small grid/admin cell
const (
	PresetLightbox       = "lightbox"
	PresetLightboxMobile = "lightbox_mobile"
	PresetThumbnail      = "thumbnail"
	PresetGrid           = "grid"

	// Zoom ladder (spec §4.2, Phase 3 A2): a BOUNDED deep-zoom ladder for Uri's
	// 96MP artwork. Three fixed INTENTS (zoom_1|zoom_2|zoom_3). zoom_1/zoom_2 are a
	// single preset each (their name IS the intent). zoom_3 is a SET of three
	// aspect-bucketed presets (see below) — the resolver selects one by the asset's
	// probed aspect, so the intent zoom_3 fans out to a preset internally, the way
	// device selects lightbox vs lightbox_mobile. Consumers only ever name zoom_3.
	// These are a DESKTOP surface: rungs above lightbox exceed the 24MiB MOBILE
	// budget by design — mobile clamp behavior on a zoom intent is decided at the
	// resolve handler, not here.
	// EXTENSION RULE: a deeper rung is a new intent `zoom_4` (+ enum member + clamp
	// test + regen). NEVER a `level` param — a rung is a deliberate contract diff.
	PresetZoom1 = "zoom_1"
	PresetZoom2 = "zoom_2"

	// zoom_3 aspect buckets. The preset caps the LONGEST EDGE (resize:fit:W:W box),
	// so ONE edge cap cannot hold the ≤24MP AREA wall across aspects (a landscape
	// cap lets a square through at >24MP → CDN 400; a square cap dips landscape).
	// zoom_3 is therefore three presets, each sized for the SQUAREST member of its
	// aspect band (that member breaches the 24MP wall first). Selected by the
	// asset's probed aspect r = max(w,h)/min(w,h) via Zoom3PresetForAspect.
	PresetZoom3NearSquare = "zoom_3_nearsquare"
	PresetZoom3Standard   = "zoom_3_standard"
	PresetZoom3Wide       = "zoom_3_wide"
)

// PresetWidths is the fit-width each preset clamps to, in CSS px of the LONGEST
// edge (imgproxy resize:fit:W:W:0 caps the long edge via a W×W box, verified against the real
// engine across orientations). These are the numbers the decoded-pixel tests hold
// the output to.
//
// ⚠️ THE PER-EDGE CAP IS A CONVENIENCE; THE REAL GUARANTEE IS AN AREA CEILING.
// The binding rule is OUTPUT ≤ 24MP (the CDN megapixel wall) — an AREA constraint.
// imgproxy expresses only per-EDGE caps, so zoom_3 is a set of aspect-bucketed
// presets whose edge caps each realize ~24MP for their band, selected by the
// asset's probed aspect — parity with ImageKit's safeWidth area clamp
// (sqrt(24MP × aspect), measured live: landscape 3:2 → w-5999, square → w-4898).
//
// zoom_3 BANDS (r = max/min; each cap = floor(sqrt(24,000,000 × r_band_min)),
// sized for the band's SQUAREST member — boundaries fit to Uri's 339-image
// catalogue audit, .scratch/plate-aspect-audit.md: 89% cluster in r∈[1.25,1.6),
// median 1.499, so boundaries sit in the histogram GAPS, not through the cluster):
//   near-square  r < 1.25        → 4898  (sized for r=1.0)
//   standard     1.25 ≤ r < 1.6  → 5477  (sized for r=1.25)
//   wide         r ≥ 1.6         → 6197  (sized for r=1.6; r clamped at band max)
// ACCEPTED TRADEOFF: the standard band's 5477 cap means a 3:2 median work gets
// ~20MP at max zoom vs the ~24MP the live ImageKit site serves — a small,
// deliberate dip on the deepest rung of the dominant aspect, the honest cost of
// bucketing a continuous area clamp into 3 discrete edge caps under ONLY_PRESETS.
// Not worth a 4th band (chuck). A future band/rung MUST be sized for its squarest
// member and stay ≤ 24MP / ≤ MaxResultDimension.
// (zoom_1/zoom_2 need no bucketing: square 3072²=9.4MP, 4096²=16.8MP, both <24MP.)
var PresetWidths = map[string]int{
	PresetLightbox:       2048,
	PresetLightboxMobile: 1400,
	PresetThumbnail:      400,
	PresetGrid:           800,
	PresetZoom1:          3072,
	PresetZoom2:          4096,
	PresetZoom3NearSquare: 4898,
	PresetZoom3Standard:   5477,
	PresetZoom3Wide:       6197,
}

// LosslessPresets are the presets served at imgproxy quality 100 — the deep-zoom
// rungs, matching the live site's q-100 at max zoom (dimensions parity without
// quality parity is a quieter regression). lightbox/grid/thumbnail/poster keep
// imgproxy's default quality.
var LosslessPresets = map[string]bool{
	PresetZoom1:           true,
	PresetZoom2:           true,
	PresetZoom3NearSquare: true,
	PresetZoom3Standard:   true,
	PresetZoom3Wide:       true,
}

// zoom3 band boundaries on r = max(w,h)/min(w,h). Boundaries fit to the catalogue
// audit (histogram gaps), not guessed. Sizing invariant: each band cap =
// floor(sqrt(24,000,000 × r_band_min)).
const (
	zoom3NearSquareMaxR = 1.25 // r < 1.25 → near-square
	zoom3StandardMaxR   = 1.6  // 1.25 ≤ r < 1.6 → standard; r ≥ 1.6 → wide
)

// Zoom3PresetForAspect selects the zoom_3 aspect-bucket preset for a source of the
// given probed dimensions. r = max/min is orientation-independent (imgproxy caps
// the long edge, so a 3:2 and a 2:3 clamp identically). A source with unknown/zero
// dims falls to the near-square (smallest, safest) bucket — fail toward the
// tightest area budget, never the largest.
func Zoom3PresetForAspect(w, h int) string {
	if w <= 0 || h <= 0 {
		return PresetZoom3NearSquare
	}
	long, short := w, h
	if short > long {
		long, short = short, long
	}
	r := float64(long) / float64(short)
	switch {
	case r < zoom3NearSquareMaxR:
		return PresetZoom3NearSquare
	case r < zoom3StandardMaxR:
		return PresetZoom3Standard
	default:
		return PresetZoom3Wide
	}
}

// MaxResultDimension is a deployment-wide belt: imgproxy's IMGPROXY_MAX_RESULT_
// DIMENSION caps the longest edge of ANY result, regardless of preset. It is set
// to the LARGEST legitimate preset edge (zoom_3 wide band = 6197) so a future
// preset misconfiguration or a forgotten cap cannot exceed the area ceiling on an
// edge — defense in depth behind the per-preset caps above. It is an EDGE limit
// (imgproxy has no area/megapixel result limit), so it backstops, it does not
// replace, the aspect-bucketed per-edge cap sizing.
const MaxResultDimension = 6197

// presetOrder is the deterministic order PresetDefs emits (tests compare the
// string; the deploy config mirrors it exactly).
var presetOrder = []string{
	PresetLightbox, PresetLightboxMobile, PresetThumbnail, PresetGrid,
	PresetZoom1, PresetZoom2,
	PresetZoom3NearSquare, PresetZoom3Standard, PresetZoom3Wide,
}

// PresetDefs returns the IMGPROXY_PRESETS environment value: each preset as
// `name=resize:fit:W:W:0/enlarge:0`, plus `/quality:100` for the lossless (deep-
// zoom) presets, joined by commas. Both the test harness and the deploy config use
// this, so the presets the tests verify are the presets production serves.
func PresetDefs() string {
	out := ""
	for i, name := range presetOrder {
		if i > 0 {
			out += ","
		}
		// fit:W:W (a W×W BOX), NOT fit:W:0 (width only). The box bounds the LONGEST
		// edge to W regardless of orientation — so a portrait's height cannot run
		// away past the cap (fit:W:0 bounds width only, letting a tall image blow the
		// area wall; that's the bug the cross-aspect test caught). enlarge:0 keeps a
		// small source untouched.
		w := itoa(PresetWidths[name])
		out += name + "=resize:fit:" + w + ":" + w + ":0/enlarge:0"
		if LosslessPresets[name] {
			out += "/quality:100"
		}
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
