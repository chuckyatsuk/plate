package plate_test

// Incident (spec §7): "a 13-minute video refuses `detail` with
// exceeded_duration_ceiling."
//
// Behind it (spec §4.3, §5.4): a `detail` rendition is bounded to <=12 minutes
// (chuck 2026-09-08). When the source is longer, Plate does not silently make a
// broken tile and does not 500 — it returns an HONEST refusal Files can act on
// (show a Vimeo embed, a poster, a download link). The refusal is a closed-enum
// reason from the contract, not free text.
//
// Verify the artifact, not the flag: the ceiling decision is fed the duration
// ffprobe MEASURES off a real >12-minute MP4, never a duration asserted by the
// test. A 13-minute clip at a tiny frame size is a few hundred KB, so this is
// cheap to build for real.

import (
	"path/filepath"
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/test/harness"
	"github.com/chuckyatsuk/plate/test/support"
)

func TestDetailIntent_RefusesOverCeiling_WithClosedEnumReason(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	const ceilingSeconds = 720.0 // spec §5.4: PLATE_DETAIL_MAX_DURATION=720s (12 min)

	// A real 13-minute source — over the ceiling. Built with ffmpeg; ffprobe then
	// MEASURES its true duration, which is what the ceiling check consumes.
	src := harness.SynthVideo(t, filepath.Join(dir, "thirteen_min.mp4"), harness.Seconds(13*60), true)
	probed := harness.Probe(t, src)
	if probed.DurationS <= ceilingSeconds {
		t.Fatalf("fixture is not actually over the ceiling: probed %.1fs <= %.1fs", probed.DurationS, ceilingSeconds)
	}

	// support.DetailResolver is the seam: a thin interface the SERVICE will
	// implement. Until it lands, support.ceilingResolver is a reference stub whose
	// ONLY input is the ffprobe-measured duration — it does not get to invent the
	// duration. That keeps the assertion anchored to the artifact.
	var resolver support.DetailResolver = support.NewCeilingResolver(ceilingSeconds)

	res := resolver.ResolveDetail(probed.DurationS)

	if res.Delivery != nil {
		t.Fatalf("expected a refusal for a %.0fs source over a %.0fs ceiling; got a delivery URL", probed.DurationS, ceilingSeconds)
	}
	if res.Reason == nil {
		t.Fatal("refusal carried no reason code; Files cannot act on a null reason")
	}
	if *res.Reason != plate.ReasonCodeExceededDurationCeiling {
		t.Fatalf("wrong refusal reason: got %q, want %q", *res.Reason, plate.ReasonCodeExceededDurationCeiling)
	}
	// The machine-readable detail must carry the numbers Files needs to explain
	// the refusal (spec §4.3 example): the actual duration and the ceiling.
	if res.Detail == nil || res.Detail.DurationS == nil || res.Detail.CeilingS == nil {
		t.Fatalf("refusal detail missing duration_s/ceiling_s: %+v", res.Detail)
	}
	if *res.Detail.CeilingS != ceilingSeconds {
		t.Fatalf("refusal reported ceiling %.0fs, want %.0fs", *res.Detail.CeilingS, ceilingSeconds)
	}
}

// The complement: a source UNDER the ceiling must NOT be refused for duration.
// This guards against a resolver that refuses everything (which would pass the
// test above for the wrong reason).
func TestDetailIntent_AllowsUnderCeiling(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	const ceilingSeconds = 720.0

	src := harness.SynthVideo(t, filepath.Join(dir, "short.mp4"), harness.Seconds(20), true)
	probed := harness.Probe(t, src)

	resolver := support.NewCeilingResolver(ceilingSeconds)
	res := resolver.ResolveDetail(probed.DurationS)

	if res.Reason != nil && *res.Reason == plate.ReasonCodeExceededDurationCeiling {
		t.Fatalf("a %.1fs source (under the %.0fs ceiling) was refused for duration", probed.DurationS, ceilingSeconds)
	}
}
