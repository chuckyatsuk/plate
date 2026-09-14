package plate_test

// The `loop` intent is BOUNDED: ≤30s, silent, ~640px (spec §4.1, §5.4).
//
// Dated failure (2026-09-15, found by the Tier 2 V3 live proof): LoopArgs scaled
// the video and dropped audio but passed NO duration flag, so a "grid tile hover
// preview" was a full-length silent re-encode of the entire work. The spec said
// ≤30s, the constant's own comment said ≤30s, and the function's doc comment
// claimed the clamp happened "before this runs" — which was false, and was
// exactly the kind of belief that keeps a bug alive.
//
// It survived because `loop` was the ONLY A/V rendition with no engine-verified
// test. `detail` and the remux path both had one; nothing had ever looked at a
// produced loop. Measured cost on a 269s source: 12s and 5.0MB unbounded, versus
// 1s and 580KB capped — and against a real 311MB/269s upload the loop job ran
// over TEN MINUTES, blocking every other job behind it at worker concurrency 1.
//
// House rule, same as the faststart test next door: assert the ARTIFACT, not the
// flag. These tests re-open the produced MP4 and measure it with ffprobe. A
// negative control proves the check can fail.

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
	"github.com/chuckyatsuk/plate/test/harness"
)

// A source LONGER than the cap must produce an output AT the cap — not a copy of
// the source. This is the regression itself.
func TestLoop_LongSource_IsCappedAt30s(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// 45s — comfortably over the 30s cap, cheap to synthesise.
	src := harness.SynthVideo(t, filepath.Join(dir, "long.mp4"), harness.Seconds(45), true)
	out := harness.TranscodeLoop(t, src, filepath.Join(dir, "loop.mp4"))

	got := harness.Probe(t, out)
	if got.DurationS > float64(mediaspec.LoopMaxDurationS)+1.0 {
		t.Fatalf(
			"loop is %.1fs from a 45s source — the ≤%ds cap is not being applied, so a grid tile "+
				"preview is a full-length re-encode of the work (the 2026-09-15 regression)",
			got.DurationS, mediaspec.LoopMaxDurationS,
		)
	}
	// And it must actually contain video, not be truncated to nothing.
	if got.DurationS < 1.0 {
		t.Fatalf("loop is %.1fs — the cap truncated it to nothing", got.DurationS)
	}
}

// A source SHORTER than the cap must be unaffected: -t is a ceiling, not a pad.
// Without this, a fix could "pass" by hard-coding every loop to 30s.
func TestLoop_ShortSource_IsNotPadded(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	src := harness.SynthVideo(t, filepath.Join(dir, "short.mp4"), harness.Seconds(5), true)
	out := harness.TranscodeLoop(t, src, filepath.Join(dir, "loop.mp4"))

	got := harness.Probe(t, out)
	if got.DurationS > 7.0 {
		t.Fatalf("a 5s source produced a %.1fs loop — the cap must be a ceiling, never a pad", got.DurationS)
	}
}

// The loop tier is SILENT (spec §5.4) — audio DROPPED with -an, not muted. A
// speaker control on a loop-only slide would be a dead affordance, and the Files
// lightbox gates its sound toggle on the detail encode existing.
func TestLoop_IsSilent(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// withAudio: true — the source HAS a track, so a pass here means it was
	// actively dropped rather than never present.
	src := harness.SynthVideo(t, filepath.Join(dir, "withsound.mp4"), harness.Seconds(5), true)
	out := harness.TranscodeLoop(t, src, filepath.Join(dir, "loop.mp4"))

	if hasAudioStream(t, out) {
		t.Fatal("the loop rendition carries an audio stream; the loop tier must be silent (spec §5.4)")
	}
	// Negative control: the same check must SEE audio in the source, or it proves
	// nothing about the loop.
	if !hasAudioStream(t, src) {
		t.Fatal("negative control failed: the source was expected to have audio, so the silence check is vacuous")
	}
}

// hasAudioStream reports whether a file contains at least one audio stream.
func hasAudioStream(t *testing.T, path string) bool {
	t.Helper()
	cmd := exec.Command(
		ffprobeBinForTest(),
		"-v", "error",
		"-select_streams", "a",
		"-show_entries", "stream=codec_type",
		"-of", "csv=p=0",
		path,
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ffprobe audio-stream check failed: %v", err)
	}
	return len(out) > 0
}

func ffprobeBinForTest() string {
	if v := os.Getenv("PLATE_FFPROBE_PATH"); v != "" {
		return v
	}
	return "ffprobe"
}
