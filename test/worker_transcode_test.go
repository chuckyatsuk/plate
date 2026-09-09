package plate_test

// The REAL worker's transcode output, walked for the faststart property
// (decision D3, add-alongside). This is distinct from av_faststart_test.go, which
// drives the harness helper directly and is the ENGINE FLOOR — proof that
// ffmpeg-with-these-args produces a faststart file, a fact about the engine
// independent of Plate. This test proves the WORKER produces the same artifact,
// because it builds its ffmpeg invocation from the same mediaspec constants the
// harness does (condition C1). Both green ⇒ the worker matches the engine; worker
// red + floor green ⇒ the fault is precisely in the worker, not ffmpeg.
//
// It verifies the artifact, not the flag: it re-opens the worker's output MP4 and
// walks the top-level box order (moov before mdat), the same as the floor test.

import (
	"context"
	"path/filepath"
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/worker"
	"github.com/chuckyatsuk/plate/test/harness"
)

func TestWorkerTranscode_Detail_IsFaststart(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// A raw source as a studio hands it over: NOT faststart (SynthVideo omits it).
	src := harness.SynthVideo(t, filepath.Join(dir, "source.mp4"), harness.Seconds(3), true)
	dst := filepath.Join(dir, "detail.mp4")

	// The REAL worker transcoder (ultrafast preset keeps the fixture cheap; preset
	// does not affect box order).
	tc := worker.NewFFmpegTranscoder("", "ultrafast", 0)
	if err := tc.Transcode(context.Background(), plate.Detail, src, dst); err != nil {
		t.Fatalf("worker transcode: %v", err)
	}

	fast, err := harness.IsFaststart(dst)
	if err != nil {
		t.Fatalf("walking box order of the worker's output: %v", err)
	}
	if !fast {
		atoms, _ := harness.TopLevelAtoms(dst)
		t.Fatalf("worker's detail MP4 is NOT faststart: moov does not precede mdat.\ntop-level atoms: %+v", atoms)
	}

	// And it honoured the detail ceiling: the probed height is <= 1080p.
	probed := harness.Probe(t, dst)
	if probed.Height > 1080 {
		t.Fatalf("worker detail output is %dp, over the 1080p detail ceiling", probed.Height)
	}
}

// The loop tier must be SILENT (spec §5.4): the worker drops audio (-an). Verify
// the produced loop has no audio stream — the artifact, not the flag.
func TestWorkerTranscode_Loop_IsSilentAndFaststart(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	src := harness.SynthVideo(t, filepath.Join(dir, "source.mp4"), harness.Seconds(3), true) // WITH audio
	dst := filepath.Join(dir, "loop.mp4")

	tc := worker.NewFFmpegTranscoder("", "ultrafast", 0)
	if err := tc.Transcode(context.Background(), plate.Loop, src, dst); err != nil {
		t.Fatalf("worker transcode loop: %v", err)
	}

	fast, err := harness.IsFaststart(dst)
	if err != nil {
		t.Fatalf("walking box order: %v", err)
	}
	if !fast {
		t.Fatal("worker's loop MP4 is not faststart")
	}
	if harness.HasAudioStream(t, dst) {
		t.Fatal("worker's loop rendition carries an audio stream; the loop tier must be silent (spec §5.4)")
	}
}
