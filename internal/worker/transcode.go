// Package worker is Plate's `plate work` process (spec §5.2, Q4): it claims
// queued A/V derivation jobs, runs ffmpeg, writes renditions, and records
// durable state. It is the second of the two processes Plate splits from day one
// (the API is `plate serve`); the worker carries the fat ffmpeg runtime and the
// retryable, CPU-bound profile, so deploying them separately keeps each honest.
//
// This file is the transcode core. It builds its ffmpeg invocation from
// internal/mediaspec — the SAME constants the test harness uses — so the
// faststart artifact the engine-floor test proves is the artifact the worker
// produces (condition C1). Faststart is unconditional, on both the re-encode and
// the stream-copy paths (spec §5.5).
package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// Transcoder produces a rendition file for an intent from a source file. The
// worker implements it; a test drives the REAL implementation and walks the
// produced MP4's box order (moov<mdat) with the same harness verifier the
// engine-floor test uses — so the worker is proven to match the engine, not just
// asserted to (decision D3, add-alongside).
type Transcoder interface {
	// Transcode reads src and writes the rendition for intent to dst. dst's parent
	// dir is created if needed. It returns an error on any ffmpeg failure or an
	// unsupported intent.
	Transcode(ctx context.Context, intent plate.Intent, src, dst string) error
}

// FFmpegTranscoder is the real Transcoder, shelling to ffmpeg.
type FFmpegTranscoder struct {
	ffmpegPath string
	preset     string // encode preset; empty → mediaspec default
	timeout    time.Duration
}

// NewFFmpegTranscoder builds a transcoder. ffmpegPath empty → "ffmpeg" on PATH
// (spec §Q4 / PLATE_FFMPEG_PATH). timeout bounds a single transcode.
func NewFFmpegTranscoder(ffmpegPath, preset string, timeout time.Duration) *FFmpegTranscoder {
	if ffmpegPath == "" {
		ffmpegPath = "ffmpeg"
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute // a 12-min ProRes master is minutes of ffmpeg (spec §5.2)
	}
	return &FFmpegTranscoder{ffmpegPath: ffmpegPath, preset: preset, timeout: timeout}
}

var _ Transcoder = (*FFmpegTranscoder)(nil)

// Transcode dispatches on intent, building args from mediaspec. `detail` carries
// audio at ≤1080p; `loop` is silent at ~640px; `poster` is a single still frame.
// All video outputs are faststart via mediaspec (unconditional, spec §5.5).
func (t *FFmpegTranscoder) Transcode(ctx context.Context, intent plate.Intent, src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("worker: mkdir transcode dst: %w", err)
	}

	var args []string
	switch intent {
	case plate.Detail:
		args = mediaspec.DetailArgs(src, dst, t.preset)
	case plate.Loop:
		args = mediaspec.LoopArgs(src, dst, t.preset)
	case plate.Poster:
		args = posterArgs(src, dst)
	default:
		return fmt.Errorf("worker: intent %q is not an A/V transcode intent", intent)
	}

	cctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, t.ffmpegPath, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("worker: ffmpeg %s failed: %w\n%s", intent, err, out)
	}
	return nil
}

// posterArgs extracts a single still frame (the `poster` intent, spec §4.1). Not
// a video output, so no faststart applies; it is one keyframe as a JPEG.
func posterArgs(src, dst string) []string {
	return []string{
		"-hide_banner", "-y", "-i", src,
		"-frames:v", "1",
		"-q:v", "3",
		dst,
	}
}
