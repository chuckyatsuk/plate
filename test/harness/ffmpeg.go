package harness

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
)

// ffmpegBin / ffprobeBin resolve the engines from PATH, honouring the same env
// var names the service uses (spec §Q4, PLATE_FFMPEG_PATH / PLATE_FFPROBE_PATH)
// so a CI runner or a self-hoster can point at a specific build.
func ffmpegBin() string {
	if p := os.Getenv("PLATE_FFMPEG_PATH"); p != "" {
		return p
	}
	return "ffmpeg"
}

func ffprobeBin() string {
	if p := os.Getenv("PLATE_FFPROBE_PATH"); p != "" {
		return p
	}
	return "ffprobe"
}

// SynthVideo builds a real MP4 at path using ffmpeg's synthetic sources
// (testsrc video + optional sine audio). It is deliberately NOT faststart —
// the raw ingest artifact a studio hands over (HandBrake omits faststart; that
// is the landmine, spec §5.5). Duration is honoured exactly, so a test can
// build a source just over a ceiling cheaply: a 13-minute clip at a tiny frame
// size and low rate is a few hundred KB, not a real master.
//
// It returns the path for chaining. It t.Fatal-s on any ffmpeg failure — a
// broken fixture is a broken test, not a skip.
func SynthVideo(t *testing.T, path string, dur time.Duration, withAudio bool) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("harness: mkdir for fixture: %v", err)
	}
	secs := strconv.FormatFloat(dur.Seconds(), 'f', -1, 64)

	args := []string{
		"-hide_banner", "-y",
		"-f", "lavfi", "-i", "testsrc=duration=" + secs + ":size=160x120:rate=10",
	}
	if withAudio {
		args = append(args, "-f", "lavfi", "-i", "sine=frequency=440:duration="+secs)
	}
	args = append(args,
		"-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
	)
	if withAudio {
		args = append(args, "-c:a", "aac", "-shortest")
	}
	// -movflags is deliberately NOT set here: this is the pre-service raw source.
	args = append(args, path)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpegBin(), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harness: SynthVideo ffmpeg failed: %v\n%s", err, out)
	}
	return path
}

// TranscodeDetail is a stand-in for the Plate worker's `detail`-intent transcode
// (spec §4.1: <=1080p, with audio). It is the smallest honest version of what
// the service will run: it applies faststart AT THE PRESET LAYER, exactly as the
// spec mandates it be unconditional and not a per-call switch (spec §5.5).
//
// The test that consumes its output does NOT trust that faststart was requested;
// it re-opens the produced file and walks the box order (IsFaststart). This is
// the seam described in the task: the stub produces a real artifact, and the
// assertion inspects the real artifact.
//
// When the service lands, this helper is replaced by a call to the real worker;
// the assertion against the output MP4 does not change.
func TranscodeDetail(t *testing.T, src, dst string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("harness: mkdir for transcode dst: %v", err)
	}
	// The args come from mediaspec — the SAME constants the real worker uses
	// (condition C1). Only the encode preset differs (ultrafast for cheap
	// fixtures), which does not affect the box order the faststart test checks.
	args := mediaspec.DetailArgs(src, dst, "ultrafast")
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpegBin(), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harness: TranscodeDetail ffmpeg failed: %v\n%s", err, out)
	}
	return dst
}

// RemuxCopy is the stream-copy path (spec §5.5: an already-web-safe source is
// remuxed, not re-encoded — a rendition may point at a verified original). The
// spec requires faststart on THIS path too, so a remux-only pass is still
// progressive. The test verifies the copied output's box order, catching the
// exact regression where faststart is applied on the encode path but forgotten
// on the copy path.
func RemuxCopy(t *testing.T, src, dst string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("harness: mkdir for remux dst: %v", err)
	}
	args := mediaspec.RemuxCopyArgs(src, dst)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpegBin(), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harness: RemuxCopy ffmpeg failed: %v\n%s", err, out)
	}
	return dst
}

// ProbeResult is the subset of ffprobe output the ingest verification cares
// about (spec §5.3): true duration, dimensions, codec, container. This mirrors
// what the service records on the VaultObject, and is how a test measures the
// real duration of a real file rather than trusting the number it asked for.
type ProbeResult struct {
	DurationS float64
	Width     int
	Height    int
	Codec     string
	Container string
}

// Probe runs ffprobe against a real file and returns its measured properties.
// This is the artifact-truth for the duration ceiling: the ceiling check runs
// against what ffprobe MEASURES, not against a duration the test asserts by
// fiat.
func Probe(t *testing.T, path string) ProbeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffprobeBin(),
		"-hide_banner", "-v", "error",
		"-show_entries", "format=duration,format_name",
		"-show_entries", "stream=codec_name,width,height,codec_type",
		"-of", "json", path,
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("harness: ffprobe failed on %s: %v", path, err)
	}

	var parsed struct {
		Format struct {
			Duration   string `json:"duration"`
			FormatName string `json:"format_name"`
		} `json:"format"`
		Streams []struct {
			CodecName string `json:"codec_name"`
			CodecType string `json:"codec_type"`
			Width     int    `json:"width"`
			Height    int    `json:"height"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("harness: parse ffprobe json: %v\n%s", err, out)
	}

	res := ProbeResult{Container: parsed.Format.FormatName}
	if parsed.Format.Duration != "" {
		if d, err := strconv.ParseFloat(parsed.Format.Duration, 64); err == nil {
			res.DurationS = d
		}
	}
	for _, s := range parsed.Streams {
		if s.CodecType == "video" {
			res.Width, res.Height, res.Codec = s.Width, s.Height, s.CodecName
			break
		}
	}
	return res
}

// HasAudioStream reports whether a file contains at least one audio stream. Used
// to verify the loop tier is SILENT (spec §5.4) — the artifact, not the flag: it
// asks ffprobe what streams the produced file actually has, rather than trusting
// that -an was passed.
func HasAudioStream(t *testing.T, path string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffprobeBin(),
		"-hide_banner", "-v", "error",
		"-select_streams", "a",
		"-show_entries", "stream=index",
		"-of", "csv=p=0", path,
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("harness: ffprobe audio check on %s: %v", path, err)
	}
	return len(bytesTrimSpace(out)) > 0
}

// bytesTrimSpace trims surrounding whitespace without importing bytes for one use.
func bytesTrimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

// FFmpegAvailable reports whether both ffmpeg and ffprobe are runnable. The AV
// tests skip cleanly when they are absent (a bare dev machine) but CI installs
// them, so the AV artifacts are actually verified there (spec §7 wants this in
// CI with no live services — ffmpeg is a static binary, not a service).
func FFmpegAvailable() bool {
	for _, bin := range []string{ffmpegBin(), ffprobeBin()} {
		if _, err := exec.LookPath(bin); err != nil {
			return false
		}
	}
	return true
}

// RequireFFmpeg skips the test unless the engines are present. It surfaces the
// reason so a green run that quietly skipped everything is visible.
func RequireFFmpeg(t *testing.T) {
	t.Helper()
	if !FFmpegAvailable() {
		t.Skipf("ffmpeg/ffprobe not on PATH (%s / %s); install them to run the A/V artifact tests", ffmpegBin(), ffprobeBin())
	}
}
