package plate_test

// Incident (spec §7): "every generated MP4 has moov before mdat — ffprobe the
// artifact, not the flag."
//
// Real, dated failure behind it (spec §5.5): HandBrake omits faststart by
// default; a browser then downloads the WHOLE file before it can paint a frame.
// AWS MediaConvert defaults MoovPlacement to NORMAL — the same trap at the API
// level. Because Plate's originals serve from R2, no vendor takes this off our
// hands.
//
// The house rule made concrete: this test does NOT assert that `-movflags
// +faststart` appeared on the ffmpeg command line. It re-opens the produced MP4,
// walks its top-level box structure, and asserts the `moov` atom physically
// precedes the `mdat` atom. That is the property a browser actually depends on,
// and it is true or false in the bytes regardless of what flags were passed. A
// negative control (a non-faststart file) proves the check can fail.

import (
	"path/filepath"
	"testing"

	"github.com/chuckyatsuk/plate/test/harness"
)

func TestGeneratedMP4_MoovBeforeMdat_OnEncodePath(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// A raw source as a studio would hand it over: NOT faststart.
	src := harness.SynthVideo(t, filepath.Join(dir, "source.mp4"), harness.Seconds(3), true)

	// The `detail`-intent transcode (stand-in for the worker) applies faststart
	// at the preset layer, per spec §5.5.
	out := harness.TranscodeDetail(t, src, filepath.Join(dir, "detail.mp4"))

	fast, err := harness.IsFaststart(out)
	if err != nil {
		t.Fatalf("walking box order of the produced MP4: %v", err)
	}
	if !fast {
		atoms, _ := harness.TopLevelAtoms(out)
		t.Fatalf("produced detail MP4 is NOT faststart: moov does not precede mdat.\ntop-level atoms: %+v", atoms)
	}
}

// The remux/stream-copy path is the one most likely to regress: a codebase can
// apply faststart on the re-encode path and forget it on the copy path (spec
// §5.5 requires it on BOTH). This asserts the copied output is progressive too.
func TestGeneratedMP4_MoovBeforeMdat_OnStreamCopyPath(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// Start from an already-web-safe H.264 file (encode once), then remux-copy it
	// — the "already web-safe 200MB H.264" case from spec §3.1.
	websafe := harness.TranscodeDetail(t,
		harness.SynthVideo(t, filepath.Join(dir, "raw.mp4"), harness.Seconds(3), true),
		filepath.Join(dir, "websafe.mp4"),
	)
	out := harness.RemuxCopy(t, websafe, filepath.Join(dir, "remuxed.mp4"))

	fast, err := harness.IsFaststart(out)
	if err != nil {
		t.Fatalf("walking box order of the remuxed MP4: %v", err)
	}
	if !fast {
		atoms, _ := harness.TopLevelAtoms(out)
		t.Fatalf("remux-copied MP4 is NOT faststart: moov does not precede mdat.\ntop-level atoms: %+v", atoms)
	}
}

// Negative control: the box-order check is only meaningful if it can distinguish
// a broken file. A plain (non-faststart) encode MUST report false. If this ever
// passes as faststart, the verifier is broken and every green result above is
// worthless.
func TestFaststartVerifier_RejectsNonFaststart(t *testing.T) {
	harness.RequireFFmpeg(t)
	dir := t.TempDir()

	// SynthVideo deliberately does not set -movflags, so ffmpeg writes mdat first.
	nonFast := harness.SynthVideo(t, filepath.Join(dir, "nonfast.mp4"), harness.Seconds(2), false)

	fast, err := harness.IsFaststart(nonFast)
	if err != nil {
		t.Fatalf("walking box order: %v", err)
	}
	if fast {
		atoms, _ := harness.TopLevelAtoms(nonFast)
		t.Fatalf("verifier called a non-faststart file faststart — the check is broken.\ntop-level atoms: %+v", atoms)
	}
}
