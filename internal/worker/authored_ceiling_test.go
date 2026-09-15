package worker

// Authored-rendition ceilings (Tier 2 V4.1). authoredCeilingBreach is the gate that
// makes "authored = no transcode" safe: a studio file is accepted only if it is
// already within the intent's bounds, so the remux is a pure stream-copy. Each
// breach must name the single limit it broke, and a good file must pass — proven by
// BREAKING each ceiling (the discipline that caught the unbounded-loop bug: assert
// against the artifact/the real check, not the intent).
//
// These drive the check with probe.Result values directly (fast, exhaustive over
// every breach). The complement — that a REAL H.264/AAC file's ffprobe output
// passes, and that the probe extension actually reports the audio codec — is
// covered end to end by the authored-rendition e2e in test/ (real ffmpeg + remux).

import (
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/probe"
)

func TestAuthoredCeilingBreach_NamesTheLimit(t *testing.T) {
	// A well-formed baseline for each intent that PASSES, so each case below breaks
	// exactly one thing.
	okDetail := probe.Result{Kind: plate.Video, Codec: "h264", AudioCodec: "aac", Width: 1920, Height: 1080, DurationS: 600, BitrateBPS: 6_000_000}
	okLoop := probe.Result{Kind: plate.Video, Codec: "h264", AudioCodec: "", Width: 640, Height: 360, DurationS: 8, BitrateBPS: 1_000_000}

	cases := []struct {
		name   string
		intent plate.Intent
		pr     probe.Result
		want   plate.ReasonCode // "" means "must pass"
	}{
		{"detail ok", plate.Detail, okDetail, ""},
		{"loop ok", plate.Loop, okLoop, ""},
		// A portrait studio loop (Favourite: 640×1138) — long edge 1138, over the old
		// 640 cap, under the 1080 one. Must PASS: the viewer ceiling is bitrate+duration.
		{"loop portrait 640x1138 passes", plate.Loop, mut(okLoop, func(r *probe.Result) { r.Width, r.Height = 640, 1138; r.DurationS = 8; r.BitrateBPS = 260_000 }), ""},

		// detail breaches
		{"detail non-h264 video", plate.Detail, mut(okDetail, func(r *probe.Result) { r.Codec = "vp9" }), plate.ReasonCodeAuthoredCodecUnsupported},
		{"detail non-aac audio", plate.Detail, mut(okDetail, func(r *probe.Result) { r.AudioCodec = "opus" }), plate.ReasonCodeAuthoredCodecUnsupported},
		{"detail over 1080p", plate.Detail, mut(okDetail, func(r *probe.Result) { r.Width, r.Height = 3840, 2160 }), plate.ReasonCodeAuthoredResolutionExceeded},
		{"detail over 8Mbps", plate.Detail, mut(okDetail, func(r *probe.Result) { r.BitrateBPS = 20_000_000; r.DurationS = 5 }), plate.ReasonCodeAuthoredBitrateExceeded},

		// loop breaches
		{"loop non-h264", plate.Loop, mut(okLoop, func(r *probe.Result) { r.Codec = "vp9" }), plate.ReasonCodeAuthoredCodecUnsupported},
		{"loop over 1920px long edge", plate.Loop, mut(okLoop, func(r *probe.Result) { r.Width, r.Height = 3840, 2160 }), plate.ReasonCodeAuthoredResolutionExceeded},
		{"loop over 30s", plate.Loop, mut(okLoop, func(r *probe.Result) { r.DurationS = 45 }), plate.ReasonCodeAuthoredLoopTooLong},
		{"loop over 2Mbps", plate.Loop, mut(okLoop, func(r *probe.Result) { r.BitrateBPS = 5_000_000 }), plate.ReasonCodeAuthoredBitrateExceeded},

		// size backstop (any intent): a huge file by bitrate×duration
		{"detail too large", plate.Detail, mut(okDetail, func(r *probe.Result) { r.BitrateBPS = 7_000_000; r.DurationS = 3600 }), plate.ReasonCodeAuthoredTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := authoredCeilingBreach(tc.intent, tc.pr)
			if tc.want == "" {
				if !ok {
					t.Fatalf("expected pass, got refusal %q", reason)
				}
				return
			}
			if ok {
				t.Fatalf("expected refusal %q, but it passed", tc.want)
			}
			if reason != tc.want {
				t.Fatalf("wrong reason: got %q, want %q", reason, tc.want)
			}
		})
	}
}

func mut(base probe.Result, f func(*probe.Result)) probe.Result {
	r := base
	f(&r)
	return r
}
