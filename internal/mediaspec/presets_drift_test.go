package mediaspec_test

// Preset-drift guard (spec C1; designer 2026-09-10): the imgproxy DEPLOY config
// hard-codes IMGPROXY_PRESETS as a literal string (a prebuilt-image env can't call
// `plate imgproxy-presets`), so it can silently drift from mediaspec.PresetDefs()
// — the single source the image-clamp tests verify against. This test reads the
// committed deploy/fly.imgproxy.toml and asserts its IMGPROXY_PRESETS line equals
// PresetDefs(), so a preset change that isn't mirrored into the deploy fails CI
// instead of shipping an imgproxy that transforms to the wrong dimensions.

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
)

func TestImgproxyDeployPresetsMatchMediaspec(t *testing.T) {
	const tomlPath = "../../deploy/fly.imgproxy.toml"
	raw, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatalf("read %s: %v", tomlPath, err)
	}
	// IMGPROXY_PRESETS = "…"
	re := regexp.MustCompile(`(?m)^\s*IMGPROXY_PRESETS\s*=\s*"([^"]*)"`)
	m := re.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("no IMGPROXY_PRESETS line in %s", tomlPath)
	}
	got := strings.TrimSpace(string(m[1]))
	want := mediaspec.PresetDefs()
	if got != want {
		t.Fatalf("deploy IMGPROXY_PRESETS has drifted from mediaspec.PresetDefs():\n deploy:    %q\n mediaspec: %q\nRegenerate the line: go run ./cmd/plate imgproxy-presets", got, want)
	}

	// The result-edge belt must also match mediaspec — same drift risk (a literal in
	// the deploy env can silently diverge from the single source), and it is a
	// LOAD-BEARING clamp: it backstops the per-preset caps so no result edge can
	// exceed the area ceiling. A deploy that drops or raises it would let the
	// square-source area breach through.
	reDim := regexp.MustCompile(`(?m)^\s*IMGPROXY_MAX_RESULT_DIMENSION\s*=\s*"([^"]*)"`)
	md := reDim.FindSubmatch(raw)
	if md == nil {
		t.Fatalf("no IMGPROXY_MAX_RESULT_DIMENSION line in %s — the result-edge belt (mediaspec.MaxResultDimension=%d) must be set in the deploy config", tomlPath, mediaspec.MaxResultDimension)
	}
	gotDim := strings.TrimSpace(string(md[1]))
	wantDim := strconv.Itoa(mediaspec.MaxResultDimension)
	if gotDim != wantDim {
		t.Fatalf("deploy IMGPROXY_MAX_RESULT_DIMENSION=%q has drifted from mediaspec.MaxResultDimension=%q", gotDim, wantDim)
	}
}
