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
}
