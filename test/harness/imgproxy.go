package harness

import (
	"context"
	"fmt"
	"image"
	_ "image/jpeg" // register decoders so image.DecodeConfig measures real output pixels
	_ "image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Imgproxy is a running imgproxy container plus the fixture root mounted into it.
// It is the real transform engine the service delegates image work to (spec §2:
// imgproxy, ONLY_PRESETS). Tests render through it and DECODE the bytes it
// returns, so the megapixel and decoded-memory clamps are checked against the
// true output dimensions of a real rendition — never against "the clamp function
// was called".
type Imgproxy struct {
	container testcontainers.Container
	baseURL   string
	fixtureRoot string
}

// Presets configured on the imgproxy container. These come from mediaspec — the
// SAME preset definitions the service builds delivery URLs against and the
// compose/production config serves (condition C1), so the presets these tests
// verify are the presets production serves. `ONLY_PRESETS` is on, so imgproxy
// REFUSES ad-hoc width/quality params in the URL — the structural property the
// spec relies on (a caller names a purpose, never a transformation, spec §4.1).
//
// The width targets encode the intent's bound: lightbox is clamped to the
// megapixel wall (~24MP → 2048 longest edge) and the mobile-budget preset is
// clamped tighter so a decoded RGBA frame fits the 24MiB mobile budget (spec
// §4.2). The tests assert the DECODED result honours these.
const (
	PresetLightbox       = mediaspec.PresetLightbox       // megapixel-wall clamp
	PresetLightboxMobile = mediaspec.PresetLightboxMobile // decoded-memory clamp (mobile budget)
	PresetThumbnail      = mediaspec.PresetThumbnail
	// Zoom ladder (Phase 3 A2): desktop deep-zoom rungs, decoded-memory clamped.
	PresetZoom1 = mediaspec.PresetZoom1
	PresetZoom2 = mediaspec.PresetZoom2
	PresetZoom3 = mediaspec.PresetZoom3
)

// imgproxyPresets is the IMGPROXY_PRESETS value, generated from mediaspec so the
// widths cannot drift from what the service and compose file use.
var imgproxyPresets = mediaspec.PresetDefs()

// StartImgproxy launches imgproxy with presets and ONLY_PRESETS, mounting
// fixtureRoot as its local source so tests can point at fixture files by name.
// It skips the test (via RequireDocker) when Docker is unavailable.
func StartImgproxy(t *testing.T, fixtureRoot string) *Imgproxy {
	t.Helper()
	RequireDocker(t)

	abs, err := filepath.Abs(fixtureRoot)
	if err != nil {
		t.Fatalf("harness: abs fixtureRoot: %v", err)
	}

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        imgproxyImage(),
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"IMGPROXY_ALLOW_UNSAFE_URL":      "1", // test-only; production signs URLs
			"IMGPROXY_ONLY_PRESETS":          "1", // refuse ad-hoc params (spec §4.1)
			"IMGPROXY_PRESETS":               imgproxyPresets,
			"IMGPROXY_LOCAL_FILESYSTEM_ROOT": "/imgs",
			// Allow a large source so a 24MP+ input is CLAMPED, not rejected as
			// oversized — the incident is "returns a clamped rendition, never a
			// 400" (spec §7). 100MP headroom covers Uri's 96MP shots.
			"IMGPROXY_MAX_SRC_RESOLUTION": "100",
		},
		Files: []testcontainers.ContainerFile{},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, abs+":/imgs:ro")
		},
		WaitingFor: wait.ForListeningPort("8080/tcp").WithStartupTimeout(60 * time.Second),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("harness: start imgproxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("harness: imgproxy host: %v", err)
	}
	port, err := c.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("harness: imgproxy port: %v", err)
	}

	return &Imgproxy{
		container:   c,
		baseURL:     fmt.Sprintf("http://%s:%s", host, port.Port()),
		fixtureRoot: abs,
	}
}

func imgproxyImage() string {
	if v := os.Getenv("PLATE_TEST_IMGPROXY_IMAGE"); v != "" {
		return v
	}
	return "darthsim/imgproxy:latest"
}

// RenderConfig fetches only the DecodeConfig (dimensions) of a preset render of
// the named fixture file. It goes over real HTTP to the real engine and decodes
// the response, so the returned width/height are the true output pixels — the
// artifact, not a claimed size.
func (ip *Imgproxy) RenderConfig(t *testing.T, preset, fixtureName string) (cfg image.Config, status int) {
	t.Helper()
	body, status := ip.render(t, preset, fixtureName)
	if status != http.StatusOK {
		return image.Config{}, status
	}
	defer body.Close()
	c, _, err := image.DecodeConfig(body)
	if err != nil {
		t.Fatalf("harness: decode rendition config (preset %s, %s): %v", preset, fixtureName, err)
	}
	return c, status
}

// RenderStatus returns just the HTTP status of a preset render, for the "24MP
// input returns 200 not 400" assertion.
func (ip *Imgproxy) RenderStatus(t *testing.T, preset, fixtureName string) int {
	t.Helper()
	body, status := ip.render(t, preset, fixtureName)
	if body != nil {
		_, _ = io.Copy(io.Discard, body)
		body.Close()
	}
	return status
}

func (ip *Imgproxy) render(t *testing.T, preset, fixtureName string) (io.ReadCloser, int) {
	t.Helper()
	// ONLY_PRESETS mode: the preset name is the bare first processing segment —
	// `unsafe/<preset>/plain/local:///file`. The explicit `preset:<name>` option
	// form is REJECTED under ONLY_PRESETS, which is exactly the property the spec
	// leans on: imgproxy refuses ad-hoc params, so a caller can only name a
	// purpose (spec §4.1). @jpg names the output format.
	url := fmt.Sprintf("%s/unsafe/%s/plain/local:///%s@jpg", ip.baseURL, preset, fixtureName)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("harness: build render request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("harness: render request to imgproxy: %v", err)
	}
	return resp.Body, resp.StatusCode
}

// SynthImage writes a real image of exactly w×h pixels into the fixture root
// using ffmpeg's testsrc. Used to build a 24MP+ source for the clamp tests.
func SynthImage(t *testing.T, fixtureRoot, name string, w, h int) string {
	t.Helper()
	RequireFFmpeg(t)
	path := filepath.Join(fixtureRoot, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("harness: mkdir fixture root: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpegBin(),
		"-hide_banner", "-y",
		"-f", "lavfi", "-i", fmt.Sprintf("testsrc=size=%dx%d:duration=1:rate=1", w, h),
		"-frames:v", "1", path,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harness: SynthImage ffmpeg failed: %v\n%s", err, out)
	}
	return path
}
