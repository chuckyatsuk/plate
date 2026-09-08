package harness

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

var (
	dockerOnce sync.Once
	dockerOK   bool
)

// dockerAvailable probes for a working Docker daemon once. Testcontainers needs
// it; GitHub-hosted runners have it by default, and it is up on a typical dev
// machine. When it is absent the container-backed tests skip cleanly rather than
// hard-fail — the suite still runs its pure and ffmpeg-only artifact checks.
func dockerAvailable() bool {
	dockerOnce.Do(func() {
		if os.Getenv("PLATE_TEST_NO_DOCKER") != "" {
			dockerOK = false
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		provider, err := testcontainers.NewDockerProvider()
		if err != nil {
			dockerOK = false
			return
		}
		defer provider.Close()
		if err := provider.Health(ctx); err != nil {
			dockerOK = false
			return
		}
		dockerOK = true
	})
	return dockerOK
}

// RequireDocker skips the test unless a Docker daemon is reachable. The skip
// message is explicit so a green run that quietly skipped the imgproxy/Postgres
// artifact tests is visible, not silent.
func RequireDocker(t *testing.T) {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("no reachable Docker daemon; container-backed artifact tests need one (set nothing special in CI — GitHub runners have Docker)")
	}
}
