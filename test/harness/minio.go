package harness

import (
	"context"
	"testing"

	"github.com/chuckyatsuk/plate/internal/storage"
	testcontainers "github.com/testcontainers/testcontainers-go"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

// MinIO is a running MinIO container plus a Storage client wired to it. MinIO is
// S3-compatible, which is the whole point (spec Q5: "S3-compatible, so a
// self-hoster points it at any S3") — so the write path is verified against REAL
// S3 semantics with no credentials and no live R2, the same ephemeral-infra win
// as the Postgres and imgproxy containers.
//
// ⚠️ MinIO is NOT R2. Presign behaviour is close but not identical; a green MinIO
// suite is not a claim about R2. Keep one manual smoke against real R2 before
// trusting the write path in production (condition C2).
type MinIO struct {
	Storage  *storage.S3
	Endpoint string
	Bucket   string
}

// StartMinIO launches a MinIO container, creates the bucket, and returns a
// Storage client pointed at it. It skips the test (via RequireDocker) when Docker
// is unavailable, like the other container-backed helpers.
func StartMinIO(t *testing.T, bucket string) *MinIO {
	t.Helper()
	RequireDocker(t)

	ctx := context.Background()
	const user, pass = "plate", "plate-secret"

	// Pinned MinIO image, pulled from quay.io — NOT Docker Hub. Docker Hub now
	// denies anonymous pulls of minio/minio (HTTP 401 "may require docker login",
	// its anonymous rate-limit), which turned CI red for every PR (2026-09-12);
	// quay.io serves the same image anonymously. PINNED to a RELEASE tag, not
	// :latest — the unpinned tag is what made this a time-bomb (green until the
	// registry policy shifted). The quay image is linux/amd64-only, so pin the
	// platform explicitly: native on CI (ubuntu amd64), emulated on Apple-Silicon
	// dev (without this, arm64 hosts fail with "no matching manifest for arm64").
	// Keep it pinned + on quay + amd64; bump the tag deliberately.
	c, err := tcminio.Run(ctx, "quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z.hotfix.c630804a1",
		tcminio.WithUsername(user),
		tcminio.WithPassword(pass),
		testcontainers.WithImagePlatform("linux/amd64"),
	)
	if err != nil {
		t.Fatalf("harness: start minio: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	endpoint, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("harness: minio connection string: %v", err)
	}
	// ConnectionString is host:port; the SDK needs a scheme.
	base := "http://" + endpoint

	st, err := storage.New(ctx, storage.Config{
		Endpoint:     base,
		Region:       "us-east-1", // MinIO default; irrelevant but must be set
		AccessKey:    user,
		SecretKey:    pass,
		Bucket:       bucket,
		UsePathStyle: true, // MinIO requires path-style addressing
	})
	if err != nil {
		t.Fatalf("harness: build storage client: %v", err)
	}
	if err := st.EnsureBucket(ctx); err != nil {
		t.Fatalf("harness: create bucket: %v", err)
	}

	return &MinIO{Storage: st, Endpoint: base, Bucket: bucket}
}
