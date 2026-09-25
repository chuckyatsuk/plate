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

// MinIOImage is the S3 stand-in every e2e test runs against. It is a MIRROR of
// quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z.hotfix.c630804a1 (linux/amd64),
// republished unmodified (AGPL-3.0) to our own public GHCR package. MinIO closed
// anonymous pulls on Docker Hub (2026-09-12) and then on quay.io (2026-09-25),
// each time turning CI red for every PR; an image we host cannot be withdrawn
// under us. PINNED to a release tag, never :latest. The image is amd64-only, so
// callers pin the platform (native on CI, emulated on Apple-Silicon dev). Every
// MinIO container in the suite uses this one constant, so they cannot drift.
const MinIOImage = "ghcr.io/chuckyatsuk/minio:RELEASE.2025-04-22T22-12-26Z"

// StartMinIO launches a MinIO container, creates the bucket, and returns a
// Storage client pointed at it. It skips the test (via RequireDocker) when Docker
// is unavailable, like the other container-backed helpers.
func StartMinIO(t *testing.T, bucket string) *MinIO {
	t.Helper()
	RequireDocker(t)

	ctx := context.Background()
	const user, pass = "plate", "plate-secret"

	c, err := tcminio.Run(ctx, MinIOImage,
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
