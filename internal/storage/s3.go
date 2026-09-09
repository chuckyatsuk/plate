package storage

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3 is the Storage implementation over an S3-compatible endpoint (R2 in
// production; MinIO in tests; any S3 for a self-hoster). It holds the derivative-
// path credentials and mints presigned URLs for the broker/download paths.
type S3 struct {
	client  *s3.Client
	presign *s3.PresignClient
	bucket  string
}

// Config configures the S3 client. In production these come from R2_* env vars
// (spec §Q4 / .env.example); in tests they point at the MinIO container.
type Config struct {
	Endpoint     string // https://<account>.r2.cloudflarestorage.com (or MinIO URL)
	Region       string // "auto" for R2
	AccessKey    string
	SecretKey    string
	Bucket       string
	UsePathStyle bool // MinIO needs path-style; R2 works with it too
}

// New builds an S3-backed Storage.
func New(ctx context.Context, cfg Config) (*S3, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("storage: bucket is required")
	}
	client := s3.New(s3.Options{
		Region:       orAuto(cfg.Region),
		BaseEndpoint: aws.String(cfg.Endpoint),
		UsePathStyle: cfg.UsePathStyle,
		Credentials: credentials.NewStaticCredentialsProvider(
			cfg.AccessKey, cfg.SecretKey, ""),
		// S3-compatible backends (R2, MinIO) do not all handle aws-sdk-go-v2's
		// default request-checksum trailer (CRC32 over aws-chunked streaming). With
		// it on, a PutObject can "succeed" while the object is never stored — a
		// silent empty write (the deployed-smoke bug). Only send a checksum when the
		// operation requires one; this is the standard setting for non-AWS S3.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return &S3{
		client:  client,
		presign: s3.NewPresignClient(client),
		bucket:  cfg.Bucket,
	}, nil
}

func orAuto(r string) string {
	if r == "" {
		return "auto"
	}
	return r
}

// PresignPut mints a presigned PUT bound to the key, content-type, and
// content-length ceiling (spec Q3.C). Binding ContentType and ContentLength into
// the PutObjectInput makes them part of the signed request, so R2/S3 REJECTS a
// PUT that declares a different type or a larger length — which is exactly what
// the MinIO test asserts (condition C2: assert the negative). The account
// isolation boundary rides on Key here: a PUT can only write this one object.
func (s *S3) PresignPut(ctx context.Context, c PutConstraints) (PresignedPut, error) {
	if c.Expiry <= 0 {
		c.Expiry = time.Hour
	}
	in := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(c.Key),
		ContentType: aws.String(c.ContentType),
	}
	// ContentLength binds the EXACT body size into the signature. S3/R2 enforce
	// the signed content-length, so a body of any other size (larger OR smaller)
	// fails the PUT — which bounds the object to exactly what the caller declared.
	if c.ContentLength > 0 {
		in.ContentLength = aws.Int64(c.ContentLength)
	}
	req, err := s.presign.PresignPutObject(ctx, in, s3.WithPresignExpires(c.Expiry))
	if err != nil {
		return PresignedPut{}, fmt.Errorf("storage: presign put: %w", err)
	}
	headers := map[string]string{}
	for k, v := range req.SignedHeader {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	// Ensure the browser sends the content-type it was signed for.
	headers["Content-Type"] = c.ContentType
	return PresignedPut{
		URL:     req.URL,
		Method:  req.Method,
		Headers: headers,
		Expires: time.Now().Add(c.Expiry),
	}, nil
}

// PresignGet mints a short-lived authenticated download URL — the
// `intent=original` escape hatch (spec §4.1).
func (s *S3) PresignGet(ctx context.Context, key string, expiry time.Duration) (string, error) {
	if expiry <= 0 {
		expiry = 5 * time.Minute
	}
	req, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", fmt.Errorf("storage: presign get: %w", err)
	}
	return req.URL, nil
}

// Head confirms an object landed and reads its true size/type (spec §5.3). A
// missing object returns Exists=false, not an error, so finalize can distinguish
// "not uploaded yet" from a real failure.
func (s *S3) Head(ctx context.Context, key string) (ObjectInfo, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return ObjectInfo{Exists: false}, nil
		}
		return ObjectInfo{}, fmt.Errorf("storage: head %s: %w", key, err)
	}
	info := ObjectInfo{Exists: true}
	if out.ContentLength != nil {
		info.Size = *out.ContentLength
	}
	if out.ContentType != nil {
		info.ContentType = *out.ContentType
	}
	if out.ETag != nil {
		info.ETag = *out.ETag
	}
	return info, nil
}

// Get streams an object — the worker pulling a vault original.
func (s *S3) Get(ctx context.Context, key string) (ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: get %s: %w", key, err)
	}
	return out.Body, nil
}

// GetRange streams bytes [start, start+length) via an HTTP Range request, so the
// image probe reads only the header instead of the whole original.
func (s *S3) GetRange(ctx context.Context, key string, start, length int64) (ReadCloser, error) {
	rng := fmt.Sprintf("bytes=%d-%d", start, start+length-1)
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Range:  aws.String(rng),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: get range %s %s: %w", key, rng, err)
	}
	return out.Body, nil
}

// Put writes bytes — the worker writing a rendition.
func (s *S3) Put(ctx context.Context, key, contentType string, r io.Reader, size int64) error {
	in := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        r,
		ContentType: aws.String(contentType),
	}
	if size > 0 {
		in.ContentLength = aws.Int64(size)
	}
	if _, err := s.client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("storage: put %s: %w", key, err)
	}
	return nil
}

// Delete removes an object (reconciliation, two-step delete).
func (s *S3) Delete(ctx context.Context, key string) error {
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}); err != nil {
		return fmt.Errorf("storage: delete %s: %w", key, err)
	}
	return nil
}

// EnsureBucket creates the bucket if it does not exist — used by tests (and
// harmless to call against R2 where the bucket is pre-created). Not part of the
// Storage interface; it's a setup convenience.
func (s *S3) EnsureBucket(ctx context.Context) error {
	_, err := s.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(s.bucket),
	})
	if err != nil {
		var owned *types.BucketAlreadyOwnedByYou
		var exists *types.BucketAlreadyExists
		if errorsAs(err, &owned) || errorsAs(err, &exists) {
			return nil
		}
		return fmt.Errorf("storage: ensure bucket %s: %w", s.bucket, err)
	}
	return nil
}

var _ Storage = (*S3)(nil)
