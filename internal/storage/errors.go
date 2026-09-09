package storage

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// isNotFound reports whether an S3 error is a "no such key / not found" so Head
// can return Exists=false rather than a hard error (spec §5.3: finalize must tell
// "not uploaded yet" from a real failure). It matches both the typed NoSuchKey /
// NotFound and the generic smithy API error codes, since S3-compatible backends
// (R2, MinIO) vary in which they return.
func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}

// errorsAs is a thin wrapper so s3.go can classify bucket-exists errors without
// importing errors directly in that file.
func errorsAs(err error, target any) bool { return errors.As(err, target) }
