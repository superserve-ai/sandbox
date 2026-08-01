package backup

import (
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
)

// BlobStore is the narrow surface the uploader needs: create-only object
// writes. The host identity holds objectCreator and nothing else, so there
// is deliberately no read, list, or delete here.
type BlobStore interface {
	// Create writes an object if and only if it does not already exist,
	// reporting whether THIS call created it. created=false (the object
	// already existed) is not an error, but callers must not infer
	// anything about the existing bytes from it: with small objects the
	// writer buffers the whole stream before the precondition failure
	// arrives, so stream consumption says nothing about what is stored.
	Create(ctx context.Context, object string, r io.Reader) (created bool, err error)
	// Identity names the destination (the bucket) so verification
	// records can be scoped to it: history earned against one bucket
	// proves nothing about another.
	Identity() string
}

// GCSStore implements BlobStore against a bucket using ifGenerationMatch=0
// preconditions. The write path never reads: a precondition failure (412)
// is the dedupe signal, not an error.
type GCSStore struct {
	bucket *storage.BucketHandle
	name   string
}

// NewGCSStore builds a store for the cell's backup bucket.
func NewGCSStore(client *storage.Client, bucket string) *GCSStore {
	return &GCSStore{bucket: client.Bucket(bucket), name: bucket}
}

func (s *GCSStore) Identity() string { return s.name }

func (s *GCSStore) Create(ctx context.Context, object string, r io.Reader) (bool, error) {
	// The writer gets its own cancelable context: on a mid-copy failure the
	// resumable session must be ABORTED, not closed. Close after a partial
	// copy would finalize a truncated object, and create-only semantics
	// would then turn every retry into a 412 "success" over corrupt bytes.
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := s.bucket.Object(object).If(storage.Conditions{DoesNotExist: true}).NewWriter(wctx)
	// Resumable-upload chunking: disk artifacts reach GiBs apparent but
	// pack to tens of MB; 16MiB chunks keep memory bounded either way.
	w.ChunkSize = 16 << 20
	if _, err := io.Copy(w, r); err != nil {
		if isPreconditionExists(err) {
			cancel()
			_ = w.Close()
			return false, nil
		}
		cancel() // abort the session so Close cannot finalize partial data
		_ = w.Close()
		return false, fmt.Errorf("write %s: %w", object, err)
	}
	if err := w.Close(); err != nil {
		if isPreconditionExists(err) {
			return false, nil
		}
		return false, fmt.Errorf("finalize %s: %w", object, err)
	}
	return true, nil
}

func isPreconditionExists(err error) bool {
	var apiErr *googleapi.Error
	return errors.As(err, &apiErr) && apiErr.Code == 412
}
