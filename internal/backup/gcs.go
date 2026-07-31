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
	// Create writes an object if and only if it does not already exist.
	// An already-existing object is success: object names are
	// content-addressed, so an existing object IS the bytes we were about
	// to write (a completed earlier attempt or an unchanged re-pause).
	Create(ctx context.Context, object string, r io.Reader) error
}

// GCSStore implements BlobStore against a bucket using ifGenerationMatch=0
// preconditions. The write path never reads: a precondition failure (412)
// is the dedupe signal, not an error.
type GCSStore struct {
	bucket *storage.BucketHandle
}

// NewGCSStore builds a store for the cell's backup bucket.
func NewGCSStore(client *storage.Client, bucket string) *GCSStore {
	return &GCSStore{bucket: client.Bucket(bucket)}
}

func (s *GCSStore) Create(ctx context.Context, object string, r io.Reader) error {
	w := s.bucket.Object(object).If(storage.Conditions{DoesNotExist: true}).NewWriter(ctx)
	// Resumable-upload chunking: disk artifacts reach GiBs apparent but
	// pack to tens of MB; 16MiB chunks keep memory bounded either way.
	w.ChunkSize = 16 << 20
	if _, err := io.Copy(w, r); err != nil {
		_ = w.Close()
		if isPreconditionExists(err) {
			return nil
		}
		return fmt.Errorf("write %s: %w", object, err)
	}
	if err := w.Close(); err != nil {
		if isPreconditionExists(err) {
			return nil
		}
		return fmt.Errorf("finalize %s: %w", object, err)
	}
	return nil
}

func isPreconditionExists(err error) bool {
	var apiErr *googleapi.Error
	return errors.As(err, &apiErr) && apiErr.Code == 412
}
