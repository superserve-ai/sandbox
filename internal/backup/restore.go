package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// ErrObjectNotFound reports a blob that does not exist in the store.
// BlobReader implementations wrap it so callers can distinguish absence
// from transport failure.
var ErrObjectNotFound = errors.New("object not found")

// ErrGenerationIncomplete reports a generation whose manifest object is
// absent. The manifest is written last, so its absence means the uploader
// never finished (or abandoned) this generation: some artifact objects may
// exist under the prefix, but the set is unverified and must never be
// restored from.
var ErrGenerationIncomplete = errors.New("generation incomplete: manifest object absent")

// BlobReader is the narrow read surface restore needs. It is the mirror of
// BlobStore: the restore identity holds objectViewer and nothing else.
type BlobReader interface {
	// NewReader opens the named object for reading. An absent object yields
	// an error wrapping ErrObjectNotFound.
	NewReader(ctx context.Context, object string) (io.ReadCloser, error)
}

// BlobLister enumerates object names under a prefix. Kept separate from
// BlobReader so RestoreGeneration does not demand list permission.
type BlobLister interface {
	List(ctx context.Context, prefix string) ([]string, error)
}

// GCSReader implements BlobReader and BlobLister against a bucket. The
// caller supplies the client and thus the credentials; which identity may
// read backups is a deployment concern, not a code one.
type GCSReader struct {
	bucket *storage.BucketHandle
}

// NewGCSReader builds a reader for the cell's backup bucket.
func NewGCSReader(client *storage.Client, bucket string) *GCSReader {
	return &GCSReader{bucket: client.Bucket(bucket)}
}

func (g *GCSReader) NewReader(ctx context.Context, object string) (io.ReadCloser, error) {
	r, err := g.bucket.Object(object).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, fmt.Errorf("%s: %w", object, ErrObjectNotFound)
		}
		return nil, fmt.Errorf("open %s: %w", object, err)
	}
	return r, nil
}

func (g *GCSReader) List(ctx context.Context, prefix string) ([]string, error) {
	it := g.bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	var names []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return names, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", prefix, err)
		}
		names = append(names, attrs.Name)
	}
}

// ListGenerations returns the complete (manifest-bearing) generations of a
// sandbox, sorted. Prefixes holding artifacts but no manifest are abandoned
// or in-flight uploads and are deliberately omitted: they are not
// restorable and listing them would only invite an operator to try.
func ListGenerations(ctx context.Context, lister BlobLister, sandboxID string) ([]string, error) {
	if err := validSegment(sandboxID); err != nil {
		return nil, fmt.Errorf("sandbox id: %w", err)
	}
	prefix := fmt.Sprintf("%s/%s/", sandboxPrefix, sandboxID)
	names, err := lister.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var generations []string
	for _, name := range names {
		rest := strings.TrimPrefix(name, prefix)
		gen, file, ok := strings.Cut(rest, "/")
		if ok && file == ManifestObject {
			generations = append(generations, gen)
		}
	}
	sort.Strings(generations)
	return generations, nil
}

// RestoreGeneration materializes one complete generation into destDir:
// fetch the manifest, rebuild each sparse artifact from its packed object
// and extent table, and verify every file's full apparent content against
// the manifest digest. destDir must be absent or an empty directory; on
// success it holds exactly the manifest's files, verified.
//
// Requiring a fresh destination is deliberate: restoring over existing
// content would truncate name-colliding files (and follow any symlinks
// planted there), and the failure cleanup below would then delete what it
// clobbered. A recovery tool must never destroy state it did not create.
//
// Failure handling is all-or-nothing: any fetch, write, or digest failure
// deletes every file this call created in destDir before returning. A
// partially restored directory that looks plausible is the dangerous
// outcome for a recovery tool; an empty one forces the operator (or the
// calling recovery flow) to retry or pick another generation, never to
// boot a half-verified sandbox.
func RestoreGeneration(ctx context.Context, r BlobReader, sandboxID, generation, destDir string) (*GenerationManifest, error) {
	manifest, err := fetchManifest(ctx, r, sandboxID, generation)
	if err != nil {
		return nil, err
	}
	if err := ensureFreshDir(destDir); err != nil {
		return nil, err
	}
	var created []string
	fail := func(err error) (*GenerationManifest, error) {
		for _, p := range created {
			os.Remove(p)
		}
		return nil, err
	}
	for _, mf := range manifest.Files {
		// The bucket is shared across the cell; never let a manifest name
		// escape destDir.
		if err := validSegment(mf.Name); err != nil {
			return fail(fmt.Errorf("manifest file name: %w", err))
		}
		dest := filepath.Join(destDir, mf.Name)
		created = append(created, dest)
		if err := restoreFile(ctx, r, sandboxID, generation, mf, dest); err != nil {
			return fail(fmt.Errorf("restore %s: %w", mf.Name, err))
		}
	}
	// Verify after every file has materialized so an error part way through
	// verification cannot leave earlier files implicitly blessed: either
	// the whole set passes or the whole set is gone.
	for _, mf := range manifest.Files {
		if err := verifyFile(ctx, filepath.Join(destDir, mf.Name), mf); err != nil {
			return fail(fmt.Errorf("verify %s: %w", mf.Name, err))
		}
	}
	return manifest, nil
}

// ensureFreshDir creates destDir (and parents) or accepts an existing but
// empty directory. Anything else is refused; see RestoreGeneration.
func ensureFreshDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("dest dir: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("dest dir: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("dest dir %s is not empty: restore refuses to overwrite existing content, use a fresh directory", dir)
	}
	return nil
}

func fetchManifest(ctx context.Context, r BlobReader, sandboxID, generation string) (*GenerationManifest, error) {
	object, err := SandboxObject(sandboxID, generation, ManifestObject)
	if err != nil {
		return nil, err
	}
	rc, err := r.NewReader(ctx, object)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			return nil, fmt.Errorf("%s/%s: %w", sandboxID, generation, ErrGenerationIncomplete)
		}
		return nil, err
	}
	defer rc.Close()
	var manifest GenerationManifest
	if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", object, err)
	}
	return &manifest, nil
}

// restoreFile streams a packed object into place: each extent's bytes land
// at their recorded apparent offset, then a final truncate to the apparent
// size rematerializes trailing holes. Interior holes are simply never
// written, so on filesystems with hole tracking the restored file is as
// sparse as the original.
func restoreFile(ctx context.Context, r BlobReader, sandboxID, generation string, mf ManifestFile, dest string) error {
	if err := validExtents(mf); err != nil {
		return err
	}
	object, err := SandboxObject(sandboxID, generation, mf.Name)
	if err != nil {
		return err
	}
	rc, err := r.NewReader(ctx, object)
	if err != nil {
		return err
	}
	defer rc.Close()
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, e := range mf.Extents {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := io.CopyN(io.NewOffsetWriter(f, e.Offset), rc, e.Length); err != nil {
			return fmt.Errorf("extent at %d: %w", e.Offset, err)
		}
	}
	// The packed object must hold exactly the extent table's bytes; trailing
	// data means object and manifest disagree.
	if n, _ := io.CopyN(io.Discard, rc, 1); n != 0 {
		return fmt.Errorf("packed object longer than extent table (%d bytes)", PackedSize(mf.Extents))
	}
	if err := f.Truncate(mf.Size); err != nil {
		return err
	}
	return f.Close()
}

// validExtents rejects extent tables that could not have come from the
// uploader: overlapping or out-of-order runs, or data past the apparent
// size. The digest check would catch the resulting corruption anyway, but
// failing on the malformed manifest gives a precise error instead.
func validExtents(mf ManifestFile) error {
	var pos int64
	for _, e := range mf.Extents {
		if e.Offset < pos || e.Length <= 0 {
			return fmt.Errorf("malformed extent table at offset %d", e.Offset)
		}
		pos = e.Offset + e.Length
	}
	if pos > mf.Size {
		return fmt.Errorf("extent table exceeds apparent size %d", mf.Size)
	}
	return nil
}

// verifyFile recomputes the full apparent digest of the rebuilt file with
// the same logic the uploader used (hashApparent over the manifest's extent
// table) and compares it to the manifest's recorded digest.
func verifyFile(ctx context.Context, path string, mf ManifestFile) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != mf.Size {
		return fmt.Errorf("apparent size %d, manifest records %d", fi.Size(), mf.Size)
	}
	sum, err := hashApparent(ctx, f, mf.Extents, mf.Size)
	if err != nil {
		return err
	}
	if sum != mf.SHA256 {
		return fmt.Errorf("sha256 mismatch: got %s, manifest records %s", sum, mf.SHA256)
	}
	return nil
}
