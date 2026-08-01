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
	root, err := openFreshDir(destDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var created []string
	fail := func(err error) (*GenerationManifest, error) {
		for _, name := range created {
			root.Remove(name)
		}
		return nil, err
	}
	for _, mf := range manifest.Files {
		// The bucket is shared across the cell; never let a manifest name
		// escape destDir.
		if err := validSegment(mf.Name); err != nil {
			return fail(fmt.Errorf("manifest file name: %w", err))
		}
		madeFile, err := restoreFile(ctx, r, sandboxID, generation, mf, root)
		if madeFile {
			created = append(created, mf.Name)
		}
		if err != nil {
			return fail(fmt.Errorf("restore %s: %w", mf.Name, err))
		}
	}
	// Verify after every file has materialized so an error part way through
	// verification cannot leave earlier files implicitly blessed: either
	// the whole set passes or the whole set is gone.
	for _, mf := range manifest.Files {
		if err := verifyFile(ctx, root, mf); err != nil {
			return fail(fmt.Errorf("verify %s: %w", mf.Name, err))
		}
	}
	return manifest, nil
}

// openFreshDir creates dir (and parents) if needed, requires it to be a
// real, empty directory, and returns a Root pinned to it. Every per-file
// open, verify, and cleanup in the restore runs relative to that pinned
// descriptor.
//
// A symlink at dir itself must never be followed, whether pre-planted
// (the plain Lstat refuses it with a clear error) or swapped in
// concurrently: openRootNoFollow makes the open itself reject a symlink
// leaf, atomically in the kernel on linux, so there is no check-to-open
// window. Once the Root is open it tracks the directory itself,
// unaffected by later renames at the path.
func openFreshDir(dir string) (*os.Root, error) {
	dir = filepath.Clean(dir)
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("dest dir %s is a symlink: restore only writes into a real directory", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("dest dir: %w", err)
	}
	root, err := openRootNoFollow(filepath.Dir(dir), filepath.Base(dir))
	if err != nil {
		return nil, fmt.Errorf("dest dir: %w", err)
	}
	// Emptiness is checked through the pinned Root so it holds for the
	// directory actually being written, not whatever the path resolves to.
	d, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("dest dir: %w", err)
	}
	names, err := d.Readdirnames(1)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		root.Close()
		return nil, fmt.Errorf("dest dir: %w", err)
	}
	if len(names) != 0 {
		root.Close()
		return nil, fmt.Errorf("dest dir %s is not empty: restore refuses to overwrite existing content, use a fresh directory", dir)
	}
	return root, nil
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
	// The manifest records its own identity; a manifest copied or misplaced
	// under another prefix could otherwise restore a different sandbox's
	// generation with every digest passing.
	if manifest.SandboxID != sandboxID || manifest.Generation != generation {
		return nil, fmt.Errorf("manifest identity mismatch: %s records %s/%s, requested %s/%s",
			object, manifest.SandboxID, manifest.Generation, sandboxID, generation)
	}
	// The manifest must also be self-authenticating: the generation prefix
	// is the content address GenerationKey derives from the enqueued file
	// set, so the entries must reproduce it. A manifest with an entry
	// dropped or a name, digest, or base dependency altered would otherwise
	// pass the identity check and restore an incomplete or wrong file set
	// with every remaining digest verifying. Shared base entries are
	// synthesized at upload time and excluded from the key; they are bound
	// instead through the consistency-pair check below, whose BaseSHA256
	// side IS key-covered.
	files := make([]TaskFile, 0, len(manifest.Files))
	baseDeps := map[string]bool{}
	sharedEntries := map[string]bool{}
	for _, mf := range manifest.Files {
		if isSharedEntry(mf) {
			sharedEntries[mf.SHA256] = true
			continue
		}
		files = append(files, TaskFile{Name: mf.Name, SHA256: mf.SHA256, BasePath: mf.BasePath, BaseSHA256: mf.BaseSHA256})
		if mf.BaseSHA256 != "" {
			baseDeps[mf.BaseSHA256] = true
		}
	}
	if key := GenerationKey(files); key != generation {
		return nil, fmt.Errorf("manifest does not reproduce its generation key: file set derives %s, prefix is %s (entry dropped or altered)", key, generation)
	}
	// Consistency pair: an overlay's holes are backed by its base, so a
	// declared base dependency without its shared entry is not restorable,
	// and a shared entry no file depends on is not something this
	// generation may vouch for.
	for dep := range baseDeps {
		if !sharedEntries[dep] {
			return nil, fmt.Errorf("manifest declares base %s but carries no shared entry for it: consistency pair incomplete", dep)
		}
	}
	for sha := range sharedEntries {
		if !baseDeps[sha] {
			return nil, fmt.Errorf("manifest carries shared object %s that no entry depends on", sha)
		}
	}
	return &manifest, nil
}

// isSharedEntry reports whether a manifest entry points at a bucket-wide
// shared object rather than one inside the generation prefix: shared
// entries record the full object path, generation-local entries a single
// name segment.
func isSharedEntry(mf ManifestFile) bool {
	return strings.Contains(mf.Object, "/")
}

// restoreFile streams a packed object into place: each extent's bytes land
// at their recorded apparent offset, then a final truncate to the apparent
// size rematerializes trailing holes. Interior holes are simply never
// written, so on filesystems with hole tracking the restored file is as
// sparse as the original.
//
// The object is fetched by the manifest entry's recorded Object name, never
// derived from the file name: the name embeds the packing fingerprint, so
// this entry's extent table describes exactly the object it points at.
//
// The destination is opened O_EXCL relative to the pinned root:
// ensureFreshDir's emptiness check and this open are separate operations,
// so exclusive fd-relative creation is what guarantees an existing file
// (or a symlink planted in between) is never opened, truncated, or
// followed. madeFile reports whether this call created the file, and only
// then may the caller's failure cleanup remove it.
func restoreFile(ctx context.Context, r BlobReader, sandboxID, generation string, mf ManifestFile, root *os.Root) (madeFile bool, _ error) {
	if mf.Object == "" {
		return false, fmt.Errorf("manifest entry records no object name")
	}
	if err := validExtents(mf); err != nil {
		return false, err
	}
	var object string
	if isSharedEntry(mf) {
		// Shared base objects live outside the generation prefix under a
		// content-addressed name. Require the recorded path to embed this
		// entry's digest: the digest chains back to a key-covered
		// BaseSHA256, so a tampered manifest cannot point the pair at an
		// arbitrary bucket object.
		fp, ok := strings.CutPrefix(mf.Object, SharedBaseObject(mf.SHA256, ""))
		if !ok || fp == "" || strings.ContainsAny(fp, "/\\") {
			return false, fmt.Errorf("shared object name %q is not bound to digest %s", mf.Object, mf.SHA256)
		}
		object = mf.Object
	} else {
		if err := validSegment(mf.Object); err != nil {
			return false, fmt.Errorf("manifest object name: %w", err)
		}
		var err error
		object, err = SandboxObject(sandboxID, generation, mf.Object)
		if err != nil {
			return false, err
		}
	}
	rc, err := r.NewReader(ctx, object)
	if err != nil {
		return false, err
	}
	defer rc.Close()
	f, err := root.OpenFile(mf.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return false, err
	}
	madeFile = true
	defer f.Close()
	for _, e := range mf.Extents {
		if err := ctx.Err(); err != nil {
			return madeFile, err
		}
		if _, err := io.CopyN(io.NewOffsetWriter(f, e.Offset), rc, e.Length); err != nil {
			return madeFile, fmt.Errorf("extent at %d: %w", e.Offset, err)
		}
	}
	// The packed object must hold exactly the extent table's bytes; trailing
	// data means object and manifest disagree.
	if n, _ := io.CopyN(io.Discard, rc, 1); n != 0 {
		return madeFile, fmt.Errorf("packed object longer than extent table (%d bytes)", PackedSize(mf.Extents))
	}
	if err := f.Truncate(mf.Size); err != nil {
		return madeFile, err
	}
	return madeFile, f.Close()
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

// verifyFile recomputes the full apparent digest of the rebuilt file and
// compares it to the manifest's recorded digest. The open is relative to
// the pinned root so verification reads the file that was written, not
// something swapped in at the path.
//
// The extent geometry is derived from the restored file itself, never
// taken from the manifest: hashing manifest-declared holes as synthetic
// zeros would miss bytes written into a hole after materialization, and
// verification would bless contents it never read. From the file's own
// geometry, a hole hashed as zeros is genuinely a hole on disk (nothing
// can hide there) and every data extent is read back. On filesystems
// without hole tracking this degrades to hashing the complete file,
// correct, just not compact.
func verifyFile(ctx context.Context, root *os.Root, mf ManifestFile) error {
	f, err := root.Open(mf.Name)
	if err != nil {
		return err
	}
	defer f.Close()
	extents, apparent, err := Extents(f)
	if err != nil {
		return fmt.Errorf("extents: %w", err)
	}
	if apparent != mf.Size {
		return fmt.Errorf("apparent size %d, manifest records %d", apparent, mf.Size)
	}
	sum, err := hashApparent(ctx, f, extents, apparent)
	if err != nil {
		return err
	}
	if sum != mf.SHA256 {
		return fmt.Errorf("sha256 mismatch: got %s, manifest records %s", sum, mf.SHA256)
	}
	return nil
}
