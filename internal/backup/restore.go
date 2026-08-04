package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

// BlobLister enumerates objects under a prefix. Kept separate from
// BlobReader so RestoreGeneration does not demand list permission.
type BlobLister interface {
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
}

// ObjectInfo describes one stored object as seen by a listing.
type ObjectInfo struct {
	Name    string
	Created time.Time
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

func (g *GCSReader) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	it := g.bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	var objects []ObjectInfo
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return objects, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", prefix, err)
		}
		objects = append(objects, ObjectInfo{Name: attrs.Name, Created: attrs.Created})
	}
}

// GenerationInfo identifies one restorable generation. Created is when
// the manifest completion object was written: the moment the generation
// became restorable, which is what an operator choosing between opaque
// content-addressed keys under DR pressure actually needs to see.
type GenerationInfo struct {
	Generation string
	Created    time.Time
}

// ListGenerations returns the complete (manifest-bearing) generations of
// a sandbox, newest first. Prefixes holding artifacts but no manifest are
// abandoned or in-flight uploads and are deliberately omitted: they are
// not restorable and listing them would only invite an operator to try.
func ListGenerations(ctx context.Context, lister BlobLister, sandboxID string) ([]GenerationInfo, error) {
	if err := validSegment(sandboxID); err != nil {
		return nil, fmt.Errorf("sandbox id: %w", err)
	}
	prefix := fmt.Sprintf("%s/%s/", sandboxPrefix, sandboxID)
	objects, err := lister.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var generations []GenerationInfo
	for _, obj := range objects {
		rest := strings.TrimPrefix(obj.Name, prefix)
		gen, file, ok := strings.Cut(rest, "/")
		if ok && file == ManifestObject {
			generations = append(generations, GenerationInfo{Generation: gen, Created: obj.Created})
		}
	}
	sort.Slice(generations, func(i, j int) bool {
		if !generations[i].Created.Equal(generations[j].Created) {
			return generations[i].Created.After(generations[j].Created)
		}
		return generations[i].Generation < generations[j].Generation
	})
	return generations, nil
}

// ProgressFunc receives human-readable progress lines during a restore.
// A nil ProgressFunc is silent.
type ProgressFunc func(format string, args ...any)

// RestoreGeneration materializes one complete generation into destDir:
// fetch the manifest, rebuild each sparse artifact from its packed object
// and extent table, and verify every file's full apparent content against
// the manifest digest. destDir must be absent or an empty directory; on
// success it holds exactly the manifest's files, verified and fsynced,
// plus the completion marker described below.
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
//
// Completion marker: after every file verifies, the generation manifest
// is written to destDir/manifest.json, fsynced, and the directory itself
// is fsynced, mirroring the upload design where the manifest object is
// written last. The marker is the completeness authority: a destination
// without it is a crashed or interrupted restore regardless of which
// artifact names happen to be present, and no consumer may treat such a
// directory as restored. Artifact entries named manifest.json are
// rejected up front so the marker can never collide.
func RestoreGeneration(ctx context.Context, r BlobReader, sandboxID, generation, destDir string, progress ProgressFunc) (*GenerationManifest, error) {
	report := func(format string, args ...any) {
		if progress != nil {
			progress(format, args...)
		}
	}
	manifest, err := fetchManifest(ctx, r, sandboxID, generation, report)
	if err != nil {
		return nil, err
	}
	report("manifest %s/%s: %d files", sandboxID, generation, len(manifest.Files))
	root, err := openFreshDir(destDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var created []string
	fail := func(err error) (*GenerationManifest, error) {
		var cleanupErrs []string
		for _, name := range created {
			if rerr := root.Remove(name); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				cleanupErrs = append(cleanupErrs, rerr.Error())
			}
		}
		if len(cleanupErrs) != 0 {
			err = fmt.Errorf("%w (cleanup also failed, destination must not be reused: %s)", err, strings.Join(cleanupErrs, "; "))
		}
		return nil, err
	}
	for _, mf := range manifest.Files {
		// The bucket is shared across the cell; never let a manifest name
		// escape destDir.
		if err := validSegment(mf.Name); err != nil {
			return fail(fmt.Errorf("manifest file name: %w", err))
		}
		report("restoring %s (%d bytes packed, %d apparent)", mf.Name, mf.PackedSize, mf.Size)
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
		report("verified %s sha256 %s", mf.Name, mf.SHA256)
	}
	madeMarker, err := writeRestoreMarker(root, manifest)
	if madeMarker {
		created = append(created, ManifestObject)
	}
	if err != nil {
		return fail(fmt.Errorf("completion marker: %w", err))
	}
	// Directory fsync makes the entries themselves durable; each file's
	// contents were fsynced as it was restored. Without this, power loss
	// after a reported success could leave a directory whose names are all
	// present but whose data never reached disk, which a rerun would
	// refuse as non-empty while looking complete.
	if err := syncRootDir(root); err != nil {
		return fail(fmt.Errorf("sync dest dir: %w", err))
	}
	// The destination's own dirent lives in its PARENT: without syncing
	// it, a freshly created destDir can vanish wholesale on power loss
	// after success was reported, even though its contents were durable.
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return fail(fmt.Errorf("resolve dest for parent sync: %w", err))
	}
	if parent, err := os.Open(filepath.Dir(absDest)); err == nil {
		serr := parent.Sync()
		parent.Close()
		if serr != nil {
			return fail(fmt.Errorf("sync dest parent: %w", serr))
		}
	} else {
		return fail(fmt.Errorf("open dest parent for sync: %w", err))
	}
	report("restore complete: %d files and completion marker durable", len(manifest.Files))
	return manifest, nil
}

// writeRestoreMarker writes the fsynced completion marker, last.
func writeRestoreMarker(root *os.Root, manifest *GenerationManifest) (madeFile bool, _ error) {
	payload, err := json.Marshal(manifest)
	if err != nil {
		return false, err
	}
	f, err := root.OpenFile(ManifestObject, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return false, err
	}
	madeFile = true
	defer f.Close()
	if _, err := f.Write(payload); err != nil {
		return madeFile, err
	}
	if err := f.Sync(); err != nil {
		return madeFile, err
	}
	return madeFile, f.Close()
}

func syncRootDir(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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
	// Creation must be as symlink-strict as the open: Mkdir and MkdirAll
	// resolve ancestors normally, so a symlinked ancestor would get the
	// destination created at its target even though the no-follow open
	// below then rejects the path. On linux makeDirNoFollow walks and
	// creates the hierarchy without following any symlink; elsewhere it
	// falls back to portable creation with the weaker guarantee.
	if err := makeDirNoFollow(dir); err != nil {
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

// makeDirPortable creates dir and any missing parents with the standard
// library primitives. Ancestor components are resolved normally, so a
// symlinked ancestor IS followed: this is the weaker-guarantee path used
// on platforms without a no-symlink traversal (and as the linux fallback
// when openat2 is unavailable). Mkdir on an existing leaf, symlink
// included, is EEXIST and creates nothing at the leaf itself.
func makeDirPortable(dir string) error {
	err := os.Mkdir(dir, 0o755)
	if errors.Is(err, fs.ErrNotExist) {
		if perr := os.MkdirAll(filepath.Dir(dir), 0o755); perr != nil {
			return fmt.Errorf("parent: %w", perr)
		}
		err = os.Mkdir(dir, 0o755)
	}
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

func fetchManifest(ctx context.Context, r BlobReader, sandboxID, generation string, report ProgressFunc) (*GenerationManifest, error) {
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
	// Real manifests are kilobytes; the cap only bounds what a corrupt or
	// hostile object can make this process buffer while decoding.
	if err := json.NewDecoder(io.LimitReader(rc, maxManifestBytes)).Decode(&manifest); err != nil {
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
	// dropped or a name, digest, size, or base dependency altered would
	// otherwise pass the identity check and restore an incomplete or wrong
	// file set with every remaining digest verifying. Shared base entries
	// are synthesized at upload time and excluded from the key; they are
	// bound instead through the consistency-pair check below, whose
	// BaseSHA256 side IS key-covered.
	//
	// Duplicates are rejected outright before any file is touched: a
	// duplicated shared entry under a fresh name would otherwise restore
	// and verify extra copies of a multi-GB base (silent disk exhaustion
	// inside a "verified" restore), and duplicate names can never
	// materialize under exclusive per-name creation.
	files := make([]TaskFile, 0, len(manifest.Files))
	baseDeps := map[string]bool{}
	sharedEntries := map[string]bool{}
	names := map[string]bool{}
	for _, mf := range manifest.Files {
		if mf.Name == ManifestObject {
			return nil, fmt.Errorf("manifest entry named %q collides with the completion marker", mf.Name)
		}
		if names[mf.Name] {
			return nil, fmt.Errorf("manifest lists file name %q twice", mf.Name)
		}
		names[mf.Name] = true
		if isSharedEntry(mf) {
			if sharedEntries[mf.SHA256] {
				return nil, fmt.Errorf("manifest lists shared object %s twice", mf.SHA256)
			}
			sharedEntries[mf.SHA256] = true
			continue
		}
		files = append(files, TaskFile{Name: mf.Name, SHA256: mf.SHA256, Size: mf.Size, BasePath: mf.BasePath, BaseSHA256: mf.BaseSHA256})
		if mf.BaseSHA256 != "" {
			baseDeps[mf.BaseSHA256] = true
		}
	}
	// Two accepted derivations: the current formula (Size in the key) and
	// the legacy pre-Size formula. Buckets hold generations uploaded under
	// the legacy formula, and refusing them would make history
	// unrestorable; a legacy match loses key coverage of Size only, which
	// the per-entry cap in validExtents bounds regardless of key version.
	if key := GenerationKey(files); key != generation {
		if legacy := generationKeyLegacy(files); legacy == generation {
			report("generation key verified via the legacy pre-size derivation")
		} else {
			return nil, fmt.Errorf("manifest does not reproduce its generation key: file set derives %s (legacy %s), prefix is %s (entry dropped or altered)", key, legacy, generation)
		}
	} else {
		report("generation key verified via the current derivation")
	}
	// Consistency pair, exact in both directions: an overlay's holes are
	// backed by its base, so a declared base dependency without its shared
	// entry is not restorable, and a shared entry no file depends on is
	// not something this generation may vouch for.
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

// maxManifestBytes bounds the manifest decode; see fetchManifest.
const maxManifestBytes = 64 << 20

// maxApparentSize bounds a single restored artifact; see validExtents.
const maxApparentSize = int64(16) << 40

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
	// The packed object must hold exactly the extent table's bytes;
	// trailing data means object and manifest disagree. A transport error
	// here is reported as such, not mistaken for a clean end of object.
	switch n, err := io.CopyN(io.Discard, rc, 1); {
	case n != 0:
		extra, _ := io.Copy(io.Discard, rc)
		return madeFile, fmt.Errorf("packed object is %d bytes, extent table describes %d", PackedSize(mf.Extents)+1+extra, PackedSize(mf.Extents))
	case err != nil && !errors.Is(err, io.EOF):
		return madeFile, fmt.Errorf("read past extents: %w", err)
	}
	if err := f.Truncate(mf.Size); err != nil {
		return madeFile, err
	}
	// Contents must be on disk before the caller can report a verified
	// restore; page-cache-only bytes would vanish in a power loss behind a
	// complete-looking directory.
	if err := f.Sync(); err != nil {
		return madeFile, err
	}
	return madeFile, f.Close()
}

// validExtents rejects extent tables that could not have come from the
// uploader: negative fields, overlapping or out-of-order runs, offsets
// that overflow int64, or data past the apparent size. The digest check
// would catch most resulting corruption anyway, but the extent table
// drives writes and truncation BEFORE any digest runs, so it must be
// bounded on its own; and Offset+Length wrapping negative would otherwise
// reset the monotonic cursor and re-admit anything.
func validExtents(mf ManifestFile) error {
	if mf.Size < 0 {
		return fmt.Errorf("negative apparent size %d", mf.Size)
	}
	// The cap applies to every entry regardless of key version: shared
	// base entries are synthesized outside the generation key, and legacy
	// pre-size generations never covered Size at all, so for both the cap
	// is the only bound before the digest check, and the digest check
	// itself costs a zero-hash proportional to Size. Fleet artifacts top
	// out in the tens of GiB apparent; 16TiB is a physical-plausibility
	// bound, not a tuning knob.
	if mf.Size > maxApparentSize {
		return fmt.Errorf("apparent size %d exceeds the %d bound", mf.Size, int64(maxApparentSize))
	}
	var pos int64
	for _, e := range mf.Extents {
		if e.Offset < 0 || e.Length <= 0 {
			return fmt.Errorf("malformed extent {offset %d, length %d}", e.Offset, e.Length)
		}
		if e.Offset < pos {
			return fmt.Errorf("out-of-order or overlapping extent at offset %d", e.Offset)
		}
		if e.Length > math.MaxInt64-e.Offset {
			return fmt.Errorf("extent {offset %d, length %d} overflows", e.Offset, e.Length)
		}
		pos = e.Offset + e.Length
	}
	if pos > mf.Size {
		return fmt.Errorf("extent table ends at %d, past apparent size %d", pos, mf.Size)
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
