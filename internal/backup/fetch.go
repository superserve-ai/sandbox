package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrNoMatchingBackup reports that the generation recorded for the pause is
// not held complete in the bucket.
var ErrNoMatchingBackup = errors.New("the recorded backup generation is not in the bucket")

// Restored locates a restored generation's bootable disk and its base.
type Restored struct {
	Disk       string
	Base       string
	Standalone bool
	// BlockMap is the snapshot's saved overlay block map, when the
	// generation carried one.
	BlockMap string
	Manifest *GenerationManifest
}

// RestoredGeneration reads a restore's completion marker and the rootfs
// it names. No base is resolved, so no artifact is read or written:
// enough to report that a restore is present.
func RestoredGeneration(dir string) (*GenerationManifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestObject))
	if err != nil {
		return nil, fmt.Errorf("not restored")
	}
	m := &GenerationManifest{}
	if err := json.Unmarshal(raw, m); err != nil {
		return nil, fmt.Errorf("restore marker: %w", err)
	}
	for _, f := range m.Files {
		if f.Name != "rootfs.ext4" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, f.Name)); err != nil {
			return nil, fmt.Errorf("restored without a rootfs")
		}
		return m, nil
	}
	return nil, fmt.Errorf("restore marker lists no rootfs")
}

// RestoredDisk reads the completion marker in dir and resolves the rootfs
// and, for an overlay, the shared base: the copy beside it, or the host's
// own template when the generation was restored without one. Resolving a
// host template hashes it, which is what ctx bounds.
func RestoredDisk(ctx context.Context, dir string) (Restored, error) {
	var r Restored
	m, err := RestoredGeneration(dir)
	if err != nil {
		return r, err
	}
	r.Manifest = m
	blockMap := ""
	for _, f := range r.Manifest.Files {
		if f.Name == BlockMapName {
			blockMap = filepath.Join(dir, f.Name)
		}
	}
	for _, f := range r.Manifest.Files {
		if f.Name != "rootfs.ext4" {
			continue
		}
		r.Disk = filepath.Join(dir, f.Name)
		if f.BaseSHA256 == "" {
			r.Standalone = true
			return r, nil
		}
		if blockMap != "" {
			if _, err := os.Stat(blockMap); err != nil {
				return r, fmt.Errorf("restored without its block map")
			}
			r.BlockMap = blockMap
		}
		r.Base = filepath.Join(dir, SharedBaseName(f.BaseSHA256))
		if _, err := os.Stat(r.Base); err == nil {
			return r, nil
		}
		src := hostBasePath(r.Manifest, f.BaseSHA256)
		if src == "" {
			return r, fmt.Errorf("restored without its base %s", f.BaseSHA256)
		}
		base, err := hostBase(ctx, dir, f.BaseSHA256, src)
		if err != nil {
			return r, fmt.Errorf("restored base %s: %w", f.BaseSHA256, err)
		}
		if base == "" {
			return r, fmt.Errorf("restored without its base %s", f.BaseSHA256)
		}
		r.Base = base
		return r, nil
	}
	return r, fmt.Errorf("restore marker lists no rootfs")
}

// FetchGeneration restores exactly the named generation into destDir. A
// completed restore of that generation already in destDir is reused;
// anything else there is discarded first. A generation the bucket no
// longer holds complete fails closed rather than falling back to another.
// owner is a sandbox id or a SnapshotOwner.
func FetchGeneration(ctx context.Context, r BlobReader, owner, generation, destDir string, progress ProgressFunc) (Restored, error) {
	if generation == "" {
		return Restored{}, ErrNoMatchingBackup
	}
	if done, err := RestoredDisk(ctx, destDir); err == nil && done.Manifest.Generation == generation && manifestOwner(done.Manifest) == owner {
		return done, nil
	}
	// A reuse check the context cut short establishes nothing about what
	// is in place, and the clear below is not recoverable: a complete
	// restore would be discarded because the budget expired mid-hash.
	if err := ctx.Err(); err != nil {
		return Restored{}, err
	}
	if err := os.RemoveAll(destDir); err != nil {
		return Restored{}, fmt.Errorf("clear restore dir: %w", err)
	}
	m, err := fetchManifest(ctx, r, owner, generation, func(string, ...any) {})
	if err != nil {
		if errors.Is(err, ErrGenerationIncomplete) {
			return Restored{}, ErrNoMatchingBackup
		}
		return Restored{}, err
	}
	// A shared base the host still holds is put into the restore from the
	// template instead of the bucket, and checked there. The verdict is
	// remembered: the restore loop and the verification loop each consult
	// skip once per file.
	satisfied := map[string]bool{}
	skip := func(mf ManifestFile) bool {
		if !isSharedEntry(mf) {
			return false
		}
		ok, seen := satisfied[mf.Name]
		if !seen {
			ok = satisfyFromHost(ctx, destDir, m, mf)
			satisfied[mf.Name] = ok
		}
		return ok
	}
	if _, err := restoreGeneration(ctx, r, owner, generation, destDir, m, skip, progress); err != nil {
		return Restored{}, err
	}
	return RestoredDisk(ctx, destDir)
}

// satisfyFromHost puts a shared base into the restore from the template
// the pause recorded, so the object need not be fetched. Reports whether
// the entry is now satisfied; a false sends it down the ordinary fetch
// path, which is also what a template that no longer holds those bytes
// gets.
func satisfyFromHost(ctx context.Context, dir string, m *GenerationManifest, mf ManifestFile) bool {
	src := hostBasePath(m, mf.SHA256)
	if src == "" {
		return false
	}
	base, err := hostBase(ctx, dir, mf.SHA256, src)
	return err == nil && base != ""
}

// hostBasePath is the template an overlay was paused over, when the host
// still has a plain file at the recorded path. The path is a claim about
// content, never proof of it: whatever is there is hashed before use.
func hostBasePath(m *GenerationManifest, sha string) string {
	for _, f := range m.Files {
		if f.BaseSHA256 != sha || f.BasePath == "" {
			continue
		}
		// Lstat, not Stat: a symlink's target can be repointed after the
		// digest is read, so only a plain file is a candidate.
		if info, err := os.Lstat(f.BasePath); err == nil && info.Mode().IsRegular() {
			return f.BasePath
		}
	}
	return ""
}

// hostBase materializes a shared base into the restore from the template
// the pause recorded, and returns the path the boot should read, or ""
// when the host cannot supply those bytes.
//
// The copy is what makes this sound: the bytes that were hashed are then
// the bytes that are read. Hashing the template where it lies proves
// less — a rebuild that truncates and rewrites it, or an inode swapped in
// after the digest was taken, changes what the guest sees for the whole
// life of the VM — so the template is never handed to a boot directly. A
// reflink costs no data copy where the filesystems allow one and a sparse
// copy where they do not; either way the object need not be fetched. A
// copy that fails its digest is removed, leaving the manifest's own name
// free for the fetch that follows. Only a check that could not run at all
// is an error.
func hostBase(ctx context.Context, dir, sha, src string) (string, error) {
	// Hashed under a name nothing resolves, and given the manifest's name
	// only once it matches: published first, a crash in between would
	// leave an unverified copy that the next resolution here trusts on
	// sight.
	staging := filepath.Join(dir, "."+SharedBaseName(sha)+".unverified")
	if err := snapshotFileMode(ctx, staging, src, stageAuto); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", nil
	}
	if err := verifyPath(ctx, staging, sha); err != nil {
		if rerr := os.Remove(staging); rerr != nil {
			return "", fmt.Errorf("discard unverified base copy: %w", rerr)
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", nil
	}
	dst := filepath.Join(dir, SharedBaseName(sha))
	if err := os.Rename(staging, dst); err != nil {
		_ = os.Remove(staging)
		return "", fmt.Errorf("publish verified base copy: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return "", fmt.Errorf("publish verified base copy: %w", err)
	}
	return dst, nil
}

// verifyPath hashes the file at path against the digest recorded for its
// contents.
func verifyPath(ctx context.Context, path, sha string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	extents, apparent, err := Extents(f)
	if err != nil {
		return fmt.Errorf("extents: %w", err)
	}
	return verifyDigest(ctx, f, extents, apparent, sha)
}

// LimitedReader caps the bytes per second streamed from a blob store.
type LimitedReader struct {
	Inner   BlobReader
	Limiter *rate.Limiter
}

func (l *LimitedReader) NewReader(ctx context.Context, object string) (io.ReadCloser, error) {
	rc, err := l.Inner.NewReader(ctx, object)
	if err != nil {
		return nil, err
	}
	return &limitedReadCloser{limitedReader: limitedReader{r: rc, limiter: l.Limiter, ctx: ctx}, c: rc}, nil
}

type limitedReadCloser struct {
	limitedReader
	c io.Closer
}

func (l *limitedReadCloser) Close() error { return l.c.Close() }

// cacheTemporary reports a spool or candidate an interrupted process may
// have left behind; nothing reads one across processes.
func cacheTemporary(name string) bool {
	return strings.HasPrefix(name, ".spool-") || strings.HasPrefix(name, ".candidate-")
}

// SweepCacheTemporaries removes leftover temporaries from a cache directory
// no fetch is using; call it at startup.
func SweepCacheTemporaries(dir string) (removed int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	for _, e := range entries {
		if !cacheTemporary(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// PruneBaseCache drops the oldest cached objects in a CachingBaseReader
// directory, unpacked masters, packed spools and stale temporaries alike,
// until the cache fits maxBytes. The caller must hold the cache exclusively
// so no fetch is mid-write; promoted bases live beside the cache and are
// never counted here.
func PruneBaseCache(dir string, maxBytes int64) (removed int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	type master struct {
		path string
		info os.FileInfo
	}
	var masters []master
	var total int64
	for _, e := range entries {
		name := e.Name()
		cached := strings.HasPrefix(name, ".unpacked-") || cacheTemporary(name) || (!strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "base-"))
		if !cached || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		masters = append(masters, master{filepath.Join(dir, e.Name()), info})
		total += info.Size()
	}
	sort.Slice(masters, func(i, j int) bool { return masters[i].info.ModTime().Before(masters[j].info.ModTime()) })
	for _, m := range masters {
		if total <= maxBytes {
			break
		}
		if err := os.Remove(m.path); err != nil {
			return removed, err
		}
		total -= m.info.Size()
		removed++
	}
	return removed, nil
}
