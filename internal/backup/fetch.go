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

// RestoredDisk reads the completion marker in dir and resolves the rootfs
// and, for an overlay, the shared base beside it or on the host. Reading
// the marker is cheap; honouring a host-held base is not, because its
// contents are hashed, which is what ctx bounds.
func RestoredDisk(ctx context.Context, dir string) (Restored, error) {
	var r Restored
	raw, err := os.ReadFile(filepath.Join(dir, ManifestObject))
	if err != nil {
		return r, fmt.Errorf("not restored")
	}
	r.Manifest = &GenerationManifest{}
	if err := json.Unmarshal(raw, r.Manifest); err != nil {
		return r, fmt.Errorf("restore marker: %w", err)
	}
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
		if _, err := os.Stat(r.Disk); err != nil {
			return r, fmt.Errorf("restored without a rootfs")
		}
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
		base, err := hostBaseFor(ctx, f)
		if err != nil {
			return r, fmt.Errorf("restored base %s: %w", f.BaseSHA256, err)
		}
		if base != "" {
			r.Base = pinHostBase(dir, f.BaseSHA256, base)
			return r, nil
		}
		return r, fmt.Errorf("restored without its base %s", f.BaseSHA256)
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
	// Honouring a host-held base hashes it, so the verdict is remembered
	// for this restore: the restore loop and the verification loop each
	// consult skip once per file.
	held := map[string]bool{}
	skip := func(mf ManifestFile) bool {
		if !isSharedEntry(mf) {
			return false
		}
		ok, seen := held[mf.SHA256]
		if !seen {
			ok = hostHoldsBase(ctx, m, mf.SHA256)
			held[mf.SHA256] = ok
		}
		return ok
	}
	if _, err := restoreGeneration(ctx, r, owner, generation, destDir, skip, progress); err != nil {
		return Restored{}, err
	}
	// Pin what the skip decision already checked, so resolving the restore
	// below does not read those bases a second time.
	for _, mf := range m.Files {
		if held[mf.BaseSHA256] && mf.BasePath != "" {
			pinHostBase(destDir, mf.BaseSHA256, mf.BasePath)
		}
	}
	return RestoredDisk(ctx, destDir)
}

// hostBaseFor is the template base an overlay was paused over, when the
// host still holds exactly those bytes. The recorded path alone does not
// establish that: a template rebuilt in place, or a base left short by an
// interrupted fetch, occupies the same path with different contents, and
// booting the overlay over it serves the wrong filesystem. So the file is
// hashed against the digest the pause recorded, and a file that does not
// match is no base at all — the caller then fetches the object, which is
// the work the match was going to save. Hashing costs what the fetched
// base costs anyway: every restored file, this base included, is hashed
// by verifyFile before the restore is called complete.
func hostBaseFor(ctx context.Context, f ManifestFile) (string, error) {
	if f.BasePath == "" || f.BaseSHA256 == "" {
		return "", nil
	}
	info, err := os.Stat(f.BasePath)
	if err != nil || !info.Mode().IsRegular() {
		return "", nil
	}
	if err := verifyPath(ctx, f.BasePath, f.BaseSHA256); err != nil {
		// A check that could not run is not a base worth replacing, and
		// callers act on that difference: a cancelled hash must surface as
		// cancellation, not as a missing base.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", nil
	}
	return f.BasePath, nil
}

// pinHostBase gives the restore its own name for a host base whose
// contents were just checked, by linking the very inode that was read.
// Two things follow: this restore resolves again without reading the base
// a second time, and a template rebuilt at that path afterwards cannot
// change the bytes under a VM already booted on them. A link the
// filesystem will not make (the base lives on another one) leaves the
// recorded path in use, checked but unpinned, as it was before.
func pinHostBase(dir, sha, hostPath string) string {
	// Only the file itself can be pinned: linking a symlink would leave
	// what the boot reads decided by whatever it points at later.
	if info, err := os.Lstat(hostPath); err != nil || !info.Mode().IsRegular() {
		return hostPath
	}
	pinned := filepath.Join(dir, SharedBaseName(sha))
	if err := os.Link(hostPath, pinned); err != nil {
		return hostPath
	}
	return pinned
}

// verifyPath hashes the file at path, which lives outside any restore
// destination, against the digest recorded for its contents.
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

// hostHoldsBase drives the restore's skip. A check that could not run
// reports false: the base is then fetched, which fails on a dead context
// without anything having been discarded.
func hostHoldsBase(ctx context.Context, m *GenerationManifest, sha string) bool {
	for _, f := range m.Files {
		if f.BaseSHA256 != sha {
			continue
		}
		if base, err := hostBaseFor(ctx, f); err == nil && base != "" {
			return true
		}
	}
	return false
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
