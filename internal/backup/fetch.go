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

	"golang.org/x/time/rate"
)

// ErrNoMatchingBackup reports that the generation recorded for the pause is
// not held complete in the bucket.
var ErrNoMatchingBackup = errors.New("the recorded backup generation is not in the bucket")

// Restored locates a restored generation's bootable disk and its base.
type Restored struct {
	Disk       string
	Base       string
	Standalone bool
	Manifest   *GenerationManifest
}

// RestoredDisk reads the completion marker in dir and resolves the rootfs
// and, for an overlay, the shared base beside it.
func RestoredDisk(dir string) (Restored, error) {
	var r Restored
	raw, err := os.ReadFile(filepath.Join(dir, ManifestObject))
	if err != nil {
		return r, fmt.Errorf("not restored")
	}
	r.Manifest = &GenerationManifest{}
	if err := json.Unmarshal(raw, r.Manifest); err != nil {
		return r, fmt.Errorf("restore marker: %w", err)
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
		r.Base = filepath.Join(dir, SharedBaseName(f.BaseSHA256))
		if _, err := os.Stat(r.Base); err == nil {
			return r, nil
		}
		if r.Base = hostBaseFor(f); r.Base != "" {
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
func FetchGeneration(ctx context.Context, r BlobReader, sandboxID, generation, destDir string, progress ProgressFunc) (Restored, error) {
	if generation == "" {
		return Restored{}, ErrNoMatchingBackup
	}
	if done, err := RestoredDisk(destDir); err == nil && done.Manifest.Generation == generation {
		return done, nil
	}
	if err := os.RemoveAll(destDir); err != nil {
		return Restored{}, fmt.Errorf("clear restore dir: %w", err)
	}
	m, err := fetchManifest(ctx, r, sandboxID, generation, func(string, ...any) {})
	if err != nil {
		if errors.Is(err, ErrGenerationIncomplete) {
			return Restored{}, ErrNoMatchingBackup
		}
		return Restored{}, err
	}
	skip := func(mf ManifestFile) bool { return isSharedEntry(mf) && hostHoldsBase(m, mf.SHA256) }
	if _, err := restoreGeneration(ctx, r, sandboxID, generation, destDir, skip, progress); err != nil {
		return Restored{}, err
	}
	return RestoredDisk(destDir)
}

// hostBaseFor is the template base an overlay was paused over, when the
// host still has it. Build directories are immutable and named by build,
// so the recorded path identifies the content.
func hostBaseFor(f ManifestFile) string {
	if f.BasePath == "" {
		return ""
	}
	if info, err := os.Stat(f.BasePath); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return f.BasePath
}

func hostHoldsBase(m *GenerationManifest, sha string) bool {
	for _, f := range m.Files {
		if f.BaseSHA256 == sha && hostBaseFor(f) != "" {
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
