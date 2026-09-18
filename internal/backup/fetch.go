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

// ErrNoMatchingBackup reports that no completed generation carries every
// digest the caller recorded for the pause it wants back.
var ErrNoMatchingBackup = errors.New("no backup generation matches the recorded pause")

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

// FetchMatching restores the newest generation whose manifest carries every
// digest in anchor into destDir. A completed restore already in destDir
// that matches is reused; anything else there is discarded first. An empty
// anchor cannot prove which pause a generation is, so it never matches.
func FetchMatching(ctx context.Context, r BlobReader, lister BlobLister, sandboxID string, anchor CaptureAnchor, destDir string, progress ProgressFunc) (Restored, error) {
	if len(anchor) == 0 {
		return Restored{}, ErrNoMatchingBackup
	}
	if done, err := RestoredDisk(destDir); err == nil && anchor.matches(done.Manifest) {
		return done, nil
	}
	if err := os.RemoveAll(destDir); err != nil {
		return Restored{}, fmt.Errorf("clear restore dir: %w", err)
	}
	gens, err := ListGenerations(ctx, lister, sandboxID)
	if err != nil {
		return Restored{}, fmt.Errorf("list generations: %w", err)
	}
	for _, g := range gens {
		m, err := fetchManifest(ctx, r, sandboxID, g.Generation, func(string, ...any) {})
		if err != nil {
			if ctx.Err() != nil {
				return Restored{}, err
			}
			continue
		}
		if !anchor.matches(m) {
			continue
		}
		skip := func(mf ManifestFile) bool { return isSharedEntry(mf) && hostHoldsBase(m, mf.SHA256) }
		if _, err := restoreGeneration(ctx, r, sandboxID, g.Generation, destDir, skip, progress); err != nil {
			return Restored{}, err
		}
		return RestoredDisk(destDir)
	}
	return Restored{}, ErrNoMatchingBackup
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

// AnchorKey is a stable identity for an anchor, for comparing requests.
func AnchorKey(anchor map[string]string) string {
	if len(anchor) == 0 {
		return ""
	}
	parts := make([]string, 0, len(anchor))
	for name, sha := range anchor {
		parts = append(parts, name+"="+sha)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
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

// PruneBaseCache drops the oldest unpacked bases in a CachingBaseReader
// directory until the cache fits maxBytes. Candidates and masters in use
// stay readable through their open descriptors.
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
		if !strings.HasPrefix(e.Name(), ".unpacked-") {
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
