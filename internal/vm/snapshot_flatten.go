package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// shouldFlatten reports whether a chain should be flattened: when it has at least
// depthThreshold overlays (bounds restore fd/walk cost), OR — when bytesThreshold > 0
// — its overlays occupy at least bytesThreshold allocated bytes (bounds storage).
// depthThreshold <= 0 defaults to 16. A single overlay is never flattened.
func shouldFlatten(overlayCount int, allocatedBytes int64, depthThreshold int, bytesThreshold int64) bool {
	if overlayCount < 2 {
		return false
	}
	if depthThreshold <= 0 {
		depthThreshold = 16
	}
	if overlayCount >= depthThreshold {
		return true
	}
	return bytesThreshold > 0 && allocatedBytes >= bytesThreshold
}

// allocatedBytes returns the on-disk bytes actually allocated to a (sparse) file
// (st_blocks × 512), not its apparent size; 0 if it can't be stat'd.
func allocatedBytes(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return info.Size()
}

// flattenPageSize is the granularity at which overlay pages are composed. Guest
// RAM and the overlay files are page-aligned (guest RAM is MiB-sized), and the
// loader requires the filesystem block size ≤ page size, so a data extent always
// covers whole pages.
const flattenPageSize = 4096

// flattenChain merges a sandbox's overlay chain into a single sparse overlay
// (newest owner of each page wins), keeping the shared template base, and
// republishes the manifest as base → merged — bounding chain depth and reclaiming
// pages duplicated across layers.
//
// Crash-safe: the merged overlay is written to a fresh name (never an input) and
// the manifest swap is the commit point — a crash before it leaves the old chain
// intact; a crash after it leaves the old layers as orphans for GC. The caller
// must ensure the sandbox is quiescent (paused, no in-flight async flush). No-op
// when the chain has fewer than two overlays.
func (m *Manager) flattenChain(snapshotDir string) error {
	man, err := readManifest(snapshotDir)
	if err != nil {
		return fmt.Errorf("flatten: read manifest: %w", err)
	}
	if man == nil || len(man.Overlays) < 2 {
		return nil
	}

	// All overlays share the base's logical size; stat the base for it.
	baseInfo, err := os.Stat(man.Base)
	if err != nil {
		return fmt.Errorf("flatten: stat base %s: %w", man.Base, err)
	}
	total := baseInfo.Size()

	outName := nextFlatName(man.Overlays)
	outTmp := filepath.Join(snapshotDir, outName+".next")
	outPath := filepath.Join(snapshotDir, outName)

	out, err := os.OpenFile(outTmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("flatten: create %s: %w", outTmp, err)
	}
	if err := out.Truncate(total); err != nil { // sparse: full logical size, no allocation
		out.Close()
		_ = os.Remove(outTmp)
		return fmt.Errorf("flatten: size output: %w", err)
	}

	written := make([]bool, (total+flattenPageSize-1)/flattenPageSize)
	// Newest → oldest: the first layer to write a page is the newest owner, so
	// older layers fill only pages the newer ones don't have. Pages owned by no
	// overlay stay holes and fall through to the base on restore.
	for i := len(man.Overlays) - 1; i >= 0; i-- {
		ov := filepath.Join(snapshotDir, man.Overlays[i])
		if err := mergeOverlayPages(ov, out, written); err != nil {
			out.Close()
			_ = os.Remove(outTmp)
			return fmt.Errorf("flatten: merge %s: %w", man.Overlays[i], err)
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(outTmp)
		return fmt.Errorf("flatten: sync output: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(outTmp)
		return fmt.Errorf("flatten: close output: %w", err)
	}
	if err := os.Rename(outTmp, outPath); err != nil {
		_ = os.Remove(outTmp)
		return fmt.Errorf("flatten: publish output: %w", err)
	}
	if err := fsyncDir(snapshotDir); err != nil {
		return fmt.Errorf("flatten: fsync dir: %w", err)
	}

	// Commit point: the manifest now names only the merged overlay.
	old := man.Overlays
	man.Overlays = []string{outName}
	if err := writeManifestAtomic(snapshotDir, man); err != nil {
		_ = os.Remove(outPath)
		return fmt.Errorf("flatten: commit manifest: %w", err)
	}
	// Reclaim the old layers — safe now, the manifest no longer references them.
	for _, name := range old {
		if err := os.Remove(filepath.Join(snapshotDir, name)); err != nil && !os.IsNotExist(err) {
			m.log.Warn().Err(err).Str("path", name).Msg("flatten: remove old layer")
		}
	}
	return nil
}

// mergeOverlayPages copies every present page of ovPath (data extents found via
// SEEK_DATA/SEEK_HOLE — the same presence test the loader uses) into out at the
// same offset, skipping any page a newer layer already wrote.
func mergeOverlayPages(ovPath string, out *os.File, written []bool) error {
	in, err := os.Open(ovPath)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	buf := make([]byte, flattenPageSize)
	fd := int(in.Fd())

	var off int64
	for off < size {
		dataStart, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if err != nil {
			if err == unix.ENXIO { // no more data extents
				break
			}
			return err
		}
		holeStart, err := unix.Seek(fd, dataStart, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		// Page-align the extent's start (a data extent always covers whole pages).
		p := dataStart - (dataStart % flattenPageSize)
		for p < holeStart {
			idx := p / flattenPageSize
			if idx < int64(len(written)) && !written[idx] {
				n, rerr := in.ReadAt(buf, p)
				if n != flattenPageSize {
					return fmt.Errorf("short read at %d: %d bytes: %v", p, n, rerr)
				}
				if _, werr := out.WriteAt(buf, p); werr != nil {
					return werr
				}
				written[idx] = true
			}
			p += flattenPageSize
		}
		off = holeStart
	}
	return nil
}

// orphanGraceSeconds is how long an unreferenced layer/temp file must be
// untouched before GC reclaims it, so a file an in-flight pause is mid-writing is
// never removed.
const orphanGraceSeconds = 600

// layerFileRe matches an overlay layer file name (mem.<n>.diff or mem.flat.<n>.diff).
var layerFileRe = regexp.MustCompile(`^mem\.(?:\d+|flat\.\d+)\.diff$`)

// gcOrphanLayers reclaims layer/temp files the manifest doesn't reference that have
// been untouched for the grace period — interrupted-flatten leftovers and stale
// *.next temps. (Crashed-pause partials self-heal: the next append overwrites the
// file at that index.) No-op for a non-chain dir, so legacy/standalone snapshots are
// untouched. Best-effort; returns apparent bytes reclaimed.
func (m *Manager) gcOrphanLayers(snapshotDir string) (int64, error) {
	man, err := readManifest(snapshotDir)
	if err != nil || man == nil {
		return 0, err
	}
	referenced := make(map[string]bool, len(man.Overlays))
	for _, o := range man.Overlays {
		referenced[o] = true
	}
	entries, err := os.ReadDir(snapshotDir)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-orphanGraceSeconds * time.Second)
	var reclaimed int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !layerFileRe.MatchString(name) && !strings.HasSuffix(name, ".next") && name != bridgeDirtyOffsetsName && name != vmstatePrevName {
			continue
		}
		if referenced[name] {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue // recent → may be an in-flight write; leave it
		}
		p := filepath.Join(snapshotDir, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			m.log.Warn().Err(err).Str("path", p).Msg("gc: remove orphan layer")
			continue
		}
		reclaimed += info.Size()
		m.log.Info().Str("file", name).Msg("gc: reclaimed orphan layer")
	}
	return reclaimed, nil
}

var flatNameRe = regexp.MustCompile(`^mem\.flat\.(\d+)\.diff$`)

// nextFlatName returns a fresh "mem.flat.<n>.diff" name not present in overlays
// (so the merge output never collides with one of its inputs).
func nextFlatName(overlays []string) string {
	max := -1
	for _, o := range overlays {
		if mm := flatNameRe.FindStringSubmatch(o); mm != nil {
			if n, err := strconv.Atoi(mm[1]); err == nil && n > max {
				max = n
			}
		}
	}
	return fmt.Sprintf("mem.flat.%d.diff", max+1)
}
