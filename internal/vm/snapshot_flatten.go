package vm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"golang.org/x/sys/unix"
)

// flattenPageSize is the granularity at which overlay pages are composed. Guest
// RAM and the overlay files are page-aligned (guest RAM is MiB-sized), and the
// loader requires the filesystem block size ≤ page size, so a data extent always
// covers whole pages.
const flattenPageSize = 4096

// flattenChain merges a sandbox's overlay chain into a single sparse overlay
// (newest owner of each page wins), keeping the shared read-only template base,
// then republishes the manifest as base → merged. This bounds chain depth and
// reclaims pages duplicated across layers, without copying the base (so base
// sharing is preserved) and without spinning a VM or faulting guest RAM.
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
