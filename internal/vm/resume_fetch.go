package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// resumeFetchSource bundles what fetch-before-resume needs: read access to
// the cell's backup bucket and a semaphore bounding how many restores run
// at once. A reconnect storm after a host loss must not let every stranded
// sandbox's resume saturate local NVMe and NIC bandwidth at the same
// instant; requests past the bound queue for a free slot under whatever
// remains of their own RPC deadline, same as any other bounded resource on
// this path.
type resumeFetchSource struct {
	reader backup.BlobReader
	sem    chan struct{}
}

// SetResumeFetch enables fetch-before-resume. A nil reader (the default)
// disables it: resumeVMLocked's local-disk checks behave exactly as before,
// hard-failing when the paused sandbox's artifacts aren't already on this
// host. concurrency below 1 is clamped to 1.
func (m *Manager) SetResumeFetch(reader backup.BlobReader, concurrency int) {
	if reader == nil {
		m.resumeFetch = nil
		return
	}
	if concurrency < 1 {
		concurrency = 1
	}
	m.resumeFetch = &resumeFetchSource{reader: reader, sem: make(chan struct{}, concurrency)}
}

// fetchGenerationForResume restores generation's artifacts into a scratch
// directory beside snapshotPath, then places the two files every sandbox
// generation is guaranteed to carry — vmstate.snap and the disk image — at
// the local paths resumeVMLocked's existing checks expect. It returns the
// apparent bytes placed even on a partial failure, so a caller's metrics
// reflect what actually reached local disk.
//
// The guest memory image (mem.snap, or mem.diff for a layered overlay) is
// never part of the generation this restores: collectPauseManifest omits
// it by design (it never leaves the originating host, and hashing/shipping
// a multi-GiB image on every pause has no durability payoff proportional
// to its cost). A generation fetched here therefore cannot make memPath
// appear — resumeVMLocked's stat check on memPath fails exactly as it did
// before this existed, for a sandbox whose host was fully replaced. Only a
// sandbox whose memory file happens to already be present locally (partial
// loss, not a full replacement) sees this fetch unblock an actual resume.
//
// A layered overlay's base image is similarly out of scope: bases are
// fleet-wide template artifacts distributed by the existing template
// pipeline, not per-sandbox generation content, and any shared-base entry
// this generation's manifest carries is left in the scratch directory
// (removed with it) rather than adopted — restoring a missing base is a
// separate, existing gap this does not change.
func (m *Manager) fetchGenerationForResume(ctx context.Context, vmID, generation, snapshotPath, rootfsPath string, log zerolog.Logger) (bytesRestored int64, err error) {
	src := m.resumeFetch
	if src == nil {
		return 0, fmt.Errorf("fetch-on-resume is disabled on this host")
	}

	select {
	case src.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-src.sem }()

	snapshotDir := filepath.Dir(snapshotPath)
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return 0, fmt.Errorf("create snapshot dir: %w", err)
	}
	// RestoreGeneration requires an empty destination (see its doc comment)
	// and refuses to reuse one; a fresh scratch dir every attempt satisfies
	// that without racing a concurrent resume of the same vmID onto shared
	// state, and lives beside snapshotPath so placing vmstate.snap below is
	// a same-filesystem rename.
	scratch, err := os.MkdirTemp(snapshotDir, ".fetch-*")
	if err != nil {
		return 0, fmt.Errorf("create fetch scratch dir: %w", err)
	}
	defer os.RemoveAll(scratch)

	manifest, err := backup.RestoreGeneration(ctx, src.reader, vmID, generation, scratch, func(format string, args ...any) {
		log.Debug().Str("generation", generation).Msgf("resume fetch: "+format, args...)
	})
	if err != nil {
		return 0, fmt.Errorf("restore generation %s: %w", generation, err)
	}

	for _, mf := range manifest.Files {
		var dest string
		switch mf.Name {
		case "vmstate.snap":
			dest = snapshotPath
		case "rootfs.ext4":
			dest = rootfsPath
		default:
			// Shared base entries and any future artifact kind: not one of
			// resume's own local paths, left in scratch to be discarded.
			continue
		}
		if err := adoptFetchedFile(scratch, mf.Name, dest); err != nil {
			return bytesRestored, fmt.Errorf("place fetched %s: %w", mf.Name, err)
		}
		bytesRestored += mf.Size
	}
	return bytesRestored, nil
}

// adoptFetchedFile moves one restored artifact from the fetch scratch dir
// to its final resume path. Rename is attempted first (free, and the
// common case: vmstate.snap's destination is always a sibling of scratch
// itself) and is already atomic — it either fully replaces dest or leaves
// it untouched, never partial. A cross-device destination — the disk
// image, whose final path is under RunDir rather than SnapshotDir and so
// may sit on a different filesystem — falls back to a copy that preserves
// the same all-or-nothing guarantee at dest; see copyAcrossDevices.
func adoptFetchedFile(scratchDir, name, dest string) error {
	destDir := filepath.Dir(dest)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	src := filepath.Join(scratchDir, name)
	err := os.Rename(src, dest)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	return copyAcrossDevices(src, destDir, dest)
}

// copyAcrossDevices is the EXDEV fallback for adoptFetchedFile. It streams
// into a temp file IN DEST'S OWN DIRECTORY, fsyncs it, then renames it onto
// dest — that final rename is then same-filesystem and atomic, so a copy
// that fails or crashes partway leaves dest exactly as it was (missing or
// its prior content), never a truncated file. Without this, a failed copy
// straight into dest would leave a partial artifact that looks like a
// complete one to the plain existence check resumeVMLocked runs next, and
// to every future resume's fetch-trigger check after that.
func copyAcrossDevices(src, destDir, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(destDir, ".fetch-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			os.Remove(tmpPath)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return err
	}
	renamed = true
	return nil
}
