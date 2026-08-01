package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"
)

// StageTask snapshots a task's artifact files into the uploader-owned
// staging tree and rewrites the task's paths to the copies. Sandbox
// teardown can then remove the originals freely, and a resume or later
// pause writing through the original inode cannot mutate the staged
// bytes: the copy is immutable, which a hard link is not (it shares the
// inode the guest reopens). Reflink clones make the snapshot free where
// the filesystem supports them; otherwise a sparse-aware copy ships
// only the data extents, which for pause artifacts is small. A staging
// failure falls back to the original path for that file, preserving the
// old best-effort behavior.
//
// Idempotent per generation: generations are content-addressed, so an
// existing staged file for this generation already holds these bytes
// and is reused (which also covers re-enqueues after the originals are
// gone).
func StageTask(root string, task *Task) error {
	_, err := stageTask(root, task, false)
	return err
}

// StageTaskClone stages with reflink clones only, skipping the byte-copy
// fallback: cheap enough to run inline under the pause operation lock,
// where quiescence is guaranteed and no at-rest proof is needed. Returns
// whether EVERY file (bases included) was staged; partially staged tasks
// keep original paths for the unstaged files and the caller falls back
// to the off-lock worker for those.
func StageTaskClone(root string, task *Task) (bool, error) {
	return stageTask(root, task, true)
}

func stageTask(root string, task *Task, cloneOnly bool) (bool, error) {
	if root == "" {
		return false, nil
	}
	all := true
	dir := filepath.Join(root, task.SandboxID, task.Generation)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	// Make the directory chain itself durable: the rename fsync below
	// covers entries in dir, not dir's own existence.
	if err := syncDir(filepath.Join(root, task.SandboxID)); err != nil {
		return false, err
	}
	if err := syncDir(root); err != nil {
		return false, err
	}
	for i, f := range task.Files {
		staged := filepath.Join(dir, f.Name)
		if _, err := os.Stat(staged); err == nil {
			task.Files[i].Path = staged
		} else if err := snapshotFileMode(staged, f.Path, cloneOnly); err != nil {
			if cloneOnly {
				all = false
			} else {
				return false, fmt.Errorf("stage %s: %w", f.Name, err)
			}
		} else {
			task.Files[i].Path = staged
		}
		// The base is GC-owned: destroying the last sandbox on an old
		// template build deletes it, which would abandon every queued
		// generation depending on it. One snapshot per base CONTENT
		// serves every generation on the host (reflink makes it free;
		// the copy fallback pays once per base, off the RPC path).
		if f.BaseSHA256 != "" && f.BasePath != "" {
			basesDir := filepath.Join(root, "bases")
			if err := os.MkdirAll(basesDir, 0o700); err != nil {
				return false, err
			}
			stagedBase := filepath.Join(basesDir, f.BaseSHA256)
			if _, err := os.Stat(stagedBase); err != nil {
				if err := snapshotFileMode(stagedBase, f.BasePath, cloneOnly); err != nil {
					if cloneOnly {
						all = false
						continue
					}
					return false, fmt.Errorf("stage base %s: %w", f.BaseSHA256, err)
				}
				if err := syncDir(basesDir); err != nil {
					return false, err
				}
			}
			task.Files[i].BasePath = stagedBase
		}
	}
	return all, nil
}

// stagingFlights serializes concurrent writers of one staged
// destination: two VMs pausing on the same template base would otherwise
// race multi-GB copies of bases/<sha>, and a shared fixed temp name
// would let one writer truncate the other mid-copy and publish a torn
// file under a name that is never re-staged.
var stagingFlights singleflight.Group

// snapshotFileMode is snapshotFile with an optional clone-only mode
// that fails fast instead of copying bytes.
func snapshotFileMode(dst, src string, cloneOnly bool) error {
	_, err, _ := stagingFlights.Do(dst, func() (any, error) {
		if _, err := os.Stat(dst); err == nil {
			return nil, nil // a concurrent flight already published it
		}
		if cloneOnly {
			return nil, snapshotClone(dst, src)
		}
		return nil, snapshotFile(dst, src)
	})
	return err
}

func snapshotClone(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	if err := cloneFile(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(dst))
}

// snapshotFile copies src to dst preserving sparseness, via reflink
// clone when available. Written to a temp name and renamed so a crash
// mid-copy never leaves a plausible-looking partial staged file.
func snapshotFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	if err := cloneFile(out, in); err != nil {
		extents, _, xerr := Extents(in)
		if xerr != nil {
			out.Close()
			os.Remove(tmp)
			return xerr
		}
		for _, e := range extents {
			if _, err := out.Seek(e.Offset, io.SeekStart); err != nil {
				out.Close()
				os.Remove(tmp)
				return err
			}
			if _, err := io.Copy(out, io.NewSectionReader(in, e.Offset, e.Length)); err != nil {
				out.Close()
				os.Remove(tmp)
				return err
			}
		}
		if err := out.Truncate(fi.Size()); err != nil {
			out.Close()
			os.Remove(tmp)
			return err
		}
	}
	// The journal enqueue that will reference this path is fsynced by
	// BoltDB; the staged bytes and their directory entry must be durable
	// FIRST, or a power loss can leave a journal pointing at a missing
	// or torn staged file, which a restart would misread as an abandoned
	// source.
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(dst))
}

// syncDir fsyncs a directory so the entries inside it are durable.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// removeStagedTask deletes a task's staging directory once the task is
// finished (verified or abandoned). Only paths under root are touched.
func removeStagedTask(root string, task Task) {
	if root == "" || len(task.Files) == 0 {
		return
	}
	dir := filepath.Join(root, task.SandboxID, task.Generation)
	if !strings.HasPrefix(dir, root+string(os.PathSeparator)) {
		return
	}
	_ = os.RemoveAll(dir)
	// Best-effort: clear the sandbox directory when this was its last
	// generation. Rmdir fails non-destructively when siblings remain.
	_ = os.Remove(filepath.Dir(dir))
}

// SweepStaging removes staged generations with no pending journal task:
// residue of a crash between staging and enqueue, or of an ack whose
// cleanup was interrupted. Run at startup before the uploader drains.
func SweepStaging(root string, j *Journal, log zerolog.Logger) {
	if root == "" {
		return
	}
	sandboxes, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Msg("backup staging sweep: read root failed")
		}
		return
	}
	referenced, err := j.PendingBaseSHAs()
	if err != nil {
		log.Warn().Err(err).Msg("backup staging sweep: base reference scan failed")
		referenced = nil // fail safe: keep every staged base this pass
	}
	for _, sb := range sandboxes {
		if !sb.IsDir() {
			continue
		}
		if sb.Name() == "bases" {
			// Shared base snapshots are cleared only when no pending
			// task references their content hash.
			if referenced == nil {
				continue
			}
			bases, err := os.ReadDir(filepath.Join(root, "bases"))
			if err != nil {
				continue
			}
			for _, b := range bases {
				if !referenced[b.Name()] {
					_ = os.RemoveAll(filepath.Join(root, "bases", b.Name()))
				}
			}
			continue
		}
		sbDir := filepath.Join(root, sb.Name())
		gens, err := os.ReadDir(sbDir)
		if err != nil {
			continue
		}
		for _, g := range gens {
			if !g.IsDir() {
				continue
			}
			pending, err := j.HasPending(sb.Name(), g.Name())
			if err != nil {
				log.Warn().Err(err).Msg("backup staging sweep: journal lookup failed")
				continue
			}
			if !pending {
				_ = os.RemoveAll(filepath.Join(sbDir, g.Name()))
			}
		}
		_ = os.Remove(sbDir)
	}
}
