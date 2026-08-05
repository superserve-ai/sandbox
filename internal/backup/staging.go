package backup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	// The sweep's grace stats the generation DIRECTORY, and directory
	// mtimes do not move when children are rewritten, so reuse renews
	// the directory itself under the same flight key the sweep locks.
	// Renewal can JOIN an in-flight sweep deletion instead of executing
	// (singleflight coalesces same-key callers), so the directory is
	// re-created after the flight returns; children lost to that race
	// re-stage below via their own existence checks.
	renewStaged(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	for i, f := range task.Files {
		staged := filepath.Join(dir, f.Name)
		if renewedExists(staged) {
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
			stagedBase, err := StageSharedBase(root, f.BasePath, f.BaseSHA256, cloneOnly)
			if err != nil {
				if cloneOnly {
					all = false
					continue
				}
				return false, fmt.Errorf("stage base %s: %w", f.BaseSHA256, err)
			}
			task.Files[i].BaseStagedPath = stagedBase
		}
	}
	return all, nil
}

// inlineStageLimit bounds the packed bytes a pause may copy on the RPC
// path. Sparse copies scale with REAL bytes, so a typical overlay (tens
// of MB dirtied) stages in tens of milliseconds; a pathologically dense
// overlay must not drag the pause RPC back into seconds, and falls back
// to the marker-only worker path.
const inlineStageLimit = 256 << 20

// ErrStageTooLarge reports a pause whose packed disk exceeds the inline
// staging budget.
var ErrStageTooLarge = errors.New("packed size exceeds the inline staging budget")

// StagePending sparse-copies a pause's mutable artifacts into a
// pending-token directory under the staging root, called on the pause
// RPC path WHILE the VM operation lock is held: nothing can resume yet,
// so the copies are pause-time bytes by construction, and the detached
// worker can hash them at leisure with no at-rest race. Returns the
// staged directory and the staged path per file name. The copy is
// O(real bytes), the same scaling as the pause itself.
func StagePending(root, vmID, token string, files map[string]string) (string, map[string]string, error) {
	if root == "" {
		return "", nil, errors.New("staging disabled")
	}
	if disk, ok := files["rootfs.ext4"]; ok {
		f, err := os.Open(disk)
		if err != nil {
			return "", nil, err
		}
		extents, _, err := Extents(f)
		f.Close()
		if err != nil {
			return "", nil, err
		}
		if PackedSize(extents) > inlineStageLimit {
			return "", nil, ErrStageTooLarge
		}
	}
	dir := filepath.Join(root, vmID, "pending-"+token)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	// The chain's own dirents must be durable before the Bolt marker
	// commits, or a power loss leaves a durable marker pointing at a
	// vanished pending directory.
	if err := syncDir(filepath.Join(root, vmID)); err != nil {
		return "", nil, err
	}
	if err := syncDir(root); err != nil {
		return "", nil, err
	}
	staged := make(map[string]string, len(files))
	for name, src := range files {
		dst := filepath.Join(dir, name)
		if err := snapshotFileMode(dst, src, false); err != nil {
			_ = os.RemoveAll(dir)
			return "", nil, err
		}
		staged[name] = dst
	}
	if err := syncDir(dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	return dir, staged, nil
}

// FinishPendingStage renames a hashed pending directory to its
// generation name so ack cleanup and the sweep manage it under the
// standard layout, returning the final path per file name.
func FinishPendingStage(pendingDir, generation string, staged map[string]string) (map[string]string, error) {
	final := filepath.Join(filepath.Dir(pendingDir), generation)
	if pendingDir == final {
		// Recovery re-running after a completed rename.
	} else if err := os.Rename(pendingDir, final); err != nil {
		if !os.IsExist(err) && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		// The destination exists, but existence is not proof of
		// completeness: the worker staging path also creates generation
		// directories, and an interrupted one leaves residue under this
		// exact name. Only a destination holding every expected file at
		// the staged size may absorb the pending copy; anything less is
		// replaced by it.
		complete := true
		for name, src := range staged {
			sfi, serr := os.Stat(src)
			dfi, derr := os.Stat(filepath.Join(final, name))
			if serr != nil || derr != nil || sfi.Size() != dfi.Size() {
				complete = false
				break
			}
		}
		if complete {
			_ = os.RemoveAll(pendingDir)
		} else {
			if err := os.RemoveAll(final); err != nil {
				return nil, err
			}
			if err := os.Rename(pendingDir, final); err != nil {
				return nil, err
			}
		}
	}
	out := make(map[string]string, len(staged))
	for name := range staged {
		out[name] = filepath.Join(final, name)
	}
	if err := syncDir(filepath.Dir(final)); err != nil {
		return nil, err
	}
	return out, nil
}

// StageSharedBase ensures a base image's content snapshot exists under
// the staging root's bases tree and returns its path. Reuse renews the
// mtime under the sweep's grace: an aged unreferenced base being
// adopted by a new pause must not be reaped by a sweep holding a
// reference snapshot taken before this enqueue; a renewal that joined
// an in-flight deletion re-checks and falls through to re-staging.
func StageSharedBase(root, basePath, baseSHA string, cloneOnly bool) (string, error) {
	basesDir := filepath.Join(root, "bases")
	if err := os.MkdirAll(basesDir, 0o700); err != nil {
		return "", err
	}
	stagedBase := filepath.Join(basesDir, baseSHA)
	if renewedExists(stagedBase) {
		return stagedBase, nil
	}
	if err := snapshotFileMode(stagedBase, basePath, cloneOnly); err != nil {
		return "", err
	}
	if err := syncDir(basesDir); err != nil {
		return "", err
	}
	return stagedBase, nil
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
	// Template tasks are never staged (their artifacts are immutable on
	// disk), and with an empty SandboxID the path math below would land
	// on root/<generation> and the trailing Remove would target the
	// staging root itself. Harmless today (recreated on demand) but a
	// trap for any refactor that assumes the root persists.
	if task.SandboxID == "" {
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

// stagingSweepGrace protects the stage-then-enqueue handoff: workers
// stage files BEFORE the journal write, so the journal is not yet the
// liveness authority for very fresh entries, and a sweep landing in
// that window would delete files whose task is about to reference them
// (the worker would then enqueue as staged, clear its marker, and the
// uploader would abandon the missing files: a permanently lost pause).
// The handoff takes seconds; an hour of grace costs only residue delay.
const stagingSweepGrace = time.Hour

// renewStaged bumps a reused staged entry's mtime inside its staging
// flight, making it fresh under the sweep grace. Callers must re-check
// existence afterwards: singleflight coalesces same-key callers, so a
// renewal arriving during the sweep's deletion flight JOINS it (the
// renewal closure never runs) and the path is gone on return.
func renewStaged(path string) {
	_, _, _ = stagingFlights.Do(path, func() (any, error) {
		now := time.Now()
		_ = os.Chtimes(path, now, now)
		return nil, nil
	})
}

// renewedExists renews the entry and reports whether it survived: false
// means the renewal joined a concurrent deletion and the caller must
// re-stage.
func renewedExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	renewStaged(path)
	_, err := os.Stat(path)
	return err == nil
}

// fresherThan reports whether the entry's mtime is within grace of now;
// stat failures count as fresh (fail safe: keep, the next sweep decides).
func fresherThan(path string, grace time.Duration) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return true
	}
	return time.Since(fi.ModTime()) < grace
}

// SweepStaging removes staged generations with no pending journal task:
// residue of a crash between staging and enqueue, or of an ack whose
// cleanup was interrupted. Runs at startup before the uploader drains
// and periodically from the drain loop thereafter.
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
				staged := filepath.Join(root, "bases", b.Name())
				if !referenced[b.Name()] {
					// Serialize with renewStaged and re-check freshness
					// inside the flight: a pause adopting this base
					// concurrently either renews first (we skip) or
					// waits for the delete and re-stages.
					_, _, _ = stagingFlights.Do(staged, func() (any, error) {
						if !fresherThan(staged, stagingSweepGrace) {
							_ = os.RemoveAll(staged)
						}
						return nil, nil
					})
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
			staged := filepath.Join(sbDir, g.Name())
			if !pending {
				_, _, _ = stagingFlights.Do(staged, func() (any, error) {
					if !fresherThan(staged, stagingSweepGrace) {
						_ = os.RemoveAll(staged)
					}
					return nil, nil
				})
			}
		}
		_ = os.Remove(sbDir)
	}
}
