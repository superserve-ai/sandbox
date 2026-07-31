package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
)

// StageTask hard-links a task's artifact files into the uploader-owned
// staging tree and rewrites the task's paths to the links. Sandbox
// teardown can then unlink the originals freely: the inodes survive
// through the links until the uploader acks, so a destroy racing a
// queued upload no longer erases the generation the retention model
// promises to keep. Links are free on the same filesystem; a link
// failure (cross-device, permissions) falls back to the original path
// for that file, preserving the old best-effort behavior.
//
// Idempotent per generation: a retry whose link already exists reuses
// it, which also covers re-enqueues after the originals are gone.
func StageTask(root string, task *Task) error {
	if root == "" {
		return nil
	}
	dir := filepath.Join(root, task.SandboxID, task.Generation)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for i, f := range task.Files {
		staged := filepath.Join(dir, f.Name)
		if err := os.Link(f.Path, staged); err != nil {
			if os.IsExist(err) {
				task.Files[i].Path = staged
				continue
			}
			if _, statErr := os.Stat(staged); statErr == nil {
				task.Files[i].Path = staged
				continue
			}
			return fmt.Errorf("stage %s: %w", f.Name, err)
		}
		task.Files[i].Path = staged
	}
	return nil
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
	for _, sb := range sandboxes {
		if !sb.IsDir() {
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
