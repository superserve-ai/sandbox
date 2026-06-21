package state

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LocalProvider is the reference Provider, backed by a base directory on the
// host filesystem. It works on darwin and linux for dev/test.
//
// It implements the durable /state SEMANTICS without a real bind/NFS/FUSE
// mount: state persists across "compute" simply by living on disk. The layout
// under baseDir is:
//
//	<baseDir>/<identity>/current               live, writable state (the mount)
//	<baseDir>/<identity>/checkpoints/<name>    immutable snapshots
//	<baseDir>/<identity>/branches/<name>       writable forks of a checkpoint
//
// Mutating operations (Checkpoint, Branch, Rollback) stage into a temporary
// directory on the same filesystem and os.Rename into place, so a failure
// mid-operation never leaves partially-written state visible. This is the
// behavior the Archil/Mesa backends must match.
type LocalProvider struct {
	baseDir string
}

// LocalProvider implements Provider.
var _ Provider = (*LocalProvider)(nil)

// NewLocalProvider returns a LocalProvider rooted at baseDir, creating it if
// necessary.
func NewLocalProvider(baseDir string) (*LocalProvider, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("state: local provider base dir is empty")
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("state: resolve base dir %q: %w", baseDir, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("state: create base dir %q: %w", abs, err)
	}
	return &LocalProvider{baseDir: abs}, nil
}

// identityDir validates identity and returns its on-disk root under baseDir.
// It rejects empty identities and any path-traversal element so a hostile
// identity cannot escape baseDir.
func (p *LocalProvider) identityDir(identity string) (string, error) {
	if err := validateName(identity); err != nil {
		return "", fmt.Errorf("%w: identity %q: %s", ErrInvalidIdentity, identity, err)
	}
	return filepath.Join(p.baseDir, identity), nil
}

// validateName rejects names that are empty, absolute, or contain a "." / ".."
// path element or a path separator. Used for both identities and checkpoint/
// branch names so they are always a single safe path segment.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("must not be empty")
	}
	if filepath.IsAbs(name) {
		return fmt.Errorf("must not be absolute")
	}
	// Disallow separators outright: a valid name is a single path segment.
	if strings.ContainsRune(name, os.PathSeparator) || strings.ContainsRune(name, '/') {
		return fmt.Errorf("must not contain a path separator")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("must not be a relative traversal element")
	}
	// filepath.Clean of a single safe segment is itself; anything else means
	// the name carried traversal or separators we want to reject.
	if filepath.Clean(name) != name {
		return fmt.Errorf("must be a clean path segment")
	}
	return nil
}

// Mount ensures <baseDir>/<identity>/current exists and returns a handle to it.
// Closing the handle is a no-op on the durable data: remounting the same
// identity returns the same directory and therefore the same files.
func (p *LocalProvider) Mount(ctx context.Context, identity, mountpoint string) (*Mount, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	idDir, err := p.identityDir(identity)
	if err != nil {
		return nil, err
	}
	current := filepath.Join(idDir, "current")
	if err := os.MkdirAll(current, 0o700); err != nil {
		return nil, fmt.Errorf("state: mount %q: %w", identity, err)
	}
	return &Mount{
		Identity: identity,
		Path:     current,
		// The local provider has nothing to release: durable state lives on
		// disk regardless of the handle's lifetime.
		unmount: func() error { return nil },
	}, nil
}

// Checkpoint snapshots current into checkpoints/<name>. The snapshot is built
// in a temp dir and renamed into place so a failure leaves no partial snapshot,
// and an existing snapshot of the same name is replaced atomically.
func (p *LocalProvider) Checkpoint(ctx context.Context, identity, name string) (Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	if err := validateName(name); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint name %q: %w", name, err)
	}
	idDir, err := p.identityDir(identity)
	if err != nil {
		return Checkpoint{}, err
	}

	current := filepath.Join(idDir, "current")
	if _, err := os.Stat(current); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint %q: current state missing (mount first): %w", identity, err)
	}

	ckptParent := filepath.Join(idDir, "checkpoints")
	if err := os.MkdirAll(ckptParent, 0o700); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint %q: %w", identity, err)
	}

	createdAt := time.Now().UTC()
	dst := filepath.Join(ckptParent, name)
	if err := copyTreeAtomic(ckptParent, dst, current); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint %q/%q: %w", identity, name, err)
	}

	return Checkpoint{
		Name:      name,
		ID:        checkpointID(name, createdAt),
		CreatedAt: createdAt,
	}, nil
}

// Branch forks branches/<newBranch> from checkpoints/<fromCheckpoint>. The
// branch is a fully independent copy on its own directory, so writes on it
// never cross into current or other branches.
func (p *LocalProvider) Branch(ctx context.Context, identity, fromCheckpoint, newBranch string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateName(fromCheckpoint); err != nil {
		return fmt.Errorf("state: from-checkpoint %q: %w", fromCheckpoint, err)
	}
	if err := validateName(newBranch); err != nil {
		return fmt.Errorf("state: branch name %q: %w", newBranch, err)
	}
	idDir, err := p.identityDir(identity)
	if err != nil {
		return err
	}

	src := filepath.Join(idDir, "checkpoints", fromCheckpoint)
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("state: branch %q/%q: %w", identity, fromCheckpoint, ErrCheckpointNotFound)
		}
		return fmt.Errorf("state: branch %q: stat checkpoint: %w", identity, err)
	}

	branchParent := filepath.Join(idDir, "branches")
	if err := os.MkdirAll(branchParent, 0o700); err != nil {
		return fmt.Errorf("state: branch %q: %w", identity, err)
	}
	dst := filepath.Join(branchParent, newBranch)
	if err := copyTreeAtomic(branchParent, dst, src); err != nil {
		return fmt.Errorf("state: branch %q/%q: %w", identity, newBranch, err)
	}
	return nil
}

// Rollback re-homes current onto checkpoints/<toCheckpoint>. The replacement is
// staged in a temp dir and swapped via rename so current is never left in a
// partially-restored state; the previous current is removed only after the new
// one is in place.
func (p *LocalProvider) Rollback(ctx context.Context, identity, toCheckpoint string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateName(toCheckpoint); err != nil {
		return fmt.Errorf("state: to-checkpoint %q: %w", toCheckpoint, err)
	}
	idDir, err := p.identityDir(identity)
	if err != nil {
		return err
	}

	src := filepath.Join(idDir, "checkpoints", toCheckpoint)
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("state: rollback %q/%q: %w", identity, toCheckpoint, ErrCheckpointNotFound)
		}
		return fmt.Errorf("state: rollback %q: stat checkpoint: %w", identity, err)
	}

	current := filepath.Join(idDir, "current")

	// Stage the restored copy alongside current on the same filesystem.
	staging, err := os.MkdirTemp(idDir, ".rollback-*")
	if err != nil {
		return fmt.Errorf("state: rollback %q: stage: %w", identity, err)
	}
	newCurrent := filepath.Join(staging, "current")
	if err := copyTree(src, newCurrent); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("state: rollback %q: copy: %w", identity, err)
	}

	// Move the old current aside, swap the new one in, then drop the old.
	// Renames on one filesystem are atomic; if the second rename fails we
	// restore the old current so we never lose state.
	old := filepath.Join(staging, "old-current")
	currentExists := true
	if _, err := os.Stat(current); os.IsNotExist(err) {
		currentExists = false
	}
	if currentExists {
		if err := os.Rename(current, old); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("state: rollback %q: park current: %w", identity, err)
		}
	}
	if err := os.Rename(newCurrent, current); err != nil {
		// Best-effort restore of the original current.
		if currentExists {
			_ = os.Rename(old, current)
		}
		_ = os.RemoveAll(staging)
		return fmt.Errorf("state: rollback %q: swap: %w", identity, err)
	}
	_ = os.RemoveAll(staging)
	return nil
}

// ListCheckpoints returns the identity's checkpoints ordered oldest-first.
func (p *LocalProvider) ListCheckpoints(ctx context.Context, identity string) ([]Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	idDir, err := p.identityDir(identity)
	if err != nil {
		return nil, err
	}

	ckptParent := filepath.Join(idDir, "checkpoints")
	entries, err := os.ReadDir(ckptParent)
	if err != nil {
		if os.IsNotExist(err) {
			return []Checkpoint{}, nil
		}
		return nil, fmt.Errorf("state: list checkpoints %q: %w", identity, err)
	}

	out := make([]Checkpoint, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("state: list checkpoints %q: stat %q: %w", identity, e.Name(), err)
		}
		createdAt := info.ModTime().UTC()
		out = append(out, Checkpoint{
			Name:      e.Name(),
			ID:        checkpointID(e.Name(), createdAt),
			CreatedAt: createdAt,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Name < out[j].Name
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// checkpointID derives a stable identifier for a snapshot from its name and
// creation time. The local provider has no content-addressing, so this is a
// human-readable surrogate.
func checkpointID(name string, createdAt time.Time) string {
	return fmt.Sprintf("%s@%d", name, createdAt.UnixNano())
}

// copyTreeAtomic copies src into a temp dir under parent, then renames it to
// dst, replacing any existing dst atomically. parent must be on the same
// filesystem as dst so the rename is atomic and cannot leave a half-written dst.
func copyTreeAtomic(parent, dst, src string) error {
	tmp, err := os.MkdirTemp(parent, ".tmp-*")
	if err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	staged := filepath.Join(tmp, "tree")
	if err := copyTree(src, staged); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}

	// Replace an existing dst: park it aside, swap, then drop it. A failed
	// final rename restores the original.
	parked := filepath.Join(tmp, "parked")
	dstExists := true
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		dstExists = false
	}
	if dstExists {
		if err := os.Rename(dst, parked); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("park existing: %w", err)
		}
	}
	if err := os.Rename(staged, dst); err != nil {
		if dstExists {
			_ = os.Rename(parked, dst)
		}
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("swap: %w", err)
	}
	_ = os.RemoveAll(tmp)
	return nil
}

// copyTree recursively copies the directory tree at src to dst (which must not
// yet exist). It preserves directory structure, regular file contents and mode
// bits, and symlinks (copied as links, not followed, so a link cannot be used
// to write outside dst).
func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(target, dst)

	case info.IsDir():
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil

	case info.Mode().IsRegular():
		return copyFile(src, dst, info.Mode().Perm())

	default:
		// Skip sockets, devices, fifos: not meaningful durable agent state.
		return nil
	}
}

// copyFile copies a regular file's contents from src to dst with the given mode,
// fsyncing dst so the copy is durable before the caller renames it into place.
func copyFile(src, dst string, perm os.FileMode) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	// Strong durability matches the /state contract (§3: durable on fsync).
	return out.Sync()
}
