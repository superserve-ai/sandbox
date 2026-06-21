package state

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LocalBlockProvider is the reference BLOCK-DEVICE Provider: it backs each
// durable identity with a formatted ext4 IMAGE FILE rather than a directory.
// This is the form the Firecracker platform needs — the VM attaches the image
// as its /state drive (vdb) and boxd mounts it at /state — because Firecracker
// has no directory-sharing transport (no virtio-fs). The SaaS adapters
// (Archil-as-block) slot in behind the same Provider shape.
//
// Layout under baseDir (mirrors the directory LocalProvider, but with .img files
// where it has directories):
//
//	<baseDir>/<identity>/state.img             live, writable block image (the mount)
//	<baseDir>/<identity>/checkpoints/<name>.img immutable snapshots
//	<baseDir>/<identity>/branches/<name>.img    writable forks of a checkpoint
//
// Versioning is whole-image: a checkpoint is an atomic copy of state.img, a
// branch is a copy of a checkpoint into a new identity's state.img, and a
// rollback atomically swaps a checkpoint back over state.img. Copies stage to a
// temp file on the same filesystem and os.Rename into place (fsync'd), so a
// failure mid-operation never leaves partial state — the same durability
// contract the directory provider gives.
type LocalBlockProvider struct {
	baseDir string
	sizeMiB int
	// formatFn creates a fresh, formatted block image at path of the given size.
	// Defaults to mke2fs (real ext4); injectable so the versioning logic is
	// testable without e2fsprogs present.
	formatFn func(path string, sizeMiB int) error
}

var _ Provider = (*LocalBlockProvider)(nil)

// DefaultStateImageMiB is the size of a freshly-created /state image. ext4 on a
// sparse file costs only the metadata until written, so this is a ceiling, not a
// reservation.
const DefaultStateImageMiB = 1024

// NewLocalBlockProvider returns a block provider rooted at baseDir. sizeMiB <= 0
// uses DefaultStateImageMiB.
func NewLocalBlockProvider(baseDir string, sizeMiB int) (*LocalBlockProvider, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("state: local block provider base dir is empty")
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("state: resolve base dir %q: %w", baseDir, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("state: create base dir %q: %w", abs, err)
	}
	if sizeMiB <= 0 {
		sizeMiB = DefaultStateImageMiB
	}
	return &LocalBlockProvider{baseDir: abs, sizeMiB: sizeMiB, formatFn: mke2fsFormat}, nil
}

func (p *LocalBlockProvider) identityDir(identity string) (string, error) {
	if err := validateName(identity); err != nil {
		return "", fmt.Errorf("%w: identity %q: %s", ErrInvalidIdentity, identity, err)
	}
	return filepath.Join(p.baseDir, identity), nil
}

func (p *LocalBlockProvider) statePath(idDir string) string {
	return filepath.Join(idDir, "state.img")
}

// Mount ensures the identity's state.img exists (formatting a fresh ext4 image
// for a new identity) and returns a block-device handle to it. The Path is the
// image file vmd attaches as the /state drive.
func (p *LocalBlockProvider) Mount(ctx context.Context, identity, _ string) (*Mount, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	idDir, err := p.identityDir(identity)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(idDir, 0o700); err != nil {
		return nil, fmt.Errorf("state: mount %q: %w", identity, err)
	}
	img := p.statePath(idDir)
	switch _, err := os.Stat(img); {
	case err == nil:
		// Existing identity — reuse its image (durable state persists).
	case os.IsNotExist(err):
		if ferr := p.formatFn(img, p.sizeMiB); ferr != nil {
			return nil, fmt.Errorf("state: format new image %q: %w", identity, ferr)
		}
	default:
		return nil, fmt.Errorf("state: mount %q: %w", identity, err)
	}
	return &Mount{
		Identity:      identity,
		Path:          img,
		IsBlockDevice: true,
		unmount:       func() error { return nil },
	}, nil
}

// Checkpoint snapshots state.img into checkpoints/<name>.img atomically.
func (p *LocalBlockProvider) Checkpoint(ctx context.Context, identity, name string) (Checkpoint, error) {
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
	src := p.statePath(idDir)
	if _, err := os.Stat(src); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint %q: state image missing (mount first): %w", identity, err)
	}
	ckptParent := filepath.Join(idDir, "checkpoints")
	if err := os.MkdirAll(ckptParent, 0o700); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint %q: %w", identity, err)
	}
	createdAt := time.Now().UTC()
	dst := filepath.Join(ckptParent, name+imageExt)
	if err := copyImageAtomic(dst, src); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint %q/%q: %w", identity, name, err)
	}
	return Checkpoint{Name: name, ID: checkpointID(name, createdAt), CreatedAt: createdAt}, nil
}

// Branch forks branches/<newBranch>.img from checkpoints/<fromCheckpoint>.img.
func (p *LocalBlockProvider) Branch(ctx context.Context, identity, fromCheckpoint, newBranch string) error {
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
	src := filepath.Join(idDir, "checkpoints", fromCheckpoint+imageExt)
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
	dst := filepath.Join(branchParent, newBranch+imageExt)
	if err := copyImageAtomic(dst, src); err != nil {
		return fmt.Errorf("state: branch %q/%q: %w", identity, newBranch, err)
	}
	return nil
}

// Rollback atomically swaps checkpoints/<toCheckpoint>.img back over state.img.
func (p *LocalBlockProvider) Rollback(ctx context.Context, identity, toCheckpoint string) error {
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
	src := filepath.Join(idDir, "checkpoints", toCheckpoint+imageExt)
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("state: rollback %q/%q: %w", identity, toCheckpoint, ErrCheckpointNotFound)
		}
		return fmt.Errorf("state: rollback %q: stat checkpoint: %w", identity, err)
	}
	// copyImageAtomic replaces state.img via a same-dir rename, so current is
	// never left half-restored.
	if err := copyImageAtomic(p.statePath(idDir), src); err != nil {
		return fmt.Errorf("state: rollback %q/%q: %w", identity, toCheckpoint, err)
	}
	return nil
}

// ListCheckpoints returns the identity's checkpoints ordered oldest-first.
func (p *LocalBlockProvider) ListCheckpoints(ctx context.Context, identity string) ([]Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	idDir, err := p.identityDir(identity)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(idDir, "checkpoints"))
	if err != nil {
		if os.IsNotExist(err) {
			return []Checkpoint{}, nil
		}
		return nil, fmt.Errorf("state: list checkpoints %q: %w", identity, err)
	}
	out := make([]Checkpoint, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(e.Name(), imageExt) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("state: list checkpoints %q: stat %q: %w", identity, e.Name(), err)
		}
		name := strings.TrimSuffix(e.Name(), imageExt)
		createdAt := info.ModTime().UTC()
		out = append(out, Checkpoint{Name: name, ID: checkpointID(name, createdAt), CreatedAt: createdAt})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Name < out[j].Name
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

const imageExt = ".img"

// mke2fsFormat creates a formatted ext4 image at path. mke2fs -F makes a
// filesystem directly in a regular file (no loop device, no root). The file is a
// sparse <sizeMiB>MiB ext4 image the guest can mount read-write.
func mke2fsFormat(path string, sizeMiB int) error {
	cmd := exec.Command("mke2fs", "-F", "-q", "-t", "ext4", path, fmt.Sprintf("%dM", sizeMiB))
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(path) // don't leave a half-written image behind
		return fmt.Errorf("mke2fs: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// copyImageAtomic copies src to dst via a temp file in dst's directory, fsync'd
// and renamed into place, so dst is replaced atomically and is never partial.
func copyImageAtomic(dst, src string) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".img-*")
	if err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(tmpName) // copyFile O_EXCL-creates; clear the placeholder first
	if err := copyFile(src, tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("swap: %w", err)
	}
	return nil
}
