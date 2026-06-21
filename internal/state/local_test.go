package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newLocal(t *testing.T) *LocalProvider {
	t.Helper()
	p, err := NewLocalProvider(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}
	return p
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestStateOutlivesCompute is the core durable-/state guarantee: mount, write,
// drop the handle ("terminate compute"), then remount the same identity and the
// file is still there.
func TestStateOutlivesCompute(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)
	const id = "acme-t-4821"

	m1, err := p.Mount(ctx, id, "/state")
	if err != nil {
		t.Fatalf("first mount: %v", err)
	}
	writeFile(t, m1.Path, "memory.json", "v1")
	if err := m1.Close(); err != nil { // terminate compute
		t.Fatalf("close: %v", err)
	}

	m2, err := p.Mount(ctx, id, "/state")
	if err != nil {
		t.Fatalf("remount: %v", err)
	}
	defer m2.Close()
	if got := readFile(t, m2.Path, "memory.json"); got != "v1" {
		t.Fatalf("state did not survive: got %q want %q", got, "v1")
	}
	if m1.Path != m2.Path {
		t.Fatalf("remount resolved a different path: %q vs %q", m1.Path, m2.Path)
	}
}

// TestCheckpointMutateRollback verifies that rollback restores a checkpoint's
// exact contents, including dropping files added after the checkpoint.
func TestCheckpointMutateRollback(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)
	const id = "rollback-id"

	m, err := p.Mount(ctx, id, "/state")
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer m.Close()

	writeFile(t, m.Path, "a.txt", "original")
	ck, err := p.Checkpoint(ctx, id, "v1")
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if ck.Name != "v1" || ck.ID == "" || ck.CreatedAt.IsZero() {
		t.Fatalf("bad checkpoint: %+v", ck)
	}

	// Mutate after the checkpoint.
	writeFile(t, m.Path, "a.txt", "changed")
	writeFile(t, m.Path, "b.txt", "added-after")

	if err := p.Rollback(ctx, id, "v1"); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if got := readFile(t, m.Path, "a.txt"); got != "original" {
		t.Fatalf("rollback did not restore a.txt: got %q", got)
	}
	if _, err := os.Stat(filepath.Join(m.Path, "b.txt")); !os.IsNotExist(err) {
		t.Fatalf("rollback did not drop b.txt added after checkpoint (err=%v)", err)
	}

	// The mount path is stable across rollback, so an existing handle still
	// points at the restored current.
	if got := readFile(t, m.Path, "a.txt"); got != "original" {
		t.Fatalf("mount path stale after rollback: %q", got)
	}
}

// TestBranchIsolation verifies a branch is an independent fork: writes to the
// branch don't touch current, and writes to current don't touch the branch.
func TestBranchIsolation(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)
	const id = "branch-id"

	m, err := p.Mount(ctx, id, "/state")
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer m.Close()

	writeFile(t, m.Path, "shared.txt", "base")
	if _, err := p.Checkpoint(ctx, id, "base"); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	if err := p.Branch(ctx, id, "base", "experiment"); err != nil {
		t.Fatalf("branch: %v", err)
	}

	// Locate the branch dir and the current dir; they must be different dirs.
	branchDir := filepath.Join(p.baseDir, id, "branches", "experiment")
	if branchDir == m.Path {
		t.Fatalf("branch shares dir with current: %s", branchDir)
	}

	// Branch starts from the checkpoint contents.
	if got := readFile(t, branchDir, "shared.txt"); got != "base" {
		t.Fatalf("branch missing checkpoint contents: %q", got)
	}

	// Mutate current; branch unaffected.
	writeFile(t, m.Path, "shared.txt", "current-edit")
	writeFile(t, m.Path, "only-current.txt", "x")
	if got := readFile(t, branchDir, "shared.txt"); got != "base" {
		t.Fatalf("current write leaked into branch: %q", got)
	}
	if _, err := os.Stat(filepath.Join(branchDir, "only-current.txt")); !os.IsNotExist(err) {
		t.Fatalf("current-only file appeared in branch (err=%v)", err)
	}

	// Mutate branch; current unaffected.
	writeFile(t, branchDir, "shared.txt", "branch-edit")
	writeFile(t, branchDir, "only-branch.txt", "y")
	if got := readFile(t, m.Path, "shared.txt"); got != "current-edit" {
		t.Fatalf("branch write leaked into current: %q", got)
	}
	if _, err := os.Stat(filepath.Join(m.Path, "only-branch.txt")); !os.IsNotExist(err) {
		t.Fatalf("branch-only file appeared in current (err=%v)", err)
	}
}

// TestListCheckpoints verifies listing and oldest-first ordering, including the
// empty case.
func TestListCheckpoints(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)
	const id = "list-id"

	// Empty before any mount: no error, empty slice.
	got, err := p.ListCheckpoints(ctx, id)
	if err != nil {
		t.Fatalf("list (empty): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no checkpoints, got %d", len(got))
	}

	m, err := p.Mount(ctx, id, "/state")
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer m.Close()
	writeFile(t, m.Path, "f.txt", "x")

	for _, name := range []string{"first", "second", "third"} {
		if _, err := p.Checkpoint(ctx, id, name); err != nil {
			t.Fatalf("checkpoint %s: %v", name, err)
		}
	}

	cks, err := p.ListCheckpoints(ctx, id)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(cks) != 3 {
		t.Fatalf("expected 3 checkpoints, got %d: %+v", len(cks), cks)
	}
	// Oldest-first ordering.
	for i := 1; i < len(cks); i++ {
		if cks[i].CreatedAt.Before(cks[i-1].CreatedAt) {
			t.Fatalf("checkpoints not oldest-first: %+v", cks)
		}
	}
}

// TestCheckpointReplace verifies re-using a name replaces the prior snapshot.
func TestCheckpointReplace(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)
	const id = "replace-id"

	m, err := p.Mount(ctx, id, "/state")
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer m.Close()

	writeFile(t, m.Path, "f.txt", "one")
	if _, err := p.Checkpoint(ctx, id, "snap"); err != nil {
		t.Fatalf("checkpoint 1: %v", err)
	}
	writeFile(t, m.Path, "f.txt", "two")
	if _, err := p.Checkpoint(ctx, id, "snap"); err != nil {
		t.Fatalf("checkpoint 2: %v", err)
	}

	cks, err := p.ListCheckpoints(ctx, id)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(cks) != 1 {
		t.Fatalf("expected name reuse to replace, got %d checkpoints", len(cks))
	}

	// Rollback should restore the replaced ("two") contents.
	writeFile(t, m.Path, "f.txt", "three")
	if err := p.Rollback(ctx, id, "snap"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := readFile(t, m.Path, "f.txt"); got != "two" {
		t.Fatalf("expected replaced checkpoint contents, got %q", got)
	}
}

// TestSubdirsAndSymlinksCopied verifies nested dirs are copied and symlinks are
// preserved as links (not followed), so a checkpoint round-trips a tree.
func TestSubdirsAndSymlinksCopied(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)
	const id = "tree-id"

	m, err := p.Mount(ctx, id, "/state")
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer m.Close()

	if err := os.MkdirAll(filepath.Join(m.Path, "sub", "deep"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(m.Path, "sub", "deep"), "x.txt", "deep-data")
	if err := os.Symlink("sub/deep/x.txt", filepath.Join(m.Path, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := p.Checkpoint(ctx, id, "t1"); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	// Wipe current then rollback.
	if err := os.RemoveAll(filepath.Join(m.Path, "sub")); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if err := os.Remove(filepath.Join(m.Path, "link")); err != nil {
		t.Fatalf("rm link: %v", err)
	}
	if err := p.Rollback(ctx, id, "t1"); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if got := readFile(t, filepath.Join(m.Path, "sub", "deep"), "x.txt"); got != "deep-data" {
		t.Fatalf("nested file not restored: %q", got)
	}
	fi, err := os.Lstat(filepath.Join(m.Path, "link"))
	if err != nil {
		t.Fatalf("lstat link: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink restored as non-symlink")
	}
}

// TestInvalidIdentityRejected verifies path-traversal and empty identities are
// rejected and never escape baseDir.
func TestInvalidIdentityRejected(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)

	for _, id := range []string{"", "..", ".", "a/b", "/abs", "../escape", "a/../b"} {
		if _, err := p.Mount(ctx, id, "/state"); !errors.Is(err, ErrInvalidIdentity) {
			t.Fatalf("Mount(%q) expected ErrInvalidIdentity, got %v", id, err)
		}
	}
}

// TestMissingCheckpoint verifies Branch/Rollback report ErrCheckpointNotFound.
func TestMissingCheckpoint(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)
	const id = "missing-ck"

	if _, err := p.Mount(ctx, id, "/state"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := p.Branch(ctx, id, "nope", "b"); !errors.Is(err, ErrCheckpointNotFound) {
		t.Fatalf("Branch from missing checkpoint: got %v", err)
	}
	if err := p.Rollback(ctx, id, "nope"); !errors.Is(err, ErrCheckpointNotFound) {
		t.Fatalf("Rollback to missing checkpoint: got %v", err)
	}
}

// TestInvalidCheckpointName verifies checkpoint/branch names are validated like
// identities (no traversal/separators).
func TestInvalidCheckpointName(t *testing.T) {
	ctx := context.Background()
	p := newLocal(t)
	const id = "name-id"
	if _, err := p.Mount(ctx, id, "/state"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	for _, bad := range []string{"", "..", "a/b", "/x"} {
		if _, err := p.Checkpoint(ctx, id, bad); err == nil {
			t.Fatalf("Checkpoint name %q should be rejected", bad)
		}
	}
}
