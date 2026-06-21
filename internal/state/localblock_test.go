package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestBlockProvider returns a block provider whose "format" just writes a
// marker file, so the whole-image versioning logic is exercisable without
// e2fsprogs. Writes to the image are simulated by overwriting its bytes.
func newTestBlockProvider(t *testing.T) *LocalBlockProvider {
	t.Helper()
	p, err := NewLocalBlockProvider(t.TempDir(), 8)
	if err != nil {
		t.Fatal(err)
	}
	p.formatFn = func(path string, _ int) error {
		return os.WriteFile(path, []byte("FRESH-EXT4"), 0o600)
	}
	return p
}

func writeImage(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readImage(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBlockMountFormatsThenReuses(t *testing.T) {
	p := newTestBlockProvider(t)
	ctx := context.Background()

	m, err := p.Mount(ctx, "act-1", "/state")
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsBlockDevice {
		t.Error("block provider mount must report IsBlockDevice=true")
	}
	if filepath.Base(m.Path) != "state.img" {
		t.Errorf("Path = %s, want .../state.img", m.Path)
	}
	if got := readImage(t, m.Path); got != "FRESH-EXT4" {
		t.Errorf("new image not formatted, got %q", got)
	}

	// Simulate the guest writing durable state, then re-Mount: the image is
	// reused, not reformatted — state persists across "compute".
	writeImage(t, m.Path, "agent-data")
	m2, err := p.Mount(ctx, "act-1", "/state")
	if err != nil {
		t.Fatal(err)
	}
	if got := readImage(t, m2.Path); got != "agent-data" {
		t.Errorf("re-mount reformatted/lost state, got %q", got)
	}
}

func TestBlockCheckpointRollbackBranchLifecycle(t *testing.T) {
	p := newTestBlockProvider(t)
	ctx := context.Background()

	m, err := p.Mount(ctx, "act-1", "/state")
	if err != nil {
		t.Fatal(err)
	}
	writeImage(t, m.Path, "v1")

	if _, err := p.Checkpoint(ctx, "act-1", "cp1"); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	// List shows cp1.
	cps, err := p.ListCheckpoints(ctx, "act-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 1 || cps[0].Name != "cp1" {
		t.Fatalf("ListCheckpoints = %+v, want [cp1]", cps)
	}

	// Advance state, then roll back to cp1 → image restored to v1.
	writeImage(t, m.Path, "v2-divergent")
	if err := p.Rollback(ctx, "act-1", "cp1"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := readImage(t, m.Path); got != "v1" {
		t.Errorf("rollback did not restore the image, got %q", got)
	}

	// Branch b1 from cp1 is an independent copy of the v1 image.
	if err := p.Branch(ctx, "act-1", "cp1", "b1"); err != nil {
		t.Fatalf("branch: %v", err)
	}
	branchImg := filepath.Join(p.baseDir, "act-1", "branches", "b1.img")
	if got := readImage(t, branchImg); got != "v1" {
		t.Errorf("branch image = %q, want v1", got)
	}
	// Writing the branch must not affect current.
	writeImage(t, branchImg, "branch-only")
	if got := readImage(t, m.Path); got != "v1" {
		t.Errorf("branch write leaked into current: %q", got)
	}
}

func TestBlockMissingCheckpointErrors(t *testing.T) {
	p := newTestBlockProvider(t)
	ctx := context.Background()
	if _, err := p.Mount(ctx, "act-1", "/state"); err != nil {
		t.Fatal(err)
	}
	if err := p.Branch(ctx, "act-1", "nope", "b1"); !errors.Is(err, ErrCheckpointNotFound) {
		t.Errorf("branch from missing checkpoint: want ErrCheckpointNotFound, got %v", err)
	}
	if err := p.Rollback(ctx, "act-1", "nope"); !errors.Is(err, ErrCheckpointNotFound) {
		t.Errorf("rollback to missing checkpoint: want ErrCheckpointNotFound, got %v", err)
	}
}

func TestBlockInvalidIdentityRejected(t *testing.T) {
	p := newTestBlockProvider(t)
	ctx := context.Background()
	for _, bad := range []string{"", "..", "a/b", "../escape"} {
		if _, err := p.Mount(ctx, bad, "/state"); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("Mount(%q): want ErrInvalidIdentity, got %v", bad, err)
		}
	}
}

func TestBlockCheckpointBeforeMountErrors(t *testing.T) {
	p := newTestBlockProvider(t)
	if _, err := p.Checkpoint(context.Background(), "act-1", "cp1"); err == nil ||
		!strings.Contains(err.Error(), "mount first") {
		t.Errorf("checkpoint before mount should error about mounting first, got %v", err)
	}
}

// TestBlockSatisfiesProvider compile-asserts the interface (also done in source).
func TestBlockSatisfiesProvider(t *testing.T) {
	var _ Provider = (*LocalBlockProvider)(nil)
}
