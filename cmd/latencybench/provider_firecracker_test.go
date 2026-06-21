package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMax1(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{-5, 1}, {0, 1}, {1, 1}, {8, 8}, {32, 32},
	} {
		if got := max1(tc.in); got != tc.want {
			t.Errorf("max1(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestNewFirecrackerProviderValidation(t *testing.T) {
	dir := t.TempDir()
	kernel := filepath.Join(dir, "vmlinux")
	rootfs := filepath.Join(dir, "rootfs.ext4")
	fcbin := filepath.Join(dir, "firecracker")
	for _, p := range []string{kernel, rootfs, fcbin} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("missing kernel errors", func(t *testing.T) {
		if _, err := newFirecrackerProvider(fcbin, filepath.Join(dir, "nope"), rootfs, filepath.Join(dir, "run")); err == nil {
			t.Fatal("expected error for missing kernel")
		}
	})
	t.Run("empty path errors", func(t *testing.T) {
		if _, err := newFirecrackerProvider(fcbin, "", rootfs, filepath.Join(dir, "run")); err == nil {
			t.Fatal("expected error for empty kernel path")
		}
	})
	t.Run("all present succeeds and creates rundir", func(t *testing.T) {
		run := filepath.Join(dir, "run")
		p, err := newFirecrackerProvider(fcbin, kernel, rootfs, run)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Label() == "" {
			t.Error("Label() should be non-empty")
		}
		if _, err := os.Stat(run); err != nil {
			t.Errorf("rundir not created: %v", err)
		}
	})
}

// TestFirecrackerProviderRejectsNonTier1 guards that the Tier-1-only provider
// errors (rather than silently mismeasuring) if handed a Tier 2/3 cell.
func TestFirecrackerProviderRejectsNonTier1(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"vmlinux", "rootfs.ext4", "firecracker"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p, err := newFirecrackerProvider(
		filepath.Join(dir, "firecracker"), filepath.Join(dir, "vmlinux"),
		filepath.Join(dir, "rootfs.ext4"), filepath.Join(dir, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Wake(t.Context(), WakeParams{Cell: Cell{Tier: Tier2}}); err == nil {
		t.Fatal("expected Tier-2 cell to be rejected by the Tier-1-only provider")
	}
}
