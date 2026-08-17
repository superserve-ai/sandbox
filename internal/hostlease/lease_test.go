package hostlease

import (
	"path/filepath"
	"testing"
)

// Two independent opens of the same lockfile are separate open file
// descriptions, so their flocks conflict even within one process — enough to
// prove exclusivity and re-acquisition after release without spawning a second
// process.
func TestAcquireIsExclusiveAndReacquirable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vmd-writer.lock")

	l1, cap1, err := Acquire(path)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if !l1.Owns(cap1) {
		t.Fatal("capability is not backed by the lease that minted it")
	}
	if l1.Owns(nil) {
		t.Fatal("Owns(nil) must be false")
	}

	if _, _, err := Acquire(path); err != ErrHeld {
		t.Fatalf("second Acquire while held = %v, want ErrHeld", err)
	}

	// Releasing (the process-exit analog) must let the next generation take it.
	if err := l1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l2, _, err := Acquire(path)
	if err != nil {
		t.Fatalf("re-Acquire after release: %v", err)
	}
	t.Cleanup(func() { l2.Close() })
}
