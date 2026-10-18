package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureStandardStreamLinksCreatesMissingAndKeepsExisting(t *testing.T) {
	dev := t.TempDir()
	// An image that ships its own /dev/stdout (pointing elsewhere) must keep it.
	if err := os.Symlink("/dev/pts/0", filepath.Join(dev, "stdout")); err != nil {
		t.Fatal(err)
	}
	if err := ensureStandardStreamLinks(dev); err != nil {
		t.Fatalf("ensure links: %v", err)
	}
	for name, want := range map[string]string{
		"fd":     "/proc/self/fd",
		"stdin":  "/proc/self/fd/0",
		"stdout": "/dev/pts/0",
		"stderr": "/proc/self/fd/2",
	} {
		got, err := os.Readlink(filepath.Join(dev, name))
		if err != nil || got != want {
			t.Fatalf("%s -> %q (err %v), want %q", name, got, err, want)
		}
	}
	// A second run is a no-op.
	if err := ensureStandardStreamLinks(dev); err != nil {
		t.Fatalf("ensure links again: %v", err)
	}
}
