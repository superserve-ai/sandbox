//go:build linux

package vm

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExclusiveFileBytesSeparatesSharedAndCOWExtents(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	clone := filepath.Join(dir, "clone")
	if err := os.WriteFile(source, bytes.Repeat([]byte{0x5a}, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reflinkImmutableFileContext(context.Background(), source, clone); err != nil {
		t.Skipf("test filesystem has no reflink support: %v", err)
	}
	if got, err := exclusiveFileBytes(clone); err != nil {
		t.Fatal(err)
	} else if got != 0 {
		t.Fatalf("fresh reflink exclusive bytes = %d, want 0", got)
	}

	f, err := os.OpenFile(clone, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xa5}, 4096), 0); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := exclusiveFileBytes(clone); err != nil {
		t.Fatal(err)
	} else if got < 4096 || got >= 2<<20 {
		t.Fatalf("COW clone exclusive bytes = %d, want a positive strict subset", got)
	}
}
