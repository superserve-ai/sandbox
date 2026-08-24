package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.log")

	if _, _, err := tailFile(p, 64); err == nil {
		t.Fatal("missing file must error, not read as empty")
	}

	if err := os.WriteFile(p, []byte("short"), 0o644); err != nil {
		t.Fatal(err)
	}
	tail, size, err := tailFile(p, 64)
	if err != nil || tail != "short" || size != 5 {
		t.Fatalf("small file: tail=%q size=%d err=%v", tail, size, err)
	}

	big := strings.Repeat("x", 100) + "THE-END"
	if err := os.WriteFile(p, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	tail, size, err = tailFile(p, 16)
	if err != nil || size != int64(len(big)) || len(tail) != 16 || !strings.HasSuffix(tail, "THE-END") {
		t.Fatalf("tail window: tail=%q size=%d err=%v", tail, size, err)
	}

	// Empty file: no error, empty tail — "guest produced no output" is the
	// signal the forensics log relies on.
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tail, size, err = tailFile(p, 16)
	if err != nil || tail != "" || size != 0 {
		t.Fatalf("empty file: tail=%q size=%d err=%v", tail, size, err)
	}
}
