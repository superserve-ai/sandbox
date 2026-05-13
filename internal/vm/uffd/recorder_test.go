package uffd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRecorder_DedupAndOrder(t *testing.T) {
	r := NewRecorder()
	r.Record(4096)
	r.Record(8192)
	r.Record(4096) // duplicate — must be ignored
	r.Record(12288)
	r.Record(8192) // duplicate

	if r.Len() != 3 {
		t.Fatalf("Len = %d, want 3", r.Len())
	}

	path := filepath.Join(t.TempDir(), "access.log")
	if err := r.Flush(path, false); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"4096", "8192", "12288"}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("flushed contents = %v, want %v (first-touch order, deduped)", lines, want)
	}
}

func TestRecorder_FlushAtomicRename(t *testing.T) {
	r := NewRecorder()
	r.Record(4096)

	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	if err := r.Flush(path, false); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// .tmp must NOT survive a successful flush — the rename should have
	// moved it into place. A leftover .tmp signals a torn flush.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file %q still exists after successful flush", path+".tmp")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("output file missing after flush: %v", err)
	}
}

func TestRecorder_FlushEmpty(t *testing.T) {
	r := NewRecorder()
	path := filepath.Join(t.TempDir(), "access.log")
	if err := r.Flush(path, false); err != nil {
		t.Fatalf("Flush on empty recorder: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("empty recorder flushed %d bytes, want 0", info.Size())
	}
}

func TestRecorder_FlushSorted(t *testing.T) {
	r := NewRecorder()
	r.Record(12288)
	r.Record(4096)
	r.Record(8192)

	path := filepath.Join(t.TempDir(), "access.log")
	if err := r.Flush(path, true); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"4096", "8192", "12288"}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("sorted flush = %v, want %v", lines, want)
	}
}
