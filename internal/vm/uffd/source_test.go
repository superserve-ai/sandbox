package uffd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceOpenAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mem.snap")

	// 8 KiB of recognizable bytes — two pages, each with a distinct pattern
	// at the page boundary so we can verify PagePointer offsets.
	page := 4096
	buf := make([]byte, 2*page)
	for i := range buf[:page] {
		buf[i] = 0x11
	}
	for i := range buf[page:] {
		buf[page+i] = 0x22
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	src, err := OpenSource(path)
	if err != nil {
		t.Fatalf("OpenSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if src.Size() != 2*page {
		t.Errorf("Size = %d, want %d", src.Size(), 2*page)
	}

	// PagePointer should report distinct offsets for the two pages.
	p0, err := src.PagePointer(0, uint64(page))
	if err != nil {
		t.Fatalf("PagePointer page 0: %v", err)
	}
	p1, err := src.PagePointer(uint64(page), uint64(page))
	if err != nil {
		t.Fatalf("PagePointer page 1: %v", err)
	}
	if p1-p0 != uint64(page) {
		t.Errorf("page pointer delta = %d, want %d", p1-p0, page)
	}

	// Verify mmap contents by reading the internal mapping (test is in
	// the same package). PagePointer returns a kernel-facing uint64; we
	// don't want to round-trip it through unsafe.Pointer in test code.
	if !bytes.Equal(src.mapping[:page], buf[:page]) {
		t.Errorf("page 0 contents mismatch")
	}
	if !bytes.Equal(src.mapping[page:], buf[page:]) {
		t.Errorf("page 1 contents mismatch")
	}
}

func TestSourceBoundsCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mem.snap")
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	src, err := OpenSource(path)
	if err != nil {
		t.Fatalf("OpenSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	// Reading past the end must error rather than reach into nothing.
	if _, err := src.PagePointer(4096, 4096); err == nil {
		t.Error("PagePointer past EOF returned nil error, want bounds error")
	}
}

func TestSourceRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.snap")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := OpenSource(path); err == nil {
		t.Error("OpenSource on empty file returned nil error, want non-nil")
	}
}
