package uffd

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Source is a memory-mapped read-only view of a snapshot's mem.snap file.
type Source struct {
	path    string
	file    *os.File
	mapping []byte
}

// OpenSource opens path and mmaps it PROT_READ | MAP_PRIVATE.
// MAP_POPULATE is intentionally NOT set — that would force synchronous
// memory loading, which is the exact behavior UFFD is meant to avoid.
func OpenSource(path string) (*Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mem.snap: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat mem.snap: %w", err)
	}
	size := st.Size()
	if size <= 0 {
		_ = f.Close()
		return nil, fmt.Errorf("mem.snap %s is empty", path)
	}
	data, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("mmap mem.snap: %w", err)
	}
	return &Source{path: path, file: f, mapping: data}, nil
}

func (s *Source) Size() int { return len(s.mapping) }

// PagePointer returns a kernel-facing address into the mmap'd backing,
// for direct use as the src argument to UFFDIO_COPY. The returned
// address is valid only while Source is open.
func (s *Source) PagePointer(offset, length uint64) (uint64, error) {
	if offset+length > uint64(len(s.mapping)) {
		return 0, fmt.Errorf("offset %d + length %d exceeds file size %d", offset, length, len(s.mapping))
	}
	return uint64(uintptr(unsafe.Pointer(unsafe.SliceData(s.mapping))) + uintptr(offset)), nil
}

func (s *Source) Close() error {
	var firstErr error
	if s.mapping != nil {
		if err := unix.Munmap(s.mapping); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("munmap: %w", err)
		}
		s.mapping = nil
	}
	if s.file != nil {
		if err := s.file.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close: %w", err)
		}
		s.file = nil
	}
	return firstErr
}
