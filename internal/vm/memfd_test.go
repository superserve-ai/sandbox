package vm

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCaptureGuestMemFd exercises the locate-by-readlink + magic-symlink reopen
// against a real memfd created in this process, named exactly like Firecracker's
// guest-memory memfd. It proves the reopened fd refers to the same inode (same
// pages) and survives the original fd being closed.
func TestCaptureGuestMemFd(t *testing.T) {
	// memfd_create("guest_mem") — same name Firecracker uses, so /proc/self/fd
	// reports the readlink captureGuestMemFd matches on.
	mfd, err := unix.MemfdCreate("guest_mem", 0)
	if err != nil {
		t.Fatalf("memfd_create: %v", err)
	}
	orig := os.NewFile(uintptr(mfd), "guest_mem")

	const want = "page-zero-marker"
	if err := orig.Truncate(4096); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := orig.WriteAt([]byte(want), 0); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	held, err := captureGuestMemFd(os.Getpid())
	if err != nil {
		t.Fatalf("captureGuestMemFd: %v", err)
	}
	defer held.Close()

	// Same inode ⇒ same memory object, not a copy.
	var origStat, heldStat unix.Stat_t
	if err := unix.Fstat(int(orig.Fd()), &origStat); err != nil {
		t.Fatalf("fstat orig: %v", err)
	}
	if err := unix.Fstat(int(held.Fd()), &heldStat); err != nil {
		t.Fatalf("fstat held: %v", err)
	}
	if origStat.Ino != heldStat.Ino || origStat.Dev != heldStat.Dev {
		t.Fatalf("captured fd is a different inode: orig dev=%d ino=%d held dev=%d ino=%d",
			origStat.Dev, origStat.Ino, heldStat.Dev, heldStat.Ino)
	}

	// Close the original (simulating Firecracker exiting): pages must persist
	// because the held fd still references the inode.
	if err := orig.Close(); err != nil {
		t.Fatalf("close orig: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := held.ReadAt(buf, 0); err != nil {
		t.Fatalf("read via held fd after orig close: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("held fd content = %q, want %q", buf, want)
	}
}

// TestDumpMemfdPages drives the bridge dump end to end: a memfd with two dirty pages,
// a dirty-offsets sidecar naming them, then readDirtyOffsets + dumpMemfdPages must
// reproduce exactly those pages in a sparse diff layer (the rest left as zero holes).
func TestDumpMemfdPages(t *testing.T) {
	ps := os.Getpagesize()
	const npages = 5

	fd, err := unix.MemfdCreate("guest_mem", 0)
	if err != nil {
		t.Fatalf("memfd_create: %v", err)
	}
	src := os.NewFile(uintptr(fd), "guest_mem")
	defer src.Close()
	if err := src.Truncate(int64(npages * ps)); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	// Dirty pages 1 (0xAA) and 3 (0xBB); pages 0,2,4 stay holes.
	if _, err := src.WriteAt(bytes.Repeat([]byte{0xAA}, ps), int64(1*ps)); err != nil {
		t.Fatalf("write page 1: %v", err)
	}
	if _, err := src.WriteAt(bytes.Repeat([]byte{0xBB}, ps), int64(3*ps)); err != nil {
		t.Fatalf("write page 3: %v", err)
	}

	dir := t.TempDir()
	sidecar := filepath.Join(dir, "mem.dirty.offsets")
	var enc []byte
	for _, off := range []uint64{uint64(1 * ps), uint64(3 * ps)} {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], off)
		enc = append(enc, b[:]...)
	}
	if err := os.WriteFile(sidecar, enc, 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	offsets, err := readDirtyOffsets(sidecar)
	if err != nil {
		t.Fatalf("readDirtyOffsets: %v", err)
	}
	if want := []uint64{uint64(1 * ps), uint64(3 * ps)}; len(offsets) != 2 || offsets[0] != want[0] || offsets[1] != want[1] {
		t.Fatalf("offsets = %v, want %v", offsets, want)
	}

	out := filepath.Join(dir, "mem.0.diff")
	if err := dumpMemfdPages(src, offsets, out, ps); err != nil {
		t.Fatalf("dumpMemfdPages: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if len(data) != npages*ps {
		t.Fatalf("out size = %d, want %d", len(data), npages*ps)
	}
	for pg, want := range map[int]byte{0: 0x00, 1: 0xAA, 2: 0x00, 3: 0xBB, 4: 0x00} {
		got := data[pg*ps : pg*ps+ps]
		if !bytes.Equal(got, bytes.Repeat([]byte{want}, ps)) {
			t.Fatalf("page %d: first byte 0x%02x, want all 0x%02x", pg, got[0], want)
		}
	}
}

func TestReadDirtyOffsetsTruncated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "off")
	if err := os.WriteFile(p, []byte{1, 2, 3}, 0o644); err != nil { // not a multiple of 8
		t.Fatal(err)
	}
	if _, err := readDirtyOffsets(p); err == nil {
		t.Fatal("expected error for truncated offsets file")
	}
}

func TestCaptureGuestMemFdAbsent(t *testing.T) {
	// This test process has no guest_mem memfd ⇒ must error, not panic.
	if _, err := captureGuestMemFd(os.Getpid()); err == nil {
		t.Fatal("expected error when no guest_mem memfd is present")
	}
	if _, err := captureGuestMemFd(0); err == nil {
		t.Fatal("expected error for invalid pid 0")
	}
}
