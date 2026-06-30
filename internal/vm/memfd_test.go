package vm

import (
	"os"
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

func TestCaptureGuestMemFdAbsent(t *testing.T) {
	// This test process has no guest_mem memfd ⇒ must error, not panic.
	if _, err := captureGuestMemFd(os.Getpid()); err == nil {
		t.Fatal("expected error when no guest_mem memfd is present")
	}
	if _, err := captureGuestMemFd(0); err == nil {
		t.Fatal("expected error for invalid pid 0")
	}
}
