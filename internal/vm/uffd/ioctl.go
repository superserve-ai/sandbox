// Package uffd implements a userfaultfd page-fault handler for Firecracker
// snapshot restore. The handler receives a userfaultfd file descriptor from
// Firecracker over a Unix domain socket, then serves page faults by copying
// pages from a memory snapshot file into the guest's address space.
//
// One handler per VM. Lifecycle is tied to the VM's gRPC restore call —
// the handler goroutine is spawned before LoadSnapshot is issued and
// terminates when the VM is destroyed or the UFFD fd closes.
package uffd

import (
	"fmt"
	"syscall"
	"unsafe"
)

// From <linux/userfaultfd.h>, verified against Linux 6.8. _IO[RW]
// encoding: (dir << 30) | (sizeof << 16) | (type << 8) | nr, with
// type = 0xAA. Pinned by TestIoctlNumbers so a struct resize can't
// silently break the kernel ABI.
const (
	UFFDIO_COPY       uintptr = 0xC028AA03
	UFFDIO_ZEROPAGE   uintptr = 0xC020AA04
	UFFDIO_UNREGISTER uintptr = 0x8010AA01
)

const (
	UFFD_EVENT_PAGEFAULT uint8 = 0x12
	UFFD_EVENT_FORK      uint8 = 0x13
	UFFD_EVENT_REMAP     uint8 = 0x14
	UFFD_EVENT_REMOVE    uint8 = 0x15
	UFFD_EVENT_UNMAP     uint8 = 0x16
)

const (
	UFFDIO_COPY_MODE_DONTWAKE uint64 = 1 << 0
	UFFDIO_COPY_MODE_WP       uint64 = 1 << 1
)

type uffdioRange struct {
	Start uint64
	Len   uint64
}

type uffdioCopy struct {
	Dst  uint64
	Src  uint64
	Len  uint64
	Mode uint64
	Copy int64 // out: bytes copied, or -errno on failure
}

type uffdioZeropage struct {
	Range    uffdioRange
	Mode     uint64
	Zeropage int64
}

// uffdMsg matches the packed 32-byte struct uffd_msg in the kernel.
// Arg is the union; interpret based on Event.
type uffdMsg struct {
	Event     uint8
	Reserved1 uint8
	Reserved2 uint16
	Reserved3 uint32
	Arg       [24]byte
}

type PageFaultArg struct {
	Flags   uint64
	Address uint64
	Ptid    uint32
	_       uint32
}

type RemoveArg struct {
	Start uint64
	End   uint64
	_     uint64
}

func (m *uffdMsg) asPageFault() PageFaultArg {
	return *(*PageFaultArg)(unsafe.Pointer(&m.Arg[0]))
}

func (m *uffdMsg) asRemove() RemoveArg {
	return *(*RemoveArg)(unsafe.Pointer(&m.Arg[0]))
}

// ioctlCopy returns bytes_copied on success, or an error wrapping the
// kernel errno. Callers should check errors.Is(err, syscall.EEXIST) and
// errors.Is(err, syscall.EAGAIN) — these are benign races (concurrent
// fault on same page, or REMOVE event pending in queue).
//
// The kernel reports failures via op.Copy = -errno, which we extract
// because the syscall return errno is often less specific.
func ioctlCopy(uffdFd uintptr, dst, src uint64, length uint64, mode uint64) (int64, error) {
	op := uffdioCopy{
		Dst:  dst,
		Src:  src,
		Len:  length,
		Mode: mode,
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uffdFd, UFFDIO_COPY, uintptr(unsafe.Pointer(&op)))
	if op.Copy < 0 {
		return op.Copy, syscall.Errno(-op.Copy)
	}
	if errno != 0 {
		return op.Copy, errno
	}
	return op.Copy, nil
}

func ioctlZeropage(uffdFd uintptr, start uint64, length uint64) error {
	op := uffdioZeropage{
		Range: uffdioRange{Start: start, Len: length},
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uffdFd, UFFDIO_ZEROPAGE, uintptr(unsafe.Pointer(&op)))
	if errno != 0 && op.Zeropage <= 0 {
		return fmt.Errorf("UFFDIO_ZEROPAGE: %w (zeropage=%d)", errno, op.Zeropage)
	}
	return nil
}

// No UFFDIO_UNREGISTER wrapper: closing the fd auto-unregisters all
// regions. Constant is pinned by TestIoctlNumbers for ABI docs.
