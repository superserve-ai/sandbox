//go:build linux

package vm

import (
	"fmt"
	"math"
	"os"
	"syscall"
	"unsafe"

	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	"golang.org/x/sys/unix"
)

func sameRetainedFileMetadata(before, after any) bool {
	a, ok := before.(*syscall.Stat_t)
	if !ok || a == nil {
		return false
	}
	b, ok := after.(*syscall.Stat_t)
	if !ok || b == nil {
		return false
	}
	left, right := *a, *b
	// Reading a saved manifest can update atime without changing its generation.
	left.Atim, right.Atim = syscall.Timespec{}, syscall.Timespec{}
	return left == right
}

type storageFiemapExtent struct {
	Logical, Physical, Length uint64
	Reserved                  [2]uint64
	Flags                     uint32
	Reserved2                 [3]uint32
}
type storageFiemap struct {
	Start, Length                  uint64
	Flags, Mapped, Count, Reserved uint32
	Extents                        [256]storageFiemapExtent
}

// No FIEMAP_FLAG_SYNC: the meter must not flush a running guest's writes.
// Delayed, encoded, inline, or otherwise ambiguous allocations are unknown.
func retainedFileExtents(f *os.File, budget int) ([]retainedstorage.Extent, string, error) {
	var before unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &before); err != nil {
		return nil, "", err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil {
		return nil, "", err
	}
	if fs.Type != unix.XFS_SUPER_MAGIC && fs.Type != unix.EXT4_SUPER_MAGIC {
		return nil, "", fmt.Errorf("unsupported allocation filesystem")
	}
	device := fmt.Sprintf("%x:%x", before.Dev, fs.Fsid.Val)
	out := make([]retainedstorage.Extent, 0)
	var start uint64
	var allocated int64
	for {
		fm := storageFiemap{Start: start, Length: math.MaxUint64 - start, Count: 256}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), 0xc020660b, uintptr(unsafe.Pointer(&fm)))
		if errno != 0 {
			return nil, "", errno
		}
		if fm.Mapped > fm.Count {
			return nil, "", fmt.Errorf("invalid extent response")
		}
		if fm.Mapped == 0 {
			break
		}
		for _, e := range fm.Extents[:fm.Mapped] {
			// LAST, UNWRITTEN and SHARED have concrete physical addresses.
			if e.Flags & ^uint32(0x1|0x800|0x2000) != 0 || e.Physical == 0 || e.Length == 0 || e.Physical > math.MaxInt64 || e.Length > math.MaxInt64-e.Physical || e.Logical < start || e.Length > math.MaxUint64-e.Logical {
				return nil, "", fmt.Errorf("unresolved physical allocation")
			}
			if len(out) >= budget || allocated > math.MaxInt64-int64(e.Length) {
				return nil, "", fmt.Errorf("extent budget exceeded")
			}
			out = append(out, retainedstorage.Extent{Device: device, Start: int64(e.Physical), Length: int64(e.Length)})
			allocated += int64(e.Length)
			start = e.Logical + e.Length
		}
		if fm.Extents[fm.Mapped-1].Flags&1 != 0 {
			break
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &after); err != nil {
		return nil, "", err
	}
	if before.Ino != after.Ino || before.Size != after.Size || before.Blocks != after.Blocks || before.Mtim != after.Mtim || before.Ctim != after.Ctim || after.Nlink == 0 {
		return nil, "", fmt.Errorf("allocation changed during sampling")
	}
	if before.Blocks < 0 || before.Blocks > math.MaxInt64/512 || allocated > before.Blocks*512 {
		return nil, "", fmt.Errorf("allocation metadata disagrees")
	}
	// Extent-tree metadata is private to the inode, even for reflink copies.
	if extra := before.Blocks*512 - allocated; extra > 0 {
		if len(out) >= budget {
			return nil, "", fmt.Errorf("extent budget exceeded")
		}
		out = append(out, retainedstorage.Extent{Device: fmt.Sprintf("%s:inode:%x", device, before.Ino), Length: extra})
	}
	generation := fmt.Sprintf("%s:%x:%d:%v:%v", device, before.Ino, before.Size, before.Mtim, before.Ctim)
	return out, generation, nil
}
