//go:build linux

package vm

import (
	"errors"
	"fmt"
	"math"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	fsIOCFiemap          = 0xC020660B
	fiemapFlagSync       = 0x00000001
	fiemapExtentLast     = 0x00000001
	fiemapExtentUnknown  = 0x00000002
	fiemapExtentDelalloc = 0x00000004
	fiemapExtentShared   = 0x00002000
	fiemapBatchExtents   = 256
)

type fiemapHeader struct {
	Start         uint64
	Length        uint64
	Flags         uint32
	MappedExtents uint32
	ExtentCount   uint32
	Reserved      uint32
}

type fiemapExtent struct {
	Logical    uint64
	Physical   uint64
	Length     uint64
	Reserved64 [2]uint64
	Flags      uint32
	Reserved   [3]uint32
}

func savedSnapshotExtentAccountingSupported() bool { return true }

// exclusiveFileBytes returns allocated data extents that are not currently
// shared by filesystem CoW. Unlike st_blocks, FIEMAP's SHARED flag lets the
// shadow ledger exclude immutable bases referenced by many forks while still
// counting blocks dirtied into an otherwise-reflinked child.
func exclusiveFileBytes(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	headerSize := int(unsafe.Sizeof(fiemapHeader{}))
	extentSize := int(unsafe.Sizeof(fiemapExtent{}))
	buf := make([]byte, headerSize+fiemapBatchExtents*extentSize)
	var start uint64
	var total uint64
	for {
		clear(buf)
		header := (*fiemapHeader)(unsafe.Pointer(&buf[0]))
		header.Start = start
		header.Length = math.MaxUint64 - start
		header.Flags = fiemapFlagSync
		header.ExtentCount = fiemapBatchExtents
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), fsIOCFiemap, uintptr(unsafe.Pointer(&buf[0])))
		if errno != 0 {
			return 0, fmt.Errorf("FIEMAP %s: %w", path, errno)
		}
		if header.MappedExtents == 0 {
			break
		}
		if header.MappedExtents > fiemapBatchExtents {
			return 0, fmt.Errorf("FIEMAP %s returned invalid extent count %d", path, header.MappedExtents)
		}

		last := false
		for i := uint32(0); i < header.MappedExtents; i++ {
			offset := headerSize + int(i)*extentSize
			extent := (*fiemapExtent)(unsafe.Pointer(&buf[offset]))
			if extent.Length == 0 {
				return 0, fmt.Errorf("FIEMAP %s returned a zero-length extent", path)
			}
			if extent.Flags&(fiemapExtentUnknown|fiemapExtentDelalloc) != 0 {
				return 0, fmt.Errorf("FIEMAP %s returned unresolved extent flags %#x", path, extent.Flags)
			}
			if extent.Flags&fiemapExtentShared == 0 {
				if math.MaxUint64-total < extent.Length {
					return 0, errors.New("exclusive extent byte count overflow")
				}
				total += extent.Length
			}
			next := extent.Logical + extent.Length
			if next <= start {
				return 0, fmt.Errorf("FIEMAP %s did not advance", path)
			}
			start = next
			last = extent.Flags&fiemapExtentLast != 0
		}
		if last {
			break
		}
	}
	if total > math.MaxInt64 {
		return 0, errors.New("exclusive extent byte count exceeds int64")
	}
	return int64(total), nil
}
