package vm

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// PunchZeroBlocks turns every all-zero, block-aligned zeroHoleBlock of path into
// a hole, leaving its size and contents unchanged, and returns the bytes punched.
// A hole reads as zeros, which is what lets a restore leave that memory to the
// kernel. Build path only: it reads the whole file.
func PunchZeroBlocks(path string) (int64, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	buf := make([]byte, zeroHoleBlock)
	var off, punched int64
	for {
		n, err := io.ReadFull(f, buf)
		if n == zeroHoleBlock && bytes.Equal(buf, zeroBlock) {
			if perr := unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, off, zeroHoleBlock); perr != nil {
				return punched, fmt.Errorf("punch %s at %d: %w", path, off, perr)
			}
			punched += zeroHoleBlock
		}
		off += int64(n)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return punched, nil
		}
		if err != nil {
			return punched, err
		}
	}
}

var zeroBlock = make([]byte, zeroHoleBlock)
