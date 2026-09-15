//go:build !linux

package backup

import (
	"errors"
	"os"
)

// cloneSupported is false here: no clone ioctl exists, so canCloneInto
// answers without probing.
const cloneSupported = false

func cloneFile(dst, src *os.File) error {
	return errors.ErrUnsupported
}

func cloneRange(dst, src *os.File, srcOff, length, dstOff int64) error {
	return errors.ErrUnsupported
}

func deviceOf(f *os.File) (uint64, bool) {
	return 0, false
}
