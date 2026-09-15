//go:build !linux

package backup

import (
	"errors"
	"os"
)

func cloneFile(dst, src *os.File) error {
	return errors.ErrUnsupported
}

func cloneRange(dst, src *os.File, srcOff, length, dstOff int64) error {
	return errors.ErrUnsupported
}
