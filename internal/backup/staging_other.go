//go:build !linux

package backup

import (
	"errors"
	"os"
)

func cloneFile(dst, src *os.File) error {
	return errors.ErrUnsupported
}
