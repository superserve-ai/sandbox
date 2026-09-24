//go:build !linux

package vm

import (
	"errors"
	"os"
)

func cloneFileFD(_, _ *os.File) error { return errors.ErrUnsupported }
