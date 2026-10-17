//go:build !linux

package vm

import "fmt"

func PunchZeroBlocks(_ string) (int64, error) {
	return 0, fmt.Errorf("punching holes requires Linux")
}
