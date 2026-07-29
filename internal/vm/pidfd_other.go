//go:build !linux

package vm

import (
	"fmt"
	"time"
)

// Production VMD hosts are Linux. Refuse to perform an identity-sensitive
// kill on platforms without pidfds rather than falling back to a racy numeric
// PID signal.
func killExactVMFirecrackerPID(pid int, vmID string, wait time.Duration) (bool, error) {
	if pid <= 0 || vmID == "" || !pidIsVMFirecracker(pid, vmID) {
		return false, nil
	}
	return true, fmt.Errorf("safe pidfd signalling is unavailable on this platform")
}
