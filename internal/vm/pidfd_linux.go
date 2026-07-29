//go:build linux

package vm

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// killExactVMFirecrackerPID binds the numeric PID to a pidfd before reading
// identity. If the process exits and the PID is reused at any later point, the
// signal still targets only the originally opened process description.
func killExactVMFirecrackerPID(pid int, vmID string, wait time.Duration) (bool, error) {
	if pid <= 0 || vmID == "" {
		return false, nil
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("pidfd_open(%d): %w", pid, err)
	}
	defer unix.Close(pidfd)

	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read process %d identity: %w", pid, err)
	}
	if !firecrackerCmdlineMatches(cmdline, vmID) {
		return false, nil
	}

	if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return true, fmt.Errorf("pidfd_send_signal(%d): %w", pid, err)
	}
	if wait > 0 {
		timeoutMS := int(wait.Milliseconds())
		if timeoutMS < 1 {
			timeoutMS = 1
		}
		poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, timeoutMS); err != nil && !errors.Is(err, unix.EINTR) {
			return true, fmt.Errorf("poll pidfd %d: %w", pid, err)
		}
	}
	return true, nil
}
