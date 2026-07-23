//go:build linux

package vm

import (
	"fmt"
	"os"
	"syscall"
)

// LauncherPruneMain is the body of the hidden `vmd launcher-prune` re-exec:
// it runs inside the mount namespace `unshare --mount=<pin>` just created and
// strips every /run/netns pin from it with raw MNT_DETACH syscalls. Returns
// the process exit code.
//
// make-rprivate MUST come first to sever propagation from the host — without
// it a detach could propagate back and drop the host's live pins. The mounts
// file is read in full before the first detach so the read cannot race the
// table mutations it drives. Per-target detach failures are tolerated (the
// validator gates the result); only the safety and read steps are fatal.
func LauncherPruneMain() int {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fmt.Fprintf(os.Stderr, "make-rprivate /: %v\n", err)
		return 1
	}
	// Parent layer; the per-netns pins stacked on /run/netns/ns-N remain and
	// are handled below.
	_ = syscall.Unmount("/run/netns", syscall.MNT_DETACH)

	mounts, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read mounts: %v\n", err)
		return 1
	}
	for _, mp := range prunePaths(mounts) {
		_ = syscall.Unmount(mp, syscall.MNT_DETACH)
	}
	return 0
}
