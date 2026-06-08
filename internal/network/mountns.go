package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const mountNsBindRoot = "/run/sandbox/ns"

// sandboxLinkNames is the exhaustive set unbound at recycle time. Missing
// names are no-ops; update when a new template layout adds a link name.
var sandboxLinkNames = []string{"base.ext4", "overlay.ext4", "rootfs.ext4"}

type slotMountNs struct {
	BindPath string
	// TmpfsMountPoint MUST match firecracker's snapshot `path_on_host` so
	// per-VM symlinks placed inside the tmpfs become visible to fc at the
	// path it expects.
	TmpfsMountPoint string
}

// prepareSlotMountNamespace creates a persistent mount namespace via
// `unshare --mount=<bind>` — the bind keeps the namespace alive after
// unshare exits. tmpfsMountPoint is the same path for every slot; each
// slot's namespace is isolated.
func prepareSlotMountNamespace(ctx context.Context, idx int, tmpfsMountPoint string) (*slotMountNs, error) {
	if tmpfsMountPoint == "" {
		return nil, fmt.Errorf("tmpfsMountPoint is required")
	}
	if err := os.MkdirAll(mountNsBindRoot, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir bind root: %w", err)
	}
	if err := os.MkdirAll(tmpfsMountPoint, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir tmpfs mount point: %w", err)
	}

	bindPath := filepath.Join(mountNsBindRoot, fmt.Sprintf("mnt-%d", idx))
	if err := writeEmptyFile(bindPath); err != nil {
		return nil, fmt.Errorf("create bind target: %w", err)
	}

	setupScript := fmt.Sprintf(
		"mount --make-rprivate / && mount -t tmpfs tmpfs %q",
		tmpfsMountPoint,
	)
	if err := run(ctx, "unshare", "--mount="+bindPath, "--", "sh", "-c", setupScript); err != nil {
		_ = os.Remove(bindPath)
		return nil, fmt.Errorf("unshare: %w", err)
	}

	return &slotMountNs{BindPath: bindPath, TmpfsMountPoint: tmpfsMountPoint}, nil
}

func releaseSlotMountNamespace(ctx context.Context, mns *slotMountNs) error {
	if mns == nil || mns.BindPath == "" {
		return nil
	}
	_ = run(ctx, "umount", mns.BindPath)
	_ = os.Remove(mns.BindPath)
	return nil
}

// ClearStaleSlotBindMounts removes leftover bind mounts from a previous
// vmd lifetime. Running sandboxes are unaffected: fc holds its own
// /proc/<pid>/ns/mnt reference, so unmounting the bind doesn't free
// the namespace. Mount points that survived to this point are
// preserved (just restored by RestoreSlotMountNsBind during reattach).
func ClearStaleSlotBindMounts(ctx context.Context) error {
	entries, err := os.ReadDir(mountNsBindRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", mountNsBindRoot, err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "mnt-") {
			continue
		}
		path := filepath.Join(mountNsBindRoot, e.Name())
		if isMountPoint(path) {
			continue
		}
		_ = run(ctx, "umount", path)
		_ = os.Remove(path)
	}
	return nil
}

// RestoreSlotMountNsBind rebinds /proc/<pid>/ns/mnt → slot bind path
// during vmd-restart reattach so the slot keeps its prepared-namespace
// handle. Caller stores the returned path on VMNetInfo.MountNsBindPath.
func RestoreSlotMountNsBind(ctx context.Context, idx, pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}
	// PID-reuse defense: refuse to bind if /proc/<pid> isn't fc. Without
	// this, a stale BoltDB PID could point at an unrelated process whose
	// namespace we'd then expose to the next sandbox.
	if !isFirecrackerPID(pid) {
		return "", fmt.Errorf("pid %d is not a firecracker process", pid)
	}
	if err := os.MkdirAll(mountNsBindRoot, 0o755); err != nil {
		return "", fmt.Errorf("mkdir bind root: %w", err)
	}
	bindPath := filepath.Join(mountNsBindRoot, fmt.Sprintf("mnt-%d", idx))
	if err := writeEmptyFile(bindPath); err != nil {
		return "", fmt.Errorf("create bind target: %w", err)
	}
	// Drop any prior bind so we don't stack mount layers across restarts.
	if isMountPoint(bindPath) {
		_ = run(ctx, "umount", bindPath)
	}
	src := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	if err := run(ctx, "mount", "--bind", src, bindPath); err != nil {
		_ = os.Remove(bindPath)
		return "", fmt.Errorf("bind %s -> %s: %w", src, bindPath, err)
	}
	return bindPath, nil
}

func isFirecrackerPID(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "firecracker"
}

// isMountPoint via st_dev comparison — avoids depending on the
// `mountpoint` binary, whose absence would silently misclassify a
// live bind as not-a-mount and let ClearStaleSlotBindMounts tear it down.
func isMountPoint(path string) bool {
	var st1, st2 syscall.Stat_t
	if err := syscall.Lstat(path, &st1); err != nil {
		return false
	}
	if err := syscall.Lstat(filepath.Dir(path), &st2); err != nil {
		return false
	}
	return st1.Dev != st2.Dev
}

// BindSandboxIntoSlot creates per-VM symlinks inside the slot's tmpfs.
// Idempotent — re-bind after a transient failure is safe.
func BindSandboxIntoSlot(ctx context.Context, bindPath, tmpfsMountPoint string, links [][2]string) error {
	if bindPath == "" {
		return fmt.Errorf("bindPath required")
	}
	for _, l := range links {
		target, name := l[0], l[1]
		if target == "" || name == "" {
			return fmt.Errorf("bind link target and name required (got target=%q name=%q)", target, name)
		}
		linkPath := filepath.Join(tmpfsMountPoint, name)
		script := fmt.Sprintf("rm -f %q && ln -s %q %q", linkPath, target, linkPath)
		if err := run(ctx, "nsenter", "--mount="+bindPath, "--", "sh", "-c", script); err != nil {
			return fmt.Errorf("bind link %s: %w", name, err)
		}
	}
	return nil
}

// UnbindSandboxFromSlot is best-effort: missing links are no-ops.
func UnbindSandboxFromSlot(ctx context.Context, bindPath, tmpfsMountPoint string, linkNames []string) {
	if bindPath == "" {
		return
	}
	for _, name := range linkNames {
		linkPath := filepath.Join(tmpfsMountPoint, name)
		_ = run(ctx, "nsenter", "--mount="+bindPath, "--", "rm", "-f", linkPath)
	}
}

func writeEmptyFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}
