package vm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// launcherPruneScript reduces a freshly cloned mount namespace to a minimal
// table by removing every /run/netns nsfs mount. A single `umount /run/netns`
// only detaches the parent layer — one nsfs mount per netns remains, stacked on
// the individual /run/netns/ns-N paths — so we also unmount each surviving
// entry. make-rprivate MUST succeed before any umount — it severs the cloned
// namespace's propagation from the host; without it, a umount could propagate
// back and detach the host's live /run/netns pins. `|| exit 1` aborts before any
// umount if it fails, so the build errors and launches fall back to legacy with
// the host untouched.
const launcherPruneScript = `mount --make-rprivate / || exit 1
umount -l /run/netns 2>/dev/null || true
for m in $(grep ' /run/netns/' /proc/self/mounts | awk '{print $2}'); do umount -l "$m" 2>/dev/null || true; done`

// EnsureLauncherNamespace makes sure the pruned launcher mount namespace exists
// and is pinned at m.launcherNSPath(), building it if missing or stale. No-op
// when the launcher launch mode is disabled.
//
// The pin is a point-in-time snapshot of the host mount table (propagation
// severed), so we REBUILD it every boot rather than reuse a prior pin — a
// launch-critical mount added since the last build (new storage volume, updated
// firecracker binary) would otherwise be invisible in a stale pin and fail
// launches. vmd restarts are the deploy/mount-change boundary, so rebuilding
// then keeps the pin current; the O(fleet) prune cost is off the hot path.
// launcherBuildTimeout bounds the boot-time launcher setup (mount/unshare/nsenter
// execs), which run before vmd serves. It must exceed the O(fleet) prune, so it's
// far larger than the 5s used for single host execs elsewhere; a wedged mount or
// /run then degrades to a logged failure + legacy fallback instead of hanging boot.
const launcherBuildTimeout = 90 * time.Second

func (m *Manager) EnsureLauncherNamespace(ctx context.Context) error {
	pinPath := m.launcherNSPath()
	if pinPath == "" {
		return nil // launcher mode disabled
	}
	ctx, cancel := context.WithTimeout(ctx, launcherBuildTimeout)
	defer cancel()
	// The launch path needs nsenter; without it, fail here (launcherReady stays
	// false) so launches fall back to legacy instead of exiting 127 per-VM.
	if _, err := exec.LookPath("nsenter"); err != nil {
		return fmt.Errorf("nsenter not found (required for launcher launch path): %w", err)
	}
	start := time.Now()
	if err := buildLauncherNamespace(ctx, pinPath); err != nil {
		return fmt.Errorf("build launcher namespace %s: %w", pinPath, err)
	}
	// The prune tolerates umount errors, so the build can exit 0 while /run/netns
	// is still present. Verify it's actually pruned before trusting it.
	if !launcherNSValid(ctx, pinPath) {
		return fmt.Errorf("launcher namespace %s built but still contains /run/netns (prune incomplete)", pinPath)
	}
	m.launcherReady.Store(true)
	m.log.Info().Str("path", pinPath).Dur("took", time.Since(start)).
		Msg("launcher namespace: built")
	return nil
}

// launcherNSValid reports whether pinPath is a live mount-namespace pin whose
// table has already been pruned of /run/netns. Absent, non-mount, or stale
// (still carrying /run/netns) → false, so the caller rebuilds.
func launcherNSValid(ctx context.Context, pinPath string) bool {
	if fi, err := os.Stat(pinPath); err != nil || fi.IsDir() {
		return false
	}
	// Match in Go, not `sh -c '! grep …'` — a missing grep would negate its 127
	// to 0 and falsely pass. Any exec error (bad pin, missing tool) → false.
	out, err := exec.CommandContext(ctx, "nsenter", "--mount="+pinPath, "--",
		"cat", "/proc/self/mounts").Output()
	if err != nil {
		return false
	}
	return !strings.Contains(string(out), " /run/netns")
}

// buildLauncherNamespace creates a fresh mount namespace, prunes /run/netns from
// it, and persists it at pinPath so it outlives the builder.
//
// util-linux `unshare --mount=<file>` persists the new mount namespace by
// binding the process's OWN /proc/self/ns/mnt to the file — the kernel-supported
// operation. (Binding another process's mount namespace cross-namespace is
// rejected by the kernel, which is what a manual parent-side bind hit.) The
// prune runs inside that same namespace, so the persisted pin refers to the
// pruned table.
func buildLauncherNamespace(ctx context.Context, pinPath string) error {
	dir := filepath.Dir(pinPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir pin dir: %w", err)
	}
	// The mount point used to persist a mount namespace must have private
	// propagation, or `unshare --mount` fails with EINVAL — systemd mounts / as
	// shared by default, so the pin dir inherits shared propagation.
	if err := ensurePrivateMount(ctx, dir); err != nil {
		return err
	}
	// unshare --mount binds onto an existing file; detach any stale pin first.
	_ = exec.CommandContext(ctx, "umount", "-l", pinPath).Run()
	if err := ensurePinFile(pinPath); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "unshare", "--mount="+pinPath, "--", "sh", "-c", launcherPruneScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("unshare --mount=%s: %v: %s", pinPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensurePrivateMount makes dir its own mount with private propagation
// (bind-mounting it to itself first if it isn't already a mount point).
// Idempotent: a dir that is already a private mount is left as-is.
func ensurePrivateMount(ctx context.Context, dir string) error {
	if exec.CommandContext(ctx, "mountpoint", "-q", dir).Run() != nil {
		if out, err := exec.CommandContext(ctx, "mount", "--bind", dir, dir).CombinedOutput(); err != nil {
			return fmt.Errorf("bind %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.CommandContext(ctx, "mount", "--make-private", dir).CombinedOutput(); err != nil {
		return fmt.Errorf("make-private %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StartMountCountSampler periodically logs the host mount-table size so the
// O(1)-launch invariant — mount count should stay roughly flat, not grow with
// the fleet — is observable in the log pipeline. One /proc/mounts read per tick.
func (m *Manager) StartMountCountSampler(ctx context.Context, every time.Duration) {
	go func() {
		defer sentrylog.Recover("mount-count sampler")
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				total, nsfs := hostMountCounts()
				m.log.Info().Int("host_mount_count", total).Int("host_nsfs_count", nsfs).
					Msg("host mount table")
				m.revalidateLauncher(ctx)
			}
		}
	}()
}

// revalidateLauncher keeps launcherReady in sync with the live pin. The startup
// check is a point-in-time snapshot; if the pin is later unmounted/deleted while
// vmd runs, every launch would keep building nsenter --mount=<stale-path> and
// fail. Re-check each tick: drop to the legacy path if the pin went bad, resume
// the launcher path if it's valid again. No-op when launcher mode is disabled.
func (m *Manager) revalidateLauncher(ctx context.Context) {
	pin := m.launcherNSPath()
	if pin == "" {
		return
	}
	valid := launcherNSValid(ctx, pin)
	switch {
	case !valid && m.launcherReady.Load():
		m.launcherReady.Store(false)
		m.log.Error().Str("path", pin).Msg("launcher pin no longer valid — falling back to legacy launch path")
	case valid && !m.launcherReady.Load():
		m.launcherReady.Store(true)
		m.log.Info().Str("path", pin).Msg("launcher pin valid again — resuming launcher launch path")
	}
}

// hostMountCounts returns the total mount count and the nsfs subset (the
// per-netns bind mounts) from /proc/mounts.
func hostMountCounts() (total, nsfs int) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		total++
		if strings.Contains(line, " nsfs ") {
			nsfs++
		}
	}
	return total, nsfs
}

func ensurePinFile(pinPath string) error {
	f, err := os.OpenFile(pinPath, os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("create pin file: %w", err)
	}
	return f.Close()
}
