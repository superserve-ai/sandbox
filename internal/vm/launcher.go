package vm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// launcherPruneScript strips every /run/netns nsfs mount from a freshly cloned
// namespace. A single `umount /run/netns` detaches only the parent layer; the
// per-netns nsfs mounts remain stacked on /run/netns/ns-N, so we unmount each.
// make-rprivate MUST run first (|| exit 1) to sever propagation from the host —
// without it a umount could propagate back and detach the host's live pins.
const launcherPruneScript = `mount --make-rprivate / || exit 1
umount -l /run/netns 2>/dev/null || true
for m in $(grep ' /run/netns/' /proc/self/mounts | awk '{print $2}'); do umount -l "$m" 2>/dev/null || true; done`

// launcherBuildTimeout reaps a genuinely wedged mount syscall — it does not
// pace the build, which runs async with legacy-path fallback until done, so a
// slow build costs nothing. The prune is O(host mount table), so the bound
// must stay comfortably ahead of fleet growth: a bound the prune catches up
// to silently strands the host on the legacy launch path.
const launcherBuildTimeout = 10 * time.Minute

// EnsureLauncherNamespace builds and pins the pruned launcher mount namespace at
// m.launcherNSPath(). No-op when launcher mode is disabled. The pin snapshots the
// host mount table, so it's rebuilt every boot rather than reused — a launch-
// critical mount added since the last build would be invisible in a stale pin,
// and vmd restart is the mount-change boundary that keeps it current.
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
	m.launcherBuilt.Store(true)
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

// nsfsMagic is NSFS_MAGIC from linux/magic.h — the statfs f_type of a namespace
// bind mount.
const nsfsMagic = 0x6e736673

// pinIsMounted reports whether pinPath still has the mount-namespace pin
// bind-mounted over it (an unmounted pin statfs's as the underlying tmpfs, a
// deleted one errors). One syscall, no fork — cheap and non-flaky enough for the
// per-launch hot path, unlike launcherNSValid's nsenter exec, which stays the
// deep check for boot and the sampler.
func pinIsMounted(pinPath string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(pinPath, &st); err != nil {
		return false
	}
	return st.Type == nsfsMagic
}

// buildLauncherNamespace creates a fresh mount namespace, prunes /run/netns from
// it, and persists it at pinPath. `unshare --mount=<file>` self-persists by
// binding the process's own /proc/self/ns/mnt (binding another process's mount
// namespace is kernel-rejected), and runs the prune in that same namespace so the
// pin refers to the pruned table.
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

// ensurePrivateMount makes dir its own mount with private propagation by
// self-binding it. Idempotent: an already-private dir (our bind from a prior
// boot) is reused; a pre-existing NON-private mount is refused — never
// make-private a mount we didn't create.
func ensurePrivateMount(ctx context.Context, dir string) error {
	// Resolve symlinks first: mountinfo records the resolved path (/var/run/… →
	// /run/…), so comparing an unresolved dir would never match our prior bind
	// and stack a fresh one every boot.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	// Read propagation from /proc/self/mountinfo, not the `mountpoint` binary: it
	// isn't preflighted, so on a minimal image its absence would read as "not a
	// mount point" and stack a fresh bind on every restart.
	mounted, private, err := mountState(dir)
	if err != nil {
		return fmt.Errorf("mount state %s: %w", dir, err)
	}
	if mounted {
		// Already a mount. If private, it's our pin-dir bind from a prior boot —
		// reuse it. If not, dir is a pre-existing host mount the pin path points
		// under (e.g. VMD_LAUNCHER_NS_PATH directly beneath /run or /); refuse
		// rather than make-private it, which would flip that mount's propagation
		// host-wide. Legacy fallback covers the misconfiguration safely.
		if !private {
			return fmt.Errorf("pin dir %s is a pre-existing non-private mount; set VMD_LAUNCHER_NS_PATH under a dedicated directory", dir)
		}
		return nil
	}
	// Fresh dir: create a dedicated self-bind and make ONLY it private, so the pin
	// gets a private parent without touching any host mount's propagation.
	if out, err := exec.CommandContext(ctx, "mount", "--bind", dir, dir).CombinedOutput(); err != nil {
		return fmt.Errorf("bind %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "mount", "--make-private", dir).CombinedOutput(); err != nil {
		return fmt.Errorf("make-private %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// mountState reports whether dir is a mount point and, if so, whether that mount
// has private propagation. Scans /proc/self/mountinfo: fields left of " - " are
// mount id, parent, major:minor, root, mount point, opts, then optional
// propagation tags (shared:/master:/propagate_from:) — a private mount has none,
// so exactly 6 left-fields.
func mountState(dir string) (mounted, private bool, err error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, false, err
	}
	mounted, private = parseMountState(data, dir)
	return mounted, private, nil
}

func parseMountState(mountinfo []byte, dir string) (mounted, private bool) {
	for _, line := range strings.Split(string(mountinfo), "\n") {
		left, _, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		// The mount point (field 5) is octal-escaped by the kernel, so unescape it
		// before comparing — otherwise a pin dir with a space matches nothing, is
		// treated as unmounted, and stacks a fresh bind on every restart.
		if f := strings.Fields(left); len(f) >= 5 && unescapeMountinfo(f[4]) == dir {
			return true, len(f) == 6
		}
	}
	return false, false
}

// unescapeMountinfo decodes the octal escapes the kernel writes for special
// bytes in /proc/self/mountinfo path fields (space \040, tab \011, newline \012,
// backslash \134). Other bytes pass through untouched.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
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

// revalidateLauncher re-syncs launcherReady with the live pin each tick: drop to
// legacy if the pin went bad, and re-enable only the pin THIS boot built
// (launcherBuilt) — a previous-boot pin left mounted after a failed rebuild may
// be missing launch-critical mounts, so it must never resurrect the launcher
// path. No-op when launcher mode is disabled.
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
	case valid && m.launcherBuilt.Load() && !m.launcherReady.Load():
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
