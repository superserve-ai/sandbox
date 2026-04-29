package builder

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// tiniBinary is a static linux/amd64 build of tini v0.19.0 — a minimal
// init that reaps zombies + forwards signals. Baked into the binary so
// every template build injects the same reviewed bytes without needing
// network access or a separate artifact pipeline.
//
// Source: https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-amd64
//
//go:embed assets/tini-static-amd64
var tiniBinary []byte

// seedentropyBinary is a static linux/amd64 binary that injects entropy
// into the kernel's CRNG pool via the RNDADDENTROPY ioctl. Firecracker
// VMs boot with near-zero entropy (no virtio-rng, no RDRAND on this
// kernel), which causes getrandom() to block and TLS handshakes to hang.
// The init script runs this before exec'ing tini to unblock getrandom().
//
//go:embed assets/seedentropy-amd64
var seedentropyBinary []byte

// injectGuestAgent copies the boxd binary into the flattened rootfs, drops
// an embedded tini binary for proper PID 1 behavior, and writes a tiny
// /sbin/init wrapper that mounts essential filesystems then exec's tini
// with boxd as the supervised child.
//
// We can't rely on systemd here: OCI base images (python:3.11-slim,
// node:22-slim, ubuntu:24.04, etc.) don't ship systemd as PID 1. We use
// tini because it's purpose-built for this — proper zombie reaping, clean
// signal forwarding — at ~850 KB vs ~100 MB of installing systemd.
//
// See docs/INIT_STRATEGY.md for the full rationale and migration path to
// systemd when we need its feature set.
//
// Must be called AFTER pullAndFlatten — operates on the extracted tree.
//
// Layout produced:
//   /usr/bin/boxd              (0755)  — the guest agent binary
//   /usr/local/bin/tini        (0755)  — PID 1 helper, embedded at build
//   /sbin/init                 (0755)  — shell wrapper that execs tini
//
// Returns the byte count of the boxd binary copied, for observability.
func injectGuestAgent(rootfsDir, boxdBinaryPath string) (int64, error) {
	if boxdBinaryPath == "" {
		return 0, fmt.Errorf("boxd binary path is empty")
	}
	if _, err := os.Stat(boxdBinaryPath); err != nil {
		return 0, fmt.Errorf("stat boxd binary %s: %w", boxdBinaryPath, err)
	}

	binSize, err := copyFile(boxdBinaryPath, filepath.Join(rootfsDir, "usr/bin/boxd"), 0o755)
	if err != nil {
		return 0, fmt.Errorf("copy boxd: %w", err)
	}

	// Write the embedded tini binary into the rootfs.
	tiniPath := filepath.Join(rootfsDir, "usr/local/bin/tini")
	if err := os.MkdirAll(filepath.Dir(tiniPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir /usr/local/bin: %w", err)
	}
	if err := os.WriteFile(tiniPath, tiniBinary, 0o755); err != nil {
		return 0, fmt.Errorf("write tini: %w", err)
	}
	if err := os.Chmod(tiniPath, 0o755); err != nil {
		return 0, fmt.Errorf("chmod tini: %w", err)
	}

	// Write the entropy seeder binary.
	seedPath := filepath.Join(rootfsDir, "usr/local/bin/seedentropy")
	if err := os.WriteFile(seedPath, seedentropyBinary, 0o755); err != nil {
		return 0, fmt.Errorf("write seedentropy: %w", err)
	}
	if err := os.Chmod(seedPath, 0o755); err != nil {
		return 0, fmt.Errorf("chmod seedentropy: %w", err)
	}

	// Write the init wrapper at /sbin/init. Overwrites whatever the base
	// image had (often a systemd symlink that won't work here). The kernel
	// defaults to /sbin/init when no init= arg is passed, so this path is
	// picked up automatically without any Firecracker-side changes.
	if err := os.MkdirAll(filepath.Join(rootfsDir, "sbin"), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir /sbin: %w", err)
	}
	initPath := filepath.Join(rootfsDir, "sbin/init")
	_ = os.Remove(initPath)
	if err := os.WriteFile(initPath, []byte(initScript), 0o755); err != nil {
		return 0, fmt.Errorf("write /sbin/init: %w", err)
	}
	if err := os.Chmod(initPath, 0o755); err != nil {
		return 0, fmt.Errorf("chmod /sbin/init: %w", err)
	}

	// Write a static /etc/resolv.conf. Many base images (notably
	// ubuntu:24.04) ship /etc/resolv.conf as a symlink to
	// /run/systemd/resolve/stub-resolv.conf expecting systemd-resolved
	// to provide DNS at 127.0.0.53. We don't run systemd-resolved — so
	// we nuke the symlink and write a real file pointing at Google +
	// Cloudflare public resolvers.
	//
	// 1.1.1.1 and 8.8.8.8 are both reachable from within our network
	// namespace via the host's NAT. Order matters slightly: the first
	// resolver is tried first, the second is a fallback.
	resolvPath := filepath.Join(rootfsDir, "etc/resolv.conf")
	if err := os.MkdirAll(filepath.Dir(resolvPath), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir /etc: %w", err)
	}
	_ = os.Remove(resolvPath) // handles the symlink case
	if err := os.WriteFile(resolvPath, []byte(resolvConf), 0o644); err != nil {
		return 0, fmt.Errorf("write /etc/resolv.conf: %w", err)
	}

	return binSize, nil
}

// resolvConf is the minimal DNS config baked into every template rootfs.
// Kept ASCII-only and ordered for predictable retry behavior.
const resolvConf = `# Superserve template rootfs — baked at build time.
# systemd-resolved is not running here; these are direct public resolvers.
nameserver 1.1.1.1
nameserver 8.8.8.8
options timeout:2 attempts:2
`

// initScript runs first as PID 1, mounts the filesystems the kernel doesn't
// auto-mount, then exec's tini to take over. After the exec, tini is PID 1
// (not the shell) and owns boxd as its supervised child.
//
// Why the shell wrapper instead of making /sbin/init be tini directly:
//
//	Tini is a C program that doesn't mount /proc, /sys, /dev. The kernel
//	only mounts rootfs; everything else is userspace responsibility. If
//	tini were PID 1 without these, libraries that read /proc/self/* —
//	which boxd's Go runtime does at startup — would fail. A few lines of
//	shell before the exec gets us a working OS environment, then hands off
//	to tini cleanly via exec (shell process is replaced, tini becomes PID 1).
//
// POSIX sh is assumed; all our allowed base images (debian, ubuntu) have it.
const initScript = `#!/bin/sh
# Superserve template init — mounts essentials, then execs tini to become
# PID 1 proper. See docs/INIT_STRATEGY.md for why this exists.

set +e
mkdir -p /proc /sys /dev /run /tmp
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmpfs /run 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
mkdir -p /dev/pts /home/user
mount -t devpts devpts /dev/pts -o gid=5,mode=620,ptmxmode=666 2>/dev/null

# Seed the kernel entropy pool. Firecracker VMs lack virtio-rng and
# RDRAND, so getrandom() blocks until entropy is credited. The
# seedentropy binary reads /proc/interrupts + clock and injects it
# via RNDADDENTROPY ioctl, unblocking TLS for pip/curl/etc.
/usr/local/bin/seedentropy 2>/dev/null

# Hand off to tini. After exec, tini is PID 1 — it'll reap zombies from
# any process whose parent exits (common when boxd spawns subprocesses for
# user ExecCommand calls and those spawn more), and forward SIGTERM to
# boxd on graceful VM shutdown.
exec /usr/local/bin/tini -- /usr/bin/boxd
`

// copyFile copies src → dst, creating parent directories as needed. Overwrites
// dst if it exists. Returns bytes written.
func copyFile(src, dst string, mode os.FileMode) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 0, err
	}
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return n, copyErr
	}
	if closeErr != nil {
		return n, closeErr
	}
	// Explicit chmod — O_CREATE respects umask, which can strip bits. We want
	// exactly the caller-supplied mode on disk.
	if err := os.Chmod(dst, mode); err != nil {
		return n, err
	}
	return n, nil
}
