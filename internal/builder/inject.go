package builder

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// injectGuestAgent copies the boxd binary into the flattened rootfs at
// /usr/bin/boxd and installs a systemd unit that starts it on boot. The
// unit is symlinked into multi-user.target.wants so it activates under the
// standard boot target used by debian/ubuntu-based images.
//
// Must be called AFTER pullAndFlatten — operates on the extracted tree.
//
// Layout produced:
//   /usr/bin/boxd                                      (0755)
//   /etc/systemd/system/boxd.service                   (0644)
//   /etc/systemd/system/multi-user.target.wants/boxd.service → ../boxd.service
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

	unitDir := filepath.Join(rootfsDir, "etc/systemd/system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", unitDir, err)
	}
	unitPath := filepath.Join(unitDir, "boxd.service")
	if err := os.WriteFile(unitPath, []byte(boxdUnit), 0o644); err != nil {
		return 0, fmt.Errorf("write boxd.service: %w", err)
	}

	// Enable: multi-user.target.wants → boxd.service. systemctl enable
	// would create this link at runtime; we bake it at build time so the
	// VM comes up with boxd active on the very first boot.
	wantsDir := filepath.Join(unitDir, "multi-user.target.wants")
	if err := os.MkdirAll(wantsDir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", wantsDir, err)
	}
	wantsLink := filepath.Join(wantsDir, "boxd.service")
	_ = os.Remove(wantsLink) // overwrite if exists from a prior inject
	if err := os.Symlink("../boxd.service", wantsLink); err != nil {
		return 0, fmt.Errorf("symlink boxd.service into multi-user.target.wants: %w", err)
	}

	return binSize, nil
}

// boxdUnit is the systemd unit that boxd runs under inside every sandbox VM.
// Kept minimal — no sandboxing directives because the entire VM is already
// the isolation boundary. Restart=always so a crash loop surfaces the error
// via journalctl without silently dropping the guest agent.
const boxdUnit = `[Unit]
Description=Superserve guest agent (boxd)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/boxd
Restart=always
RestartSec=2
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
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
