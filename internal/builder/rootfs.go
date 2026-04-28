package builder

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// makeExt4 produces an ext4 filesystem image at destPath sized to sizeMiB,
// populated from srcDir. Requires mkfs.ext4 on the host PATH.
//
// Flags chosen to match modern Linux distro defaults and what Firecracker
// expects:
//   -t ext4                    filesystem type
//   -d srcDir                  populate from directory
//   -L rootfs                  filesystem label
//   -E root_owner=0:0          entries owned by root:root regardless of
//                              builder uid (we may not run as root)
//   -F                         force creation (don't prompt if file exists)
//   -m 1                       reserve 1% for root (default is 5% — wasteful
//                              for small rootfs images)
//
// destPath is created / truncated to exactly sizeMiB MiB before mkfs runs.
// If mkfs fails, destPath is removed so the caller doesn't see a half-written
// file.
func makeExt4(ctx context.Context, srcDir, destPath string, sizeMiB uint32) error {
	if sizeMiB == 0 {
		return fmt.Errorf("sizeMiB must be > 0")
	}
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		return fmt.Errorf("mkfs.ext4 not found on PATH: %w", err)
	}

	// Pre-allocate the target file to exactly sizeMiB MiB. We truncate
	// instead of dd so the file is sparse — mkfs.ext4 happily writes into
	// a sparse file, and we don't burn IO writing zeros that would be
	// overwritten anyway.
	if err := os.Truncate(destPath, 0); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("truncate existing %s: %w", destPath, err)
	}
	f, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	if err := f.Truncate(int64(sizeMiB) << 20); err != nil {
		f.Close()
		_ = os.Remove(destPath)
		return fmt.Errorf("size %s: %w", destPath, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("close %s: %w", destPath, err)
	}

	cmd := exec.CommandContext(ctx, "mkfs.ext4",
		"-t", "ext4",
		"-d", srcDir,
		"-L", "rootfs",
		"-E", "root_owner=0:0",
		"-m", "1",
		"-F",
		destPath,
	)
	// Capture stderr so the caller sees mkfs's actual error message on
	// failure, rather than just "exit status 1".
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("mkfs.ext4: %w: %s", err, string(out))
	}

	return nil
}
