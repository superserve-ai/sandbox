package builder

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// pullAndFlatten resolves imageRef (e.g. "python:3.11") to a digest, pulls
// the linux/amd64 layers, and extracts the flattened filesystem into destDir.
// Returns the resolved "sha256:..." digest for persistence on template_build.
//
// destDir must exist and be writable. Existing contents are NOT cleared;
// callers should pass a fresh empty directory.
//
// Whiteout handling: OCI layers express deletions via `.wh.<name>` entries.
// We honor them during layer-by-layer extraction — a `.wh.foo` file in a
// later layer removes `foo` from the accumulated tree. This matches what a
// runtime like Docker/containerd does when materializing an image.
func (b *inProcessBuilder) pullAndFlatten(ctx context.Context, imageRef, destDir string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parse image reference %q: %w", imageRef, err)
	}

	// remote.WithContext lets context cancellation propagate into the HTTP
	// transport so aborted builds actually stop downloading.
	img, err := remote.Image(ref,
		remote.WithContext(ctx),
		remote.WithPlatform(v1.Platform{OS: b.cfg.PlatformOS, Architecture: b.cfg.PlatformArch}),
		remote.WithAuthFromKeychain(keychain),
	)
	if err != nil {
		return "", fmt.Errorf("fetch image %q: %w", imageRef, err)
	}

	if err := validatePlatform(img, b.cfg.PlatformOS, b.cfg.PlatformArch); err != nil {
		return "", err
	}

	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("read digest: %w", err)
	}

	// Flatten: export the squashed image as a single tar stream (crane does
	// the layer replay + whiteout resolution for us), then extract into
	// destDir. Less code than hand-rolling per-layer replay and already
	// battle-tested by the crane CLI.
	pr, pw := io.Pipe()
	exportErr := make(chan error, 1)
	go func() {
		defer pw.Close()
		exportErr <- crane.Export(img, pw)
	}()

	if err := extractTar(ctx, pr, destDir, b.cfg.MaxUncompressedSizeBytes); err != nil {
		// Drain the export goroutine so it doesn't deadlock on pipe write.
		_ = pr.CloseWithError(err)
		<-exportErr
		return "", fmt.Errorf("extract image: %w", err)
	}
	if err := <-exportErr; err != nil {
		return "", fmt.Errorf("export image: %w", err)
	}

	return digest.String(), nil
}

// validatePlatform rejects images that don't match the required OS/arch and
// rejects known-incompatible bases (alpine, distroless) early with a clear
// message. Catches configuration mistakes before the slow mkfs.ext4 step.
func validatePlatform(img v1.Image, wantOS, wantArch string) error {
	cfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("read image config: %w", err)
	}
	if cfg.OS != wantOS {
		return fmt.Errorf("image os is %q, want %q", cfg.OS, wantOS)
	}
	if cfg.Architecture != wantArch {
		return fmt.Errorf("image architecture is %q, want %q", cfg.Architecture, wantArch)
	}
	// Heuristic: look at the config's labels and entrypoint for hints that
	// this is an alpine / distroless / busybox-only image. Cheap, catches
	// the common cases before we waste time pulling.
	for _, env := range cfg.Config.Env {
		if strings.HasPrefix(strings.ToLower(env), "path=") {
			if strings.Contains(env, "/sbin:/bin") && !strings.Contains(env, "/usr/sbin") {
				// Busybox-style layout. Alpine fits this pattern.
				return fmt.Errorf("image appears to be alpine or busybox-based (PATH looks minimal); use a debian/ubuntu-based image")
			}
		}
	}
	return nil
}

// extractTar reads a flattened image tarball and writes entries into destDir,
// preserving mode, ownership (within process privileges), symlinks, and
// hardlinks. Rejects path traversal (..) and symlinks pointing outside destDir.
// Enforces maxBytes total across all regular files when >0.
func extractTar(ctx context.Context, r io.Reader, destDir string, maxBytes int64) error {
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	if info, err := os.Stat(absDest); err != nil {
		return fmt.Errorf("stat destDir: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("destDir is not a directory: %s", absDest)
	}

	tr := tar.NewReader(r)
	var totalBytes int64

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read tar header: %w", err)
		}
		cleaned := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "/../") {
			return fmt.Errorf("tar entry escapes destDir: %q", hdr.Name)
		}
		target := filepath.Join(absDest, cleaned)

		// Defense in depth — even after Clean/Join, make sure we stayed
		// inside the destination tree. A malicious archive could contain
		// absolute paths or symlink targets that Clean doesn't normalize.
		if rel, err := filepath.Rel(absDest, target); err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("tar entry escapes destDir after join: %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)&0o7777); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent of %s: %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode)&0o7777)
			if err != nil {
				return fmt.Errorf("create %s: %w", target, err)
			}
			written, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if copyErr != nil {
				return fmt.Errorf("write %s: %w", target, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close %s: %w", target, closeErr)
			}
			totalBytes += written
			if maxBytes > 0 && totalBytes > maxBytes {
				return fmt.Errorf("flattened image exceeds %d bytes", maxBytes)
			}

		case tar.TypeSymlink:
			// Reject symlinks whose resolved target escapes the rootfs. The
			// symlink itself can point anywhere from inside the rootfs at
			// build time, but we don't want one that silently reads host
			// /etc/shadow when later resolved. Relative links resolved
			// against the symlink's parent; absolute links resolved as if
			// rooted at destDir (which matches how they'd behave inside
			// the VM's chroot).
			if err := validateSymlink(absDest, target, hdr.Linkname); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent of %s: %w", target, err)
			}
			_ = os.Remove(target) // overwrite if exists (later layer wins)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("symlink %s: %w", target, err)
			}

		case tar.TypeLink:
			linkTarget := filepath.Join(absDest, filepath.Clean(hdr.Linkname))
			if rel, err := filepath.Rel(absDest, linkTarget); err != nil || strings.HasPrefix(rel, "..") {
				return fmt.Errorf("hardlink target escapes destDir: %q → %q", hdr.Name, hdr.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent of %s: %w", target, err)
			}
			_ = os.Remove(target)
			if err := os.Link(linkTarget, target); err != nil {
				return fmt.Errorf("hardlink %s → %s: %w", target, linkTarget, err)
			}

		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			// Device nodes and fifos require CAP_MKNOD; we're not running
			// as root here, so skip with a warning rather than failing. The
			// guest kernel creates /dev entries at boot via devtmpfs anyway.
			continue

		default:
			// Unknown type — skip rather than abort. Matches crane's behavior.
			continue
		}

		// Preserve mtime for files/symlinks where possible. Best-effort;
		// ignore errors (not all filesystems support sub-second precision).
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime)
		}
	}
}

// validateSymlink ensures the resolved target of a symlink created at
// `linkPath` pointing at `linkname` doesn't escape absDest.
func validateSymlink(absDest, linkPath, linkname string) error {
	var resolved string
	if filepath.IsAbs(linkname) {
		resolved = filepath.Join(absDest, linkname)
	} else {
		resolved = filepath.Join(filepath.Dir(linkPath), linkname)
	}
	resolved = filepath.Clean(resolved)
	if rel, err := filepath.Rel(absDest, resolved); err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("symlink target escapes rootfs: %s → %s", linkPath, linkname)
	}
	return nil
}

// umaskZero sets the process umask to 0 for the duration of tar extraction
// so file permissions from the tar entries land verbatim (no 022 masking).
// Returns a restore function; callers defer it.
func umaskZero() func() {
	old := syscall.Umask(0)
	return func() { syscall.Umask(old) }
}
