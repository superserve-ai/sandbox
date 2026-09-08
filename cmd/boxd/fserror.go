package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// fsErrorCode marks a failure raised by the sandbox's own filesystem — a
// stale handle, an I/O error, an unreachable mount — as opposed to boxd
// itself failing. Callers branch on `error.code` the same way they do for
// sandbox_storage_full.
const fsErrorCode = "sandbox_filesystem_error"

// fsErrnos are the errors a filesystem returns when it, rather than the
// request, is the problem. They are typical of network and FUSE mounts a
// workload attaches inside the sandbox.
var fsErrnos = map[syscall.Errno]bool{
	syscall.ESTALE:       true,
	syscall.EIO:          true,
	syscall.ENOTCONN:     true,
	syscall.ETIMEDOUT:    true,
	syscall.EHOSTDOWN:    true,
	syscall.EHOSTUNREACH: true,
	syscall.ENETDOWN:     true,
	syscall.ENETUNREACH:  true,
}

type fsErrorMount struct {
	Mountpoint string `json:"mountpoint"`
	Fstype     string `json:"fstype"`
}

type fsErrorBody struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Errno   string        `json:"errno"`
	Path    string        `json:"path,omitempty"`
	Mount   *fsErrorMount `json:"mount,omitempty"`
}

// writeFSError reports a failed filesystem operation on path. A failure
// that came from the filesystem itself gets the sandbox_filesystem_error
// code, the errno, and the mount that served the path, so the caller can
// tell a misbehaving mount from a boxd fault. Any other error keeps the
// plain `{"error": message}` body.
func writeFSError(w http.ResponseWriter, path string, err error) {
	var errno syscall.Errno
	if !errors.As(err, &errno) || !fsErrnos[errno] {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	body := fsErrorBody{
		Code:    fsErrorCode,
		Message: err.Error(),
		Errno:   unix.ErrnoName(errno),
		Path:    path,
		Mount:   mountFor(path),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": body})
}

// mountFor returns the mount serving path, or nil when it cannot be
// determined. Symlinks are followed by name only: the target of a link
// into a mount is matched even when that mount no longer answers stat.
func mountFor(path string) *fsErrorMount {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	return mountForIn(string(data), resolveByName(path))
}

// mountForIn picks the longest mountpoint in mountinfo that contains path.
func mountForIn(mountinfo, path string) *fsErrorMount {
	var best *fsErrorMount
	for _, line := range strings.Split(mountinfo, "\n") {
		fields := strings.Fields(line)
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if len(fields) < 5 || sep < 0 || sep+1 >= len(fields) {
			continue
		}
		mp := strings.ReplaceAll(fields[4], `\040`, " ")
		if path != mp && !strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/") {
			continue
		}
		if best == nil || len(mp) > len(best.Mountpoint) {
			best = &fsErrorMount{Mountpoint: mp, Fstype: fields[sep+1]}
		}
	}
	return best
}

// resolveByName expands the symlinks in path using readlink alone. Unlike
// filepath.EvalSymlinks it never stats a link's target, so a link pointing
// into a broken mount still resolves to that mount's path; components that
// cannot be inspected are kept as written.
func resolveByName(path string) string {
	path = filepath.Clean(path)
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		relinked := false
		for i := range parts {
			prefix := "/" + filepath.Join(parts[:i+1]...)
			fi, err := os.Lstat(prefix)
			if err != nil {
				return path
			}
			if fi.Mode()&os.ModeSymlink == 0 {
				continue
			}
			target, err := os.Readlink(prefix)
			if err != nil {
				return path
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(prefix), target)
			}
			path = filepath.Clean(filepath.Join(append([]string{target}, parts[i+1:]...)...))
			relinked = true
			break
		}
		if !relinked {
			return path
		}
	}
	return path
}

// ensureParentDir creates path's parent only when it is genuinely absent.
// An existing entry — including a symlink into another filesystem — is
// left alone, and any other lookup failure is returned as-is. os.MkdirAll
// treats every stat error as "missing" and then trips over the existing
// entry with EEXIST, hiding the filesystem's real error.
func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	_, err := os.Lstat(dir)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(dir, 0o755)
}
