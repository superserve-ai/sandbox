package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// fsErrorCode marks a failure raised by the sandbox's own filesystem rather
// than by boxd; callers branch on it like sandbox_storage_full.
const fsErrorCode = "sandbox_filesystem_error"

// fsErrnos are the errors a filesystem returns when it, not the request, is
// the problem — typical of network and FUSE mounts.
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

// writeFSError reports a failed filesystem operation. A failure raised by
// the filesystem itself carries its errno and the mount that served the
// path; any other error keeps the plain `{"error": message}` body.
func writeFSError(w http.ResponseWriter, path string, err error) {
	errno, ok := fsErrno(err)
	if !ok {
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

// fsErrno reports whether err was raised by the filesystem itself.
func fsErrno(err error) (syscall.Errno, bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) && fsErrnos[errno] {
		return errno, true
	}
	return 0, false
}

// mountFor returns the mount serving path, or nil when unknown. Symlinks
// are followed by name only and the walk stops at the first mountpoint, so
// a failing mount is identified without being touched again.
func mountFor(path string) *fsErrorMount {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	mounts := parseMountinfo(string(data))
	return longestMount(mounts, resolveByName(path, mounts))
}

func mountForIn(mountinfo, path string) *fsErrorMount {
	return longestMount(parseMountinfo(mountinfo), path)
}

func parseMountinfo(mountinfo string) []fsErrorMount {
	var mounts []fsErrorMount
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
		mounts = append(mounts, fsErrorMount{Mountpoint: unescapeMountinfo(fields[4]), Fstype: fields[sep+1]})
	}
	return mounts
}

// longestMount picks the deepest mountpoint that contains path.
func longestMount(mounts []fsErrorMount, path string) *fsErrorMount {
	var best *fsErrorMount
	for i := range mounts {
		m := &mounts[i]
		if pathWithin(path, m.Mountpoint) && (best == nil || len(m.Mountpoint) > len(best.Mountpoint)) {
			best = m
		}
	}
	return best
}

func pathWithin(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// insideMount reports whether p sits at or below a mountpoint other than
// the root filesystem.
func insideMount(mounts []fsErrorMount, p string) bool {
	for _, m := range mounts {
		if m.Mountpoint != "/" && pathWithin(p, m.Mountpoint) {
			return true
		}
	}
	return false
}

// unescapeMountinfo decodes the octal escapes the kernel writes for special
// characters in mountinfo fields, such as \040 for a space.
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

// resolveByName expands symlinks with readlink alone and stops once the
// path enters a mount: unlike filepath.EvalSymlinks it never stats a
// link's target or looks inside a mount, so a hung mount cannot stall the
// error response. Anything it cannot inspect is kept as written.
func resolveByName(path string, mounts []fsErrorMount) string {
	path = filepath.Clean(path)
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		relinked := false
		for i := range parts {
			prefix := "/" + filepath.Join(parts[:i+1]...)
			if insideMount(mounts, prefix) {
				return path
			}
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
// os.MkdirAll treats any stat error as "missing" and then trips over the
// existing entry (often a symlink into a mount) with EEXIST, hiding the
// filesystem's real error; here that error is returned as-is instead.
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
