package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// standardStreamLinks are the /dev entries udev or systemd would create on a
// regular system. The guest init only mounts devtmpfs, which has none of
// them, and shells (bash process substitution), tee, and install scripts
// that read /dev/stdin fail without them.
var standardStreamLinks = [...]struct{ name, target string }{
	{"fd", "/proc/self/fd"},
	{"stdin", "/proc/self/fd/0"},
	{"stdout", "/proc/self/fd/1"},
	{"stderr", "/proc/self/fd/2"},
}

// ensureStandardStreamLinks creates the missing links under dev and leaves
// any entry an image already provides untouched. It runs before the
// listener exists, so the first exec sees them; the cost is bounded at four
// lstat/symlink calls on an in-memory filesystem at boot, and a restore
// never boots.
func ensureStandardStreamLinks(dev string) error {
	var errs []error
	for _, link := range standardStreamLinks {
		path := filepath.Join(dev, link.name)
		if _, err := os.Lstat(path); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("lstat %s: %w", path, err))
			continue
		}
		if err := os.Symlink(link.target, path); err != nil && !errors.Is(err, os.ErrExist) {
			errs = append(errs, fmt.Errorf("symlink %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}
