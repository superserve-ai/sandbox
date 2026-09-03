package vm

import (
	"errors"
	"os"
	"path/filepath"
)

// A pause rewrites this VM's image in place. Between removing the old
// wall-clock manifest and committing the new record, a crash would leave an
// image, a manifest and a record from different pauses, and a restore could
// trust a manifest that describes an image that no longer exists. The intent
// marker, durable beside the image before any of that starts and removed only
// once the paused record is durable, says the rewrite may not have completed.
// Every restore and resume refuses while it is present.
const pauseIntentName = "pause.intent"

func pauseIntentPath(dir string) string { return filepath.Join(dir, pauseIntentName) }

func writePauseIntent(dir, vmID string) error {
	f, err := os.OpenFile(pauseIntentPath(dir), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(vmID + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncDir(dir)
}

func clearPauseIntent(dir string) error {
	if err := os.Remove(pauseIntentPath(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(dir)
}

// pauseIntentPresent fails closed: only a definite absence permits a restore.
func pauseIntentPresent(dir string) bool {
	_, err := os.Stat(pauseIntentPath(dir))
	return !errors.Is(err, os.ErrNotExist)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
