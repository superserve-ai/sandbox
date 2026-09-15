package vm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// A pause rewrites this VM's image in place. Between freezing the guest,
// removing the old wall-clock manifest and committing the new record, a crash
// would leave a guest frozen with nobody holding its token, or an image, a
// manifest and a record from different pauses. The intent, durable beside the
// image before the freeze and removed only once the paused record is durable,
// carries what recovery needs: the token to release the guest, and the
// artifact id that tells a completed pause's leftover marker from an
// interrupted one. Every restore and resume refuses while an unresolved
// intent is present.
const pauseIntentName = "pause.intent"

type pauseIntent struct {
	VMID        string `json:"vm_id"`
	FreezeToken string `json:"freeze_token,omitempty"`
	ArtifactID  string `json:"artifact_id"`
}

func pauseIntentPath(dir string) string { return filepath.Join(dir, pauseIntentName) }

func writePauseIntent(dir string, in pauseIntent) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(pauseIntentPath(dir), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
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

// readPauseIntent returns nil for an absent intent and an error for one that
// cannot be read or parsed; the callers treat that as blocking.
func readPauseIntent(dir string) (*pauseIntent, error) {
	b, err := os.ReadFile(pauseIntentPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var in pauseIntent
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, err
	}
	return &in, nil
}

func clearPauseIntent(dir string) error {
	if err := os.Remove(pauseIntentPath(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(dir)
}

// pauseIntentBlocks reports whether an intent beside the image forbids a
// restore. An intent naming the artifact the record already describes is the
// leftover of a pause that completed but could not remove it; that one is
// cleared and does not block. Anything else, including an unreadable intent,
// blocks until inspected.
func pauseIntentBlocks(dir, recordedArtifactID string) (blocked bool, reason string) {
	in, err := readPauseIntent(dir)
	if err != nil {
		return true, "pause intent unreadable: " + err.Error()
	}
	if in == nil {
		return false, ""
	}
	if in.ArtifactID != "" && in.ArtifactID == recordedArtifactID {
		if err := clearPauseIntent(dir); err != nil {
			return true, "completed pause's intent could not be cleared: " + err.Error()
		}
		return false, ""
	}
	return true, "a pause was interrupted while rewriting this image"
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
