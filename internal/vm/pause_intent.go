package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	// Staged means the write went to a staging directory and the images
	// beside this intent were not touched, so their manifests stand.
	Staged bool `json:"staged,omitempty"`
}

// StagedIntentCapability is the string a vmd that reads staged intents
// carries; the host guard greps the binary for it.
const StagedIntentCapability = "staged-intent-1"

// stagedIntentEvidencePath records that this host has journalled a staged
// intent. A vmd without StagedIntentCapability recovers one as an
// interrupted rewrite and strips the manifest the source's images still
// need, so the evidence is durable before the first such intent is written
// and the host guard refuses such a vmd from then on.
var stagedIntentEvidencePath = "/var/lib/sandbox/staged-intent-evidence"

const stagedIntentEvidenceNote = "this host has journalled staged capture intents\n"

var (
	stagedIntentEvidenceDurable atomic.Bool
	stagedIntentEvidenceMu      sync.Mutex
)

// ensureStagedIntentFloor is durable once, then free.
func ensureStagedIntentFloor() error {
	if stagedIntentEvidenceDurable.Load() {
		return nil
	}
	stagedIntentEvidenceMu.Lock()
	defer stagedIntentEvidenceMu.Unlock()
	if stagedIntentEvidenceDurable.Load() {
		return nil
	}
	if _, err := os.Stat(stagedIntentEvidencePath); err == nil {
		// Visible, but not proven durable by this process.
		if err := syncDir(filepath.Dir(stagedIntentEvidencePath)); err != nil {
			return err
		}
	} else if err := raiseEvidenceFile(stagedIntentEvidencePath, stagedIntentEvidenceNote); err != nil {
		return err
	}
	stagedIntentEvidenceDurable.Store(true)
	return nil
}

// writeStagedIntent journals an intent whose write goes to staging, behind
// the floor that keeps an older vmd from misreading it.
func writeStagedIntent(dir string, in pauseIntent) error {
	if err := ensureStagedIntentFloor(); err != nil {
		return fmt.Errorf("raise the staged-intent floor: %w", err)
	}
	in.Staged = true
	return writePauseIntent(dir, in)
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
