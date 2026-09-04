package vm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// WallClockManifest sits beside a memory image and says what a supervisor may
// assume about the guest inside it. Written by the template builder once the
// guest has proven it corrects its clock and froze its workload, and rewritten
// by every pause with that pause's outcome. Absent means a legacy image:
// restored the older way, owed nothing. Unreadable, or a version this binary
// does not know, refuses the restore before Firecracker is launched: guessing
// could release a frozen workload onto a stale clock, or never release it.
type WallClockManifest struct {
	Version int `json:"version"`
	// ArtifactID is minted with the manifest; a record that caches a manifest
	// names the artifact it describes.
	ArtifactID         string `json:"artifact_id"`
	WorkloadFrozen     bool   `json:"workload_frozen"`
	GuestCorrectsClock bool   `json:"guest_corrects_clock"`
	// FreezeToken is the supervisor's proof, kept by the guest across the
	// snapshot, that a wake belongs to this image's freeze. Empty when the
	// workload is not frozen.
	FreezeToken string `json:"freeze_token,omitempty"`
}

const WallClockManifestVersion = 1

// wakeProtocolEvidencePath records that this host has held an image that
// owes a wake, so the host-resident guard refuses a vmd without the wake
// protocol from then on. Raised by the template builder before it publishes
// a frozen image, and by a supervisor before it acts on one. A supervisor
// that only starts creates none, or every host would raise the floor with
// both switches off and block a rollback of itself. A host without the
// directory is not a fleet host.
var wakeProtocolEvidencePath = "/var/lib/sandbox/wake-protocol-evidence"

// wakeProtocolEvidenceNote is what the evidence file says. The guard only
// asks whether the file exists; the note is for whoever finds it.
const wakeProtocolEvidenceNote = "this host has held images that owe a wake\n"

// wakeProtocolEvidenceDone is set once evidence is known durable, whether a
// previous process wrote it or this one did.
var wakeProtocolEvidenceDone atomic.Bool

// RecognizeWakeProtocolFloor notes, at startup, evidence a previous process
// made durable. It never writes.
func RecognizeWakeProtocolFloor() bool {
	if wakeProtocolEvidenceDone.Load() {
		return true
	}
	if st, err := os.Stat(wakeProtocolEvidencePath); err == nil && st.Size() > 0 {
		wakeProtocolEvidenceDone.Store(true)
		return true
	}
	return false
}

// wakeProtocolFloorRaised reports what startup recognised, without I/O. A
// pause intent is only ever written on a host whose floor is up, so on any
// other host the checks for one are skipped, at no cost.
func wakeProtocolFloorRaised() bool { return wakeProtocolEvidenceDone.Load() }

// RaiseWakeProtocolFloor durably records that this host holds, or is about to
// hold, an image that owes a wake. The template builder calls it before it
// publishes a frozen image, so the floor is up before the artifact exists.
func RaiseWakeProtocolFloor() error {
	f, err := os.OpenFile(wakeProtocolEvidencePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(wakeProtocolEvidenceNote); err != nil {
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
	if err := syncDir(filepath.Dir(wakeProtocolEvidencePath)); err != nil {
		return err
	}
	wakeProtocolEvidenceDone.Store(true)
	return nil
}

var ErrWallClockManifest = errors.New("wall-clock manifest unreadable")

const clockFreezeMarkerSuffix = ".wallclock"

// WallClockMarkerPath is the manifest beside a memory image.
func WallClockMarkerPath(memPath string) string { return memPath + clockFreezeMarkerSuffix }

// clockFreezeMarkerPath is the internal spelling; see WallClockMarkerPath.
func clockFreezeMarkerPath(memPath string) string { return WallClockMarkerPath(memPath) }

// ReadWallClockManifest returns nil for an absent manifest and an error
// wrapping ErrWallClockManifest for one that cannot be trusted.
func ReadWallClockManifest(memPath string) (*WallClockManifest, error) {
	if memPath == "" {
		return nil, nil
	}
	b, err := os.ReadFile(WallClockMarkerPath(memPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWallClockManifest, err)
	}
	// An empty file is the marker an earlier supervisor left beside an image
	// whose guest corrects its clock. It carries no manifest: the image is
	// restored the older way, and the next pause replaces or removes it.
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var m WallClockManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrWallClockManifest, WallClockMarkerPath(memPath), err)
	}
	if m.Version != WallClockManifestVersion {
		return nil, fmt.Errorf("%w: %s: version %d, this supervisor speaks %d", ErrWallClockManifest, WallClockMarkerPath(memPath), m.Version, WallClockManifestVersion)
	}
	if m.WorkloadFrozen && m.FreezeToken == "" {
		return nil, fmt.Errorf("%w: %s: frozen workload without a freeze token", ErrWallClockManifest, WallClockMarkerPath(memPath))
	}
	return &m, nil
}

// WriteWallClockManifest publishes the manifest atomically: a reader sees the
// previous one or this one, never a partial file.
func WriteWallClockManifest(memPath string, m WallClockManifest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	path := WallClockMarkerPath(memPath)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// NewFreezeToken and NewArtifactID mint 16 random bytes; uniqueness is all
// that matters, and nothing inside a guest can guess one.
func NewFreezeToken() string { return randomHex() }
func NewArtifactID() string  { return randomHex() }

func randomHex() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// imageManifest is the manifest that governs a restore of memPath: its own,
// and only its own. An overlay never inherits its base's: a paused overlay
// without a manifest of its own is a legacy image, whatever the template it
// was cut from says, or a running workload could be restored under a frozen
// clock.
func imageManifest(memPath string) (*WallClockManifest, error) {
	return ReadWallClockManifest(memPath)
}
