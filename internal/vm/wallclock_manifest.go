package vm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
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

// WakeProtocolCapability is the string a vmd that can wake a frozen image
// carries; the host guard and the deploy check grep the binary for it.
const WakeProtocolCapability = "wake-protocol-1"

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

// Two facts about the evidence, kept apart: seen, the file is visible, which
// is what turns the pause-intent checks on; and durable, this process has
// itself synced the directory that holds it. A file left visible by a raise
// whose directory sync failed is seen but not durable, and the next raise
// must repair that rather than trust it.
var (
	wakeProtocolEvidenceSeen    atomic.Bool
	wakeProtocolEvidenceDurable atomic.Bool
)

// RecognizeWakeProtocolFloor notes, at startup, evidence a previous process
// left. It never writes. Existence is the fact, as it is for the host guard:
// the file is only ever created whole, so its size says nothing.
func RecognizeWakeProtocolFloor() bool {
	if wakeProtocolEvidenceSeen.Load() {
		return true
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); err == nil {
		wakeProtocolEvidenceSeen.Store(true)
		return true
	}
	return false
}

// wakeProtocolFloorRaised reports what startup recognised, without I/O. A
// pause intent is only ever written on a host whose floor is up, so on any
// other host the checks for one are skipped, at no cost.
func wakeProtocolFloorRaised() bool { return wakeProtocolEvidenceSeen.Load() }

// wakeProtocolEvidenceMu makes concurrent first raises share one write
// instead of each paying the sync.
var wakeProtocolEvidenceMu sync.Mutex

// ensureWakeProtocolFloor is the form a supervisor uses before it acts on an
// image that owes a wake — freezing one, restoring one: durable once, then
// free. Never on a request path for an image that owes nothing.
func ensureWakeProtocolFloor() error {
	if wakeProtocolEvidenceDurable.Load() {
		return nil
	}
	wakeProtocolEvidenceMu.Lock()
	defer wakeProtocolEvidenceMu.Unlock()
	return RaiseWakeProtocolFloor()
}

// noteWakeProtocolEvidence is the best-effort form, for the template scan: a
// host without the directory is not a fleet host.
func noteWakeProtocolEvidence() {
	if _, err := os.Stat(filepath.Dir(wakeProtocolEvidencePath)); err != nil {
		return
	}
	_ = ensureWakeProtocolFloor()
}

// RaiseWakeProtocolFloor durably records that this host holds, or is about to
// hold, an image that owes a wake. The template builder calls it before it
// publishes a frozen image, so the floor is up before the artifact exists.
// Created once and whole: an existing file is left as it is, and a new one
// appears by rename, so no crash and no concurrent build can leave an empty
// file that one reader honours and another does not.
func RaiseWakeProtocolFloor() error {
	if wakeProtocolEvidenceDurable.Load() {
		return nil
	}
	if _, err := os.Stat(wakeProtocolEvidencePath); err == nil {
		// Visible, but not proven durable by this process: a raise whose
		// directory sync failed leaves the file visible all the same, and
		// startup recognition proves nothing. Sync the directory before
		// this one counts it.
		if err := syncDir(filepath.Dir(wakeProtocolEvidencePath)); err != nil {
			return err
		}
		wakeProtocolEvidenceSeen.Store(true)
		wakeProtocolEvidenceDurable.Store(true)
		return nil
	}
	tmp := wakeProtocolEvidencePath + ".tmp." + strconv.Itoa(os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(wakeProtocolEvidenceNote); err != nil {
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
	if err := os.Rename(tmp, wakeProtocolEvidencePath); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := syncDir(filepath.Dir(wakeProtocolEvidencePath)); err != nil {
		return err
	}
	wakeProtocolEvidenceSeen.Store(true)
	wakeProtocolEvidenceDurable.Store(true)
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
	// The fields are protocol and recovery invariants: a manifest names its
	// artifact, and a frozen workload carries the token its wake must present
	// and comes from a guest that will correct its clock once woken.
	if m.ArtifactID == "" {
		return nil, fmt.Errorf("%w: %s: no artifact id", ErrWallClockManifest, WallClockMarkerPath(memPath))
	}
	if m.WorkloadFrozen && (m.FreezeToken == "" || !m.GuestCorrectsClock) {
		return nil, fmt.Errorf("%w: %s: frozen workload without a freeze token, or from a guest that does not correct its clock", ErrWallClockManifest, WallClockMarkerPath(memPath))
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

// WatchTemplateManifests keeps the wake-protocol evidence in step with the
// templates this host holds. Templates are seeded while the daemon runs, so
// the first frozen one to land is what raises the rollback floor here — no
// restore has to happen first. A directory listing at start and every few
// minutes, off every request path.
func (m *Manager) WatchTemplateManifests(ctx context.Context, log zerolog.Logger) {
	if m.cfg.SnapshotDir == "" {
		return
	}
	scan := func() {
		if n := m.scanTemplateManifests(); n > 0 && !wakeProtocolEvidenceLogged.Swap(true) {
			log.Info().Int("templates", n).Msg("this host holds images that owe a wake; a vmd without the wake protocol is refused from now on")
		}
	}
	go func() {
		scan()
		t := time.NewTicker(firecrackerCapabilityRefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				scan()
			}
		}
	}()
}

var wakeProtocolEvidenceLogged atomic.Bool

// scanTemplateManifests reads every template manifest under the snapshot
// directory, raises the floor for each frozen one, and returns how many
// frozen ones it found.
func (m *Manager) scanTemplateManifests() int {
	// Templates live at templates/<template>/<build>/; the shallower pattern
	// is kept so a flattened layout could never hide one.
	root := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName)
	deep, _ := filepath.Glob(filepath.Join(root, "*", "*", "*"+clockFreezeMarkerSuffix))
	shallow, _ := filepath.Glob(filepath.Join(root, "*", "*"+clockFreezeMarkerSuffix))
	n := 0
	for _, path := range append(deep, shallow...) {
		man, err := ReadWallClockManifest(strings.TrimSuffix(path, clockFreezeMarkerSuffix))
		if err != nil || man == nil || !man.WorkloadFrozen {
			continue
		}
		n++
		noteWakeProtocolEvidence()
	}
	return n
}
