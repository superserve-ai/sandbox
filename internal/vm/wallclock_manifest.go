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

// WakeProtocolCapability is the string a vmd that speaks this manifest and its
// wake protocol carries; rollback tooling greps binaries for it.
const WakeProtocolCapability = "wake-protocol-1"

// wakeProtocolEvidencePath is written the first time this daemon reads a
// manifest — on restore, on pause, or in the templates it holds: this host has
// images only a vmd with the wake protocol can handle, and the host-resident
// guard refuses any other from then on. Best-effort and once; a host without
// the directory is not a fleet host.
var wakeProtocolEvidencePath = "/var/lib/sandbox/wake-protocol-evidence"

// wakeProtocolEvidenceDone is set only once the write is durable, so a failed
// attempt is retried rather than forgotten; the mutex makes concurrent first
// restores share one write instead of each paying the fsync.
var (
	wakeProtocolEvidenceDone atomic.Bool
	wakeProtocolEvidenceMu   sync.Mutex
)

// noteWakeProtocolEvidence is the best-effort form, for manifests read where
// nothing is about to act on them (a pause, the template scan).
func noteWakeProtocolEvidence() {
	if _, err := os.Stat(filepath.Dir(wakeProtocolEvidencePath)); err != nil {
		return
	}
	_ = ensureWakeProtocolFloor()
}

// recognizeWakeProtocolFloor notes evidence a previous process made durable.
// It never writes: only an image that owes a wake raises the floor.
func recognizeWakeProtocolFloor() bool {
	if wakeProtocolEvidenceDone.Load() {
		return true
	}
	if st, err := os.Stat(wakeProtocolEvidencePath); err == nil && st.Size() > 0 {
		wakeProtocolEvidenceDone.Store(true)
		return true
	}
	return false
}

// ensureWakeProtocolFloor is the form a restore of an image that owes a wake
// must pass before it launches anything: durable once, then free.
func ensureWakeProtocolFloor() error {
	if recognizeWakeProtocolFloor() {
		return nil
	}
	wakeProtocolEvidenceMu.Lock()
	defer wakeProtocolEvidenceMu.Unlock()
	if recognizeWakeProtocolFloor() {
		return nil
	}
	if err := RaiseWakeProtocolFloor(); err != nil {
		return err
	}
	wakeProtocolEvidenceDone.Store(true)
	return nil
}

// RaiseWakeProtocolFloor durably records that this host holds, or is about to
// hold, an image that owes a wake. The template builder calls it before it
// publishes a frozen image, so the floor is up before the artifact exists;
// the daemon calls it before it restores one and on every manifest it reads.
func RaiseWakeProtocolFloor() error {
	f, err := os.OpenFile(wakeProtocolEvidencePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(WakeProtocolCapability + "\n"); err != nil {
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
	return syncDir(filepath.Dir(wakeProtocolEvidencePath))
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
	noteWakeProtocolEvidence()
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
// restore has to happen first, and nothing is configured anywhere. A
// directory listing every few minutes, off every request path.
func (m *Manager) WatchTemplateManifests(ctx context.Context, log zerolog.Logger) {
	if m.cfg.SnapshotDir == "" {
		return
	}
	// Before any request: evidence a previous process made durable is
	// recognised, so the first frozen operation after a restart pays nothing.
	// Only recognised — starting a vmd creates no evidence, or the daemon
	// would raise the floor on every host with both switches off and block a
	// rollback of itself.
	recognizeWakeProtocolFloor()
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
// directory (which records the evidence as a side effect) and returns how
// many it found.
func (m *Manager) scanTemplateManifests() int {
	// Templates live at templates/<template>/<build>/; the shallower pattern
	// is kept so a flattened layout could never hide one.
	root := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName)
	deep, _ := filepath.Glob(filepath.Join(root, "*", "*", "*"+clockFreezeMarkerSuffix))
	shallow, _ := filepath.Glob(filepath.Join(root, "*", "*"+clockFreezeMarkerSuffix))
	matches := append(deep, shallow...)
	n := 0
	for _, path := range matches {
		if man, err := ReadWallClockManifest(strings.TrimSuffix(path, clockFreezeMarkerSuffix)); err == nil && man != nil {
			n++
		}
	}
	return n
}
