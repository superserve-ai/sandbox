package vm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// snapshotManifest records a layered memory snapshot as a read-only base image
// plus an ordered chain of immutable diff overlays (oldest → newest). It is the
// on-disk form for the append-only pause path: each pause appends a new overlay
// and republishes the manifest, instead of merging the diff in place. An
// interrupted write therefore can never corrupt a prior layer — the previously
// committed manifest still points at the intact chain.
//
// It generalizes the single-overlay ".base" sidecar: that case is a one-element
// chain. The manifest lives at <snapshotDir>/manifest.json alongside the overlay
// files it names.
type snapshotManifest struct {
	// Base is the absolute path to the read-only template memory image — the
	// chain's bottom layer (a full image), shared per template and living outside
	// the sandbox's snapshot dir.
	Base string `json:"base"`
	// Overlays are the diff-layer file names (basenames within the snapshot dir),
	// ordered oldest → newest. The newest is the active layer (the loader's
	// snapshot path); the earlier ones are lower overlays.
	Overlays []string `json:"overlays"`
}

const manifestFileName = "manifest.json"

func manifestPath(dir string) string { return filepath.Join(dir, manifestFileName) }

// overlayLayerName is the file name for the diff overlay at chain index i.
func overlayLayerName(i int) string { return fmt.Sprintf("mem.%d.diff", i) }

// readManifest loads the layered manifest from dir, or (nil, nil) when absent
// (the non-layered / legacy single-overlay case).
func readManifest(dir string) (*snapshotManifest, error) {
	b, err := os.ReadFile(manifestPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var m snapshotManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse snapshot manifest %s: %w", manifestPath(dir), err)
	}
	return &m, nil
}

// writeManifestAtomic publishes m via a temp file + rename, so a crash mid-write
// leaves the previous manifest intact — the rename is the commit point. The temp
// file and the directory are fsync'd so the published manifest is durable.
func writeManifestAtomic(dir string, m *snapshotManifest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := manifestPath(dir) + ".next"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := fsyncFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, manifestPath(dir)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return fsyncDir(dir)
}

// removeManifest deletes the manifest so a standalone (non-layered) snapshot in the same
// dir becomes authoritative for a resume. Used when a pause falls back to a Full image:
// the manifest must not keep naming the now-superseded chain. Absent manifest is not an
// error. fsyncs the dir so the removal is durable before the caller relies on it.
func removeManifest(dir string) error {
	if err := os.Remove(manifestPath(dir)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return fsyncDir(dir)
}

// chainPaths resolves the manifest into absolute layer paths for a restore: the
// base, the lower overlays (oldest → newest, all but the last), and the newest
// overlay (the active snapshot path). ok is false when the chain has no overlays.
func (m *snapshotManifest) chainPaths(dir string) (base string, lower []string, newest string, ok bool) {
	if m == nil || len(m.Overlays) == 0 {
		return "", nil, "", false
	}
	abs := make([]string, len(m.Overlays))
	for i, name := range m.Overlays {
		abs[i] = filepath.Join(dir, name)
	}
	return m.Base, abs[:len(abs)-1], abs[len(abs)-1], true
}

// fsyncFile flushes a file's contents to stable storage.
func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// fsyncDir flushes a directory entry (so a rename within it is durable).
func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
