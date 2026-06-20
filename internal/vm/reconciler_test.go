package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	uuidA = "11111111-1111-1111-1111-111111111111"
	uuidB = "22222222-2222-2222-2222-222222222222"
	uuidC = "33333333-3333-3333-3333-333333333333"
)

// scanSandboxDirs enumerates only UUID-named dirs and merges a sandbox's dirs
// across roots, so template/templates/build-* and stray files are ignored.
func TestScanSandboxDirs_UUIDOnly_MergesRoots(t *testing.T) {
	runDir := t.TempDir()
	snapDir := t.TempDir()

	for _, name := range []string{uuidA, uuidB, templateDirName, TemplatesDirName, "build-xyz"} {
		if err := os.MkdirAll(filepath.Join(runDir, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(runDir, "stray.file"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write stray: %v", err)
	}
	// uuidA also under snapshots (merge), plus a snapshots-only uuidC.
	for _, name := range []string{uuidA, uuidC} {
		if err := os.MkdirAll(filepath.Join(snapDir, name), 0o755); err != nil {
			t.Fatalf("mkdir snap %s: %v", name, err)
		}
	}

	got := scanSandboxDirs(runDir, snapDir)

	if len(got) != 3 {
		t.Fatalf("want 3 sandbox dirs, got %d: %v", len(got), keysOf(got))
	}
	for _, id := range []string{uuidA, uuidB, uuidC} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s", id)
		}
	}
	if n := len(got[uuidA].paths); n != 2 {
		t.Errorf("uuidA should span both roots (2 paths), got %d", n)
	}
	for _, reserved := range []string{templateDirName, TemplatesDirName, "build-xyz", "stray.file"} {
		if _, ok := got[reserved]; ok {
			t.Errorf("reserved/non-uuid entry %q was enumerated", reserved)
		}
	}
}

// selectOrphanDirs keeps live and grace-window sandboxes, drops orphans, and
// ignores dirs newer than the pass snapshot.
func TestSelectOrphanDirs(t *testing.T) {
	cutoff := time.Unix(1_000_000, 0)
	old := cutoff.Add(-time.Hour)
	fresh := cutoff.Add(time.Hour)

	onDisk := map[string]sandboxDirInfo{
		uuidA: {mtime: old},   // not in keep, older than cutoff → orphan
		uuidB: {mtime: old},   // in keep → kept
		uuidC: {mtime: fresh}, // not in keep but within grace (in-flight create) → kept
	}
	keep := map[string]struct{}{uuidB: {}}

	got := selectOrphanDirs(onDisk, keep, cutoff)
	if len(got) != 1 || got[0] != uuidA {
		t.Fatalf("want [%s], got %v", uuidA, got)
	}
}

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b"), make([]byte, 23), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dirSize(context.Background(), []string{dir}); got != 123 {
		t.Errorf("dirSize = %d, want 123", got)
	}
}

// liveKeepSet keeps every status except failures that settled before the
// cutoff; recently-failed rows stay (grace) so an in-flight cleanup isn't raced.
func TestLiveKeepSet_ExcludesSettledFailed(t *testing.T) {
	cutoff := time.Unix(1_000_000, 0)
	row := func(s db.SandboxStatus, updated time.Time) db.ListSandboxesByHostRow {
		return db.ListSandboxesByHostRow{Sandbox: db.Sandbox{Status: s, UpdatedAt: updated}}
	}
	rows := map[string]db.ListSandboxesByHostRow{
		"active":     row(db.SandboxStatusActive, cutoff.Add(-time.Hour)),
		"paused":     row(db.SandboxStatusPaused, cutoff.Add(-time.Hour)),
		"failed-old": row(db.SandboxStatusFailed, cutoff.Add(-time.Hour)), // settled → reclaimable
		"failed-new": row(db.SandboxStatusFailed, cutoff.Add(time.Hour)),  // within grace → kept
	}

	keep := liveKeepSet(rows, cutoff)

	for _, id := range []string{"active", "paused", "failed-new"} {
		if _, ok := keep[id]; !ok {
			t.Errorf("%s should be in keep-set", id)
		}
	}
	if _, ok := keep["failed-old"]; ok {
		t.Error("settled-failed sandbox should be excluded from keep-set")
	}
}

func keysOf(m map[string]sandboxDirInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
