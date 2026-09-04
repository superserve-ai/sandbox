package vm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A build never lands on a published template: a caller that names one is
// refused, a caller that names nothing gets a fresh id every time, and the
// leftovers of an unpublished build are cleared before the new one starts.
func TestBuildsNeverOverwriteAPublishedTemplate(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{log: zerolog.Nop(), cfg: ManagerConfig{SnapshotDir: dir}}

	if a, b := defaultBuildVMID("tpl"), defaultBuildVMID("tpl"); a == b {
		t.Fatalf("default build ids collide: %q", a)
	}

	published := filepath.Join(dir, TemplatesDirName, "tpl", "build-1")
	if err := os.MkdirAll(published, 0o755); err != nil {
		t.Fatal(err)
	}
	seedFrozenManifest(t, filepath.Join(published, "mem.snap"), "tok")
	if err := os.WriteFile(filepath.Join(published, buildMetaFilename), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.prepareBuildDir("tpl", "build-1"); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("build onto a published template: err=%v, want AlreadyExists", err)
	}
	if _, err := os.Stat(WallClockMarkerPath(filepath.Join(published, "mem.snap"))); err != nil {
		t.Fatal("the published template was touched")
	}

	// Unpublished leftovers: a crashed build's snapshot and manifest must not
	// survive beside the new build's.
	stale := filepath.Join(dir, TemplatesDirName, "tpl", "build-2")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	seedFrozenManifest(t, filepath.Join(stale, "mem.snap"), "tok")
	if err := m.prepareBuildDir("tpl", "build-2"); err != nil {
		t.Fatalf("build over unpublished leftovers: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("unpublished leftovers were kept")
	}

	if err := m.prepareBuildDir("tpl", "build-3"); err != nil {
		t.Fatalf("fresh build: %v", err)
	}
}
