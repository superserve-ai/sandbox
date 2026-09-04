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

	// A retry of an id still in flight is refused by the registry before the
	// directory is touched: the running build's files survive.
	inflight := filepath.Join(dir, TemplatesDirName, "tpl", "build-4")
	if err := os.MkdirAll(inflight, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inflight, "mem.snap"), []byte("half written"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.builds = map[string]*buildRecord{}
	if _, err := m.registerBuild("build-4", "tpl", 1, 512, func() {}, func() error { return m.prepareBuildDir("tpl", "build-4") }); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(inflight, "mem.snap")); !os.IsNotExist(err) {
		t.Fatal("unpublished leftovers survived the registration that claimed the id")
	}
	// The running build recreates its directory and writes into it.
	if err := os.MkdirAll(inflight, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inflight, "mem.snap"), []byte("half written"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.registerBuild("build-4", "tpl", 1, 512, func() {}, func() error { return m.prepareBuildDir("tpl", "build-4") }); err == nil {
		t.Fatal("a retry of an id in flight was accepted")
	}
	if _, err := os.Stat(filepath.Join(inflight, "mem.snap")); err != nil {
		t.Fatal("the retry removed the running build's files")
	}
}
