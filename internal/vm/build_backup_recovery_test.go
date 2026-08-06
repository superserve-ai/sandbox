package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// adoptedSnapshot builds the BuildStatusSnapshot the sweep would hand to
// the reconcile flow for a fixture directory.
func adoptedSnapshot(t *testing.T, dir, templateID, buildVMID string) BuildStatusSnapshot {
	t.Helper()
	res, err := readBuildMetaJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	return BuildStatusSnapshot{
		BuildVMID:  buildVMID,
		TemplateID: templateID,
		Status:     BuildStatusReady,
		Result:     res,
	}
}

// A reconcile worker racing a rebuild that reuses the same build id (the
// default id is build-<templateID>) must not stamp stale digests over the
// new build's meta or enqueue the old artifact set: the guard sees the
// non-terminal registration and drops the work silently.
func TestReconcileDropsWhenRebuildActive(t *testing.T) {
	root := t.TempDir()
	dir := writeAdoptableBuildFixture(t, root, "tpl", "build-tpl")
	meta, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks <- task
		return nil
	})
	// A new build for the same id is in flight.
	if _, err := m.registerBuild("build-tpl", "tpl", nil); err != nil {
		t.Fatal(err)
	}

	m.reconcileAdoptedBuildBackup(adoptedSnapshot(t, dir, "tpl", "build-tpl"))
	time.Sleep(300 * time.Millisecond)
	select {
	case task := <-tasks:
		t.Fatalf("reconcile enqueued despite an active rebuild: %+v", task)
	default:
	}
	got, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, meta) {
		t.Fatalf("reconcile stamped digests under an active rebuild:\n%s", got)
	}
}

// The reconcile guard pins build.meta.json by stat identity; a rewrite
// (what a completing rebuild does) must change that identity.
func TestBuildMetaRewriteChangesIdentity(t *testing.T) {
	dir := t.TempDir()
	writeBuildFixture(t, dir)
	metaPath := filepath.Join(dir, buildMetaFilename)
	before, err := baseIdentity(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBuildDigests(dir, []ManifestEntry{{FileName: "mem.snap", SHA256: "aa", SizeBytes: 1}}); err != nil {
		t.Fatal(err)
	}
	after, err := baseIdentity(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("meta rewrite kept the same stat identity; the reconcile pin cannot see rebuilds")
	}
}

// Stamped digests whose size no longer matches the disk are provably
// stale (truncation, corruption): the reconcile must fall through to the
// full re-hash and enqueue fresh digests instead of shipping a stamp the
// uploader would abandon forever.
func TestReconcileRehashesOnStampSizeDivergence(t *testing.T) {
	root := t.TempDir()
	dir := writeAdoptableBuildFixture(t, root, "tpl", "build-tpl")

	stamper := &Manager{}
	stamper.SetBackupEnqueue(func(backup.Task) error { return nil })
	stamper.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", nil, zerolog.Nop())

	// Truncate: different size than the stamp recorded.
	truncated := []byte("short")
	if err := os.WriteFile(filepath.Join(dir, "mem.snap"), truncated, 0o644); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks <- task
		return nil
	})
	m.reconcileAdoptedBuildBackup(adoptedSnapshot(t, dir, "tpl", "build-tpl"))
	task := waitForTask(t, tasks)
	want := sha256.Sum256(truncated)
	var got string
	for _, f := range task.Files {
		if f.Name == "mem.snap" {
			got = f.SHA256
		}
	}
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("mem.snap digest = %s, want fresh %s (stale stamp shipped)", got, hex.EncodeToString(want[:]))
	}
}

// The sweep recovers a completed build whose enqueue never reached the
// journal (retries exhausted or the process died mid-retry): the stamped
// meta is the durable retry state, and the sweep rebuilds the exact task
// from it.
func TestTemplateSweepRecoversUnjournaledBuild(t *testing.T) {
	root := t.TempDir()
	dir := writeAdoptableBuildFixture(t, root, "tpl", "build-tpl")

	// Completion-time enqueue failed for good: stamps exist, no journal.
	stamper := &Manager{}
	stamper.SetBackupEnqueue(func(backup.Task) error { return errors.New("journal down") })
	stamper.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", nil, zerolog.Nop())
	stamped, err := readStampedBuildDigests(dir)
	if err != nil || len(stamped) == 0 {
		t.Fatalf("fixture not stamped: %v err=%v", stamped, err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks <- task
		return nil
	})
	m.runTemplateBackupSweep(zerolog.Nop())
	task := waitForTask(t, tasks)
	if task.TemplateID != "tpl" || task.BuildID != "build-tpl" {
		t.Fatalf("task owner = %q/%q, want tpl/build-tpl", task.TemplateID, task.BuildID)
	}
	recorded := make(map[string]string, len(stamped))
	for _, d := range stamped {
		recorded[d.Name] = d.SHA256
	}
	for _, f := range task.Files {
		if f.Name == buildMetaFilename {
			continue
		}
		if recorded[f.Name] != f.SHA256 {
			t.Fatalf("swept digest for %s = %s, want stamped %s", f.Name, f.SHA256, recorded[f.Name])
		}
	}
}

// A build whose generation is already covered (pending or completed in
// the journal) is skipped by the sweep: no re-enqueue and no re-stamp.
func TestTemplateSweepSkipsCoveredBuild(t *testing.T) {
	root := t.TempDir()
	dir := writeAdoptableBuildFixture(t, root, "tpl", "build-tpl")

	stamper := &Manager{}
	stamper.SetBackupEnqueue(func(backup.Task) error { return nil })
	stamper.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", nil, zerolog.Nop())
	meta, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 1)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks <- task
		return nil
	})
	m.SetBackupCovered(func(backup.Task) (bool, error) { return true, nil })
	m.runTemplateBackupSweep(zerolog.Nop())
	time.Sleep(300 * time.Millisecond)
	select {
	case task := <-tasks:
		t.Fatalf("sweep re-enqueued a covered generation: %+v", task)
	default:
	}
	got, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, meta) {
		t.Fatal("sweep re-stamped a covered build (re-hash happened)")
	}
}

// Adopted-build hashing shares the pause recovery's bounded slots: with
// every slot busy the reconcile is skipped (the sweep retries later), and
// it proceeds once a slot frees.
func TestReconcileHonorsRehashSlots(t *testing.T) {
	root := t.TempDir()
	dir := writeAdoptableBuildFixture(t, root, "tpl", "build-tpl")

	tasks := make(chan backup.Task, 1)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks <- task
		return nil
	})
	slots := m.ensureRehashSlots()
	for i := 0; i < cap(slots); i++ {
		slots <- struct{}{}
	}
	m.reconcileAdoptedBuildBackup(adoptedSnapshot(t, dir, "tpl", "build-tpl"))
	time.Sleep(200 * time.Millisecond)
	select {
	case task := <-tasks:
		t.Fatalf("reconcile ran with all rehash slots busy: %+v", task)
	default:
	}
	for i := 0; i < cap(slots); i++ {
		<-slots
	}
	m.reconcileAdoptedBuildBackup(adoptedSnapshot(t, dir, "tpl", "build-tpl"))
	waitForTask(t, tasks)
}

// Overlay-mode end to end: the base image lives outside the snapshot dir
// (extraPaths), the declared-set check accepts the set, and the reconcile
// cheap path resolves the base back to its run-dir location.
func TestBackupBuildArtifactsOverlayFixture(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, TemplatesDirName, "tpl", "build-tpl")
	runDir := filepath.Join(root, "run")
	for _, d := range []string{dir, runDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(dir, "vmstate.snap"): "vm state",
		filepath.Join(dir, "mem.snap"):     "memory image",
		filepath.Join(dir, "rootfs.delta"): "delta bytes",
		filepath.Join(runDir, "base.ext4"): "base image bytes",
	}
	for p, content := range files {
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	meta := fmt.Sprintf(`{"snapshot_path":%q,"mem_path":%q,"base_path":%q,"delta_path":%q,"size_bytes":1}`,
		filepath.Join(dir, "vmstate.snap"), filepath.Join(dir, "mem.snap"),
		filepath.Join(runDir, "base.ext4"), filepath.Join(dir, "rootfs.delta"))
	if err := os.WriteFile(filepath.Join(dir, buildMetaFilename), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 2)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks <- task
		return nil
	})
	m.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, filepath.Join(runDir, "base.ext4"), nil, zerolog.Nop())
	task := waitForTask(t, tasks)
	var basePath string
	for _, f := range task.Files {
		if f.Name == "base.ext4" {
			basePath = f.Path
			if f.BaseSHA256 != "" || f.BasePath != "" {
				t.Fatalf("template base carries a base dependency: %+v", f)
			}
		}
	}
	if basePath != filepath.Join(runDir, "base.ext4") {
		t.Fatalf("base path = %q, want the run-dir base", basePath)
	}

	// Reconcile cheap path on a fresh manager: base.ext4 is not in the
	// snapshot dir, so the stamped entry must resolve through the
	// declared base path.
	m2 := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m2.SetBackupEnqueue(func(task backup.Task) error {
		tasks <- task
		return nil
	})
	m2.reconcileAdoptedBuildBackup(adoptedSnapshot(t, dir, "tpl", "build-tpl"))
	task2 := waitForTask(t, tasks)
	basePath = ""
	for _, f := range task2.Files {
		if f.Name == "base.ext4" {
			basePath = f.Path
		}
	}
	if basePath != filepath.Join(runDir, "base.ext4") {
		t.Fatalf("reconciled base path = %q, want the run-dir base", basePath)
	}
}

// writeBuildDigests edits the document as raw JSON: every field
// template-builder wrote survives, including ones vmd does not model.
func TestWriteBuildDigestsPreservesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	meta := []byte(`{"snapshot_path":"vmstate.snap","mem_path":"mem.snap","size_bytes":12,"builder_extra":"keepme"}`)
	if err := os.WriteFile(filepath.Join(dir, buildMetaFilename), meta, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeBuildDigests(dir, []ManifestEntry{{FileName: "mem.snap", SHA256: "aa", SizeBytes: 1}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if string(out["builder_extra"]) != `"keepme"` {
		t.Fatalf("unknown field lost across the digest stamp: %s", raw)
	}
	if _, ok := out["artifacts"]; !ok {
		t.Fatal("artifacts field not stamped")
	}
	// No temp residue left behind by the atomic replace.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range entries {
		if de.Name() != buildMetaFilename {
			t.Fatalf("unexpected residue in snapshot dir: %s", de.Name())
		}
	}
}

// Crash residue and reserved names never enter the artifact set: a torn
// writeBuildDigests temp would be renamed away (dangling task path), and
// a file named like the bucket's manifest object would collide with the
// generation's completion marker.
func TestCollectBuildManifestSkipsResidueAndReservedNames(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"mem.snap":                "memory image",
		"build.meta.json.123.tmp": "torn residue",
		backup.ManifestObject:     "squatter",
		buildMetaFilename:         `{"mem_path":"mem.snap"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, complete := collectBuildManifest(context.Background(), dir, nil, zerolog.Nop())
	if !complete {
		t.Fatal("skipping residue must not mark the set incomplete")
	}
	if len(entries) != 1 || entries[0].FileName != "mem.snap" {
		t.Fatalf("entries = %+v, want only mem.snap", entries)
	}
}

// Two different files sharing a basename cannot silently collapse into
// one artifact: object names are basenames, so the set is ambiguous and
// must fail closed.
func TestCollectBuildManifestFlagsBasenameCollision(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "base.ext4"), []byte("copy in dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "base.ext4"), []byte("different file"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, complete := collectBuildManifest(context.Background(), dir, []string{filepath.Join(other, "base.ext4")}, zerolog.Nop())
	if complete {
		t.Fatal("conflicting basenames must flip complete to false")
	}
	// The same path via extraPaths is the intentional dedupe, not a
	// collision.
	_, complete = collectBuildManifest(context.Background(), dir, []string{filepath.Join(dir, "base.ext4")}, zerolog.Nop())
	if !complete {
		t.Fatal("deduping the same path must stay complete")
	}
}
