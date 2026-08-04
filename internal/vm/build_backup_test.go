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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// writeBuildFixture lays out a minimal finished build: one artifact plus the
// build.meta.json template-builder writes. Returns the meta bytes as written
// so tests can assert the file was (or was not) rewritten with digests.
func writeBuildFixture(t *testing.T, dir string) []byte {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "mem.snap"), []byte("memory image"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmstate.snap"), []byte("vm state"), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := []byte(`{"snapshot_path":"vmstate.snap","mem_path":"mem.snap","size_bytes":12}`)
	if err := os.WriteFile(filepath.Join(dir, buildMetaFilename), meta, 0o644); err != nil {
		t.Fatal(err)
	}
	return meta
}

// A host without a backup hook installed (BACKUP_BUCKET unset) must not pay
// for hashing at all: no artifact hashing, no digest stamping into
// build.meta.json, no metadata hash. The digest rewrite is the observable:
// whenever the hashing pipeline runs to completion it rewrites the meta file,
// so an untouched file proves the pipeline never started.
func TestBackupBuildArtifactsSkipsAllHashingWhenHookNil(t *testing.T) {
	dir := t.TempDir()
	meta := writeBuildFixture(t, dir)

	m := &Manager{} // no SetBackupEnqueue: backup disabled
	m.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", nil, zerolog.Nop())

	got, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, meta) {
		t.Fatalf("build.meta.json rewritten with backup disabled; hashing pipeline ran:\n%s", got)
	}
}

// Contrast case proving the observable above is sensitive: with a hook
// installed the same fixture gets hashed, build.meta.json gains the
// artifacts field, and the task reaches the enqueue hook.
func TestBackupBuildArtifactsHashesAndEnqueuesWithHook(t *testing.T) {
	dir := t.TempDir()
	writeBuildFixture(t, dir)

	var tasks []backup.Task
	m := &Manager{}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks = append(tasks, task)
		return nil
	})
	m.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", nil, zerolog.Nop())

	if len(tasks) != 1 {
		t.Fatalf("enqueued %d tasks, want 1", len(tasks))
	}
	task := tasks[0]
	if task.TemplateID != "tpl" || task.BuildID != "build-tpl" {
		t.Fatalf("task owner = %q/%q, want tpl/build-tpl", task.TemplateID, task.BuildID)
	}
	names := make(map[string]bool, len(task.Files))
	for _, f := range task.Files {
		names[f.Name] = true
	}
	if !names["mem.snap"] || !names["vmstate.snap"] || !names[buildMetaFilename] {
		t.Fatalf("task files = %v, want mem.snap, vmstate.snap and %s", names, buildMetaFilename)
	}

	raw, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}
	var rewritten struct {
		Artifacts []buildArtifactDigest `json:"artifacts"`
	}
	if err := json.Unmarshal(raw, &rewritten); err != nil {
		t.Fatal(err)
	}
	if len(rewritten.Artifacts) == 0 {
		t.Fatal("build.meta.json not stamped with artifact digests")
	}
}

// A required artifact that is absent before enumeration never reaches the
// hasher, so the hashed set looks internally complete while build.meta.json
// knows better. The declared set is the completeness authority: a missing
// declared artifact must keep the build out of the backup queue.
func TestBackupBuildArtifactsRefusesMissingDeclaredArtifact(t *testing.T) {
	dir := t.TempDir()
	writeBuildFixture(t, dir)
	if err := os.Remove(filepath.Join(dir, "vmstate.snap")); err != nil {
		t.Fatal(err)
	}

	var tasks []backup.Task
	m := &Manager{}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks = append(tasks, task)
		return nil
	})
	m.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", nil, zerolog.Nop())

	if len(tasks) != 0 {
		t.Fatalf("enqueued %d tasks despite a missing declared artifact, want 0", len(tasks))
	}
}

// writeAdoptableBuildFixture lays a completed build out under the templates
// tree the way loadDurableBuild expects: snapshotRoot/templates/<tpl>/<build>/
// with the artifacts and a build.meta.json whose declared paths are absolute
// (adoption stats them). Returns the build dir.
func writeAdoptableBuildFixture(t *testing.T, root, templateID, buildVMID string) string {
	t.Helper()
	dir := filepath.Join(root, TemplatesDirName, templateID, buildVMID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mem.snap"), []byte("memory image"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmstate.snap"), []byte("vm state"), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := fmt.Sprintf(`{"snapshot_path":%q,"mem_path":%q,"size_bytes":12}`,
		filepath.Join(dir, "vmstate.snap"), filepath.Join(dir, "mem.snap"))
	if err := os.WriteFile(filepath.Join(dir, buildMetaFilename), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// waitForTask receives one enqueued task or fails the test.
func waitForTask(t *testing.T, tasks <-chan backup.Task) backup.Task {
	t.Helper()
	select {
	case task := <-tasks:
		return task
	case <-time.After(10 * time.Second):
		t.Fatal("no backup task enqueued for adopted build")
		return backup.Task{}
	}
}

// A vmd exit after template-builder wrote build.meta.json but before the
// backup enqueue leaves a durable build with no journal record and no
// stamped digests. Adopting it via GetBuildStatus must rerun the full
// hashing pipeline and enqueue the set.
func TestAdoptedBuildWithoutStampedDigestsRerunsBackup(t *testing.T) {
	root := t.TempDir()
	dir := writeAdoptableBuildFixture(t, root, "tpl", "build-tpl")

	tasks := make(chan backup.Task, 2)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		tasks <- task
		return nil
	})

	snap, ok := m.GetBuildStatus("build-tpl")
	if !ok || snap.Status != BuildStatusReady {
		t.Fatalf("adoption = %+v ok=%v, want ready", snap, ok)
	}
	task := waitForTask(t, tasks)
	if task.TemplateID != "tpl" || task.BuildID != "build-tpl" {
		t.Fatalf("task owner = %q/%q, want tpl/build-tpl", task.TemplateID, task.BuildID)
	}
	want := sha256.Sum256([]byte("memory image"))
	var got string
	for _, f := range task.Files {
		if f.Name == "mem.snap" {
			got = f.SHA256
		}
	}
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("mem.snap digest = %s, want freshly hashed %s", got, hex.EncodeToString(want[:]))
	}
	// The rerun also stamps the digests, so the next restart takes the
	// cheap recorded-digest path.
	stamped, err := readStampedBuildDigests(dir)
	if err != nil || len(stamped) == 0 {
		t.Fatalf("stamped digests after rerun = %v err=%v", stamped, err)
	}
}

// A build whose digests were already stamped must be re-enqueued from the
// record, not re-hashed: multi-GiB artifacts cannot be re-read on every
// restart. Observable: mutate an artifact after stamping; the enqueued
// digest still matches the stamp, proving no re-hash happened (the uploader
// verifies bytes against the digest later and fails closed on divergence).
func TestAdoptedBuildWithStampedDigestsEnqueuesWithoutRehash(t *testing.T) {
	root := t.TempDir()
	dir := writeAdoptableBuildFixture(t, root, "tpl", "build-tpl")

	// Stamp via the normal completion pipeline.
	stamper := &Manager{}
	stamper.SetBackupEnqueue(func(backup.Task) error { return nil })
	stamper.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", nil, zerolog.Nop())
	stamped, err := readStampedBuildDigests(dir)
	if err != nil || len(stamped) == 0 {
		t.Fatalf("fixture not stamped: %v err=%v", stamped, err)
	}
	var recorded string
	for _, d := range stamped {
		if d.Name == "mem.snap" {
			recorded = d.SHA256
		}
	}
	if recorded == "" {
		t.Fatal("mem.snap missing from stamped digests")
	}

	// Diverge the bytes on disk at the SAME size (the size check guards
	// truncation, not content); a re-hash would notice, the record won't.
	if err := os.WriteFile(filepath.Join(dir, "mem.snap"), []byte("MEMORY IMAGE"), 0o644); err != nil {
		t.Fatal(err)
	}

	tasks := make(chan backup.Task, 2)
	var covered atomic.Bool
	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		covered.Store(true) // journal now holds the generation
		tasks <- task
		return nil
	})
	m.SetBackupCovered(func(backup.Task) (bool, error) { return covered.Load(), nil })
	if snap, ok := m.GetBuildStatus("build-tpl"); !ok || snap.Status != BuildStatusReady {
		t.Fatalf("adoption = %+v ok=%v, want ready", snap, ok)
	}
	task := waitForTask(t, tasks)
	var got string
	for _, f := range task.Files {
		if f.Name == "mem.snap" {
			got = f.SHA256
		}
	}
	if got != recorded {
		t.Fatalf("mem.snap digest = %s, want recorded %s (artifact was re-hashed)", got, recorded)
	}

	// Repeat polls re-run the reconcile but the covered check stops the
	// re-enqueue: nothing new lands on the channel.
	if _, ok := m.GetBuildStatus("build-tpl"); !ok {
		t.Fatal("second adoption lookup failed")
	}
	time.Sleep(100 * time.Millisecond)
	select {
	case extra := <-tasks:
		t.Fatalf("second status poll enqueued another task: %+v", extra)
	default:
	}
}

// Backup disabled: adoption still reports the build ready but touches
// nothing, mirroring the completion path's nil-hook gate.
func TestAdoptedBuildWithoutHookDoesNothing(t *testing.T) {
	root := t.TempDir()
	dir := writeAdoptableBuildFixture(t, root, "tpl", "build-tpl")
	meta, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	snap, ok := m.GetBuildStatus("build-tpl")
	if !ok || snap.Status != BuildStatusReady {
		t.Fatalf("adoption = %+v ok=%v, want ready", snap, ok)
	}
	time.Sleep(50 * time.Millisecond)
	got, err := os.ReadFile(filepath.Join(dir, buildMetaFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, meta) {
		t.Fatalf("build.meta.json rewritten with backup disabled:\n%s", got)
	}
}

// A journal write that fails transiently must not be swallowed: the
// completion path returns without blocking (the retry backoff runs off
// the build path) and the task is re-enqueued from the digests already in
// hand, no rehash. The hook fails once, then succeeds; the delivered task
// must carry the digests stamped during the original hash pass.
func TestBackupBuildArtifactsRetriesFailedEnqueue(t *testing.T) {
	dir := t.TempDir()
	writeBuildFixture(t, dir)

	var calls atomic.Int32
	tasks := make(chan backup.Task, 1)
	m := &Manager{}
	m.SetBackupEnqueue(func(task backup.Task) error {
		if calls.Add(1) == 1 {
			return errors.New("journal unavailable")
		}
		tasks <- task
		return nil
	})

	start := time.Now()
	m.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", nil, zerolog.Nop())
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("build path blocked %v on enqueue retry; retry must be async", elapsed)
	}

	task := waitForTask(t, tasks)
	if calls.Load() < 2 {
		t.Fatalf("hook called %d times, want a retry after the failure", calls.Load())
	}
	if task.TemplateID != "tpl" || task.BuildID != "build-tpl" {
		t.Fatalf("task owner = %q/%q, want tpl/build-tpl", task.TemplateID, task.BuildID)
	}
	// The retried task is rebuilt from the manifest in hand: its digests
	// are exactly the ones stamped into build.meta.json by the original
	// (only) hash pass.
	stamped, err := readStampedBuildDigests(dir)
	if err != nil || len(stamped) == 0 {
		t.Fatalf("stamped digests = %v err=%v", stamped, err)
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
			t.Fatalf("retried digest for %s = %s, want stamped %s", f.Name, f.SHA256, recorded[f.Name])
		}
	}
}

// The sweep must process every match even when the rehash slots are
// held: a non-blocking drop with deterministic glob order would let the
// same early builds consume the slots each pass and starve a later
// build forever. The sweep path blocks for a slot instead.
func TestSweepReconcileWaitsForSlotInsteadOfDropping(t *testing.T) {
	dir := t.TempDir()
	writeAdoptableBuildFixture(t, dir, "tpl", "build-tpl")

	tasks := make(chan backup.Task, 1)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir}}
	m.SetBackupEnqueue(func(task backup.Task) error { tasks <- task; return nil })

	// Occupy every rehash slot, then release them shortly after the
	// sweep starts: a dropping implementation returns without ever
	// enqueueing, a blocking one proceeds once slots free.
	slots := m.ensureRehashSlots()
	held := cap(slots)
	for i := 0; i < held; i++ {
		slots <- struct{}{}
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		for i := 0; i < held; i++ {
			<-slots
		}
	}()

	res, err := readBuildMetaJSON(filepath.Join(dir, TemplatesDirName, "tpl", "build-tpl"))
	if err != nil {
		t.Fatal(err)
	}
	m.reconcileAdoptedBuildBackupMode(BuildStatusSnapshot{
		BuildVMID: "build-tpl", TemplateID: "tpl", Status: BuildStatusReady, Result: res,
	}, true)

	select {
	case task := <-tasks:
		if task.TemplateID != "tpl" {
			t.Fatalf("task owner = %q, want tpl", task.TemplateID)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("blocking sweep reconcile never enqueued after slots freed")
	}
}

// Registering a rebuild cancels an in-flight adoption reconcile for the
// same template+build and waits for it to exit, so stale stamps can
// never land after the new build is admitted.
func TestRegisterBuildCancelsInFlightReconcile(t *testing.T) {
	dir := t.TempDir()
	writeAdoptableBuildFixture(t, dir, "tpl", "build-tpl")

	// A hook that blocks keeps the reconcile in flight until cancelled.
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		entered <- struct{}{}
		<-release
		return nil
	})
	defer close(release)

	res, err := readBuildMetaJSON(filepath.Join(dir, TemplatesDirName, "tpl", "build-tpl"))
	if err != nil {
		t.Fatal(err)
	}
	m.reconcileAdoptedBuildBackupMode(BuildStatusSnapshot{
		BuildVMID: "build-tpl", TemplateID: "tpl", Status: BuildStatusReady, Result: res,
	}, true)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("reconcile never reached the enqueue hook")
	}

	// Registration must cancel the reconcile and return once it exits.
	done := make(chan error, 1)
	go func() {
		_, err := m.registerBuild("build-tpl", "tpl", func() {})
		done <- err
	}()
	// The blocked hook ignores cancellation, so release it shortly
	// after the cancel lands to let the goroutine exit.
	go func() {
		time.Sleep(300 * time.Millisecond)
		release <- struct{}{}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("registerBuild after reconcile exit: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("registerBuild never returned")
	}
}

// In-flight reconcile keys carry the template: two templates reusing one
// build id must not starve each other.
func TestReconcileInFlightKeyIsTemplateScoped(t *testing.T) {
	dir := t.TempDir()
	writeAdoptableBuildFixture(t, dir, "tpl-a", "build-1")
	writeAdoptableBuildFixture(t, dir, "tpl-b", "build-1")

	var mu sync.Mutex
	owners := map[string]bool{}
	m := &Manager{cfg: ManagerConfig{SnapshotDir: dir}}
	m.SetBackupEnqueue(func(task backup.Task) error {
		mu.Lock()
		owners[task.TemplateID] = true
		mu.Unlock()
		return nil
	})

	for _, tpl := range []string{"tpl-a", "tpl-b"} {
		res, err := readBuildMetaJSON(filepath.Join(dir, TemplatesDirName, tpl, "build-1"))
		if err != nil {
			t.Fatal(err)
		}
		m.reconcileAdoptedBuildBackupMode(BuildStatusSnapshot{
			BuildVMID: "build-1", TemplateID: tpl, Status: BuildStatusReady, Result: res,
		}, true)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(owners)
		mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("owners = %v, want both templates enqueued", owners)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
