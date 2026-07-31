package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
	m.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", zerolog.Nop())

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
	m.SetBackupEnqueue(func(task backup.Task) { tasks = append(tasks, task) })
	m.backupBuildArtifacts(context.Background(), "tpl", "build-tpl", dir, "", zerolog.Nop())

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
	if !names["mem.snap"] || !names[buildMetaFilename] {
		t.Fatalf("task files = %v, want mem.snap and %s", names, buildMetaFilename)
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
