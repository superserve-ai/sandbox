package backup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTemplatePublicationRequiresEveryRuntimeArtifact(t *testing.T) {
	r := TemplateRuntime{RootfsPath: "/build/base.ext4", BasePath: "/build/base.ext4", SnapshotPath: "/build/vmstate.snap", MemPath: "/build/mem.snap", DeltaPath: "/build/rootfs.delta"}
	var files []PublicationFile
	for _, name := range []string{"base.ext4", "vmstate.snap", "mem.snap", "rootfs.delta", "build.meta.json"} {
		files = append(files, PublicationFile{Name: name, RuntimePath: "/build/" + name, SHA256: strings.Repeat("a", 64), SizeBytes: 100})
	}
	if err := ValidateTemplatePublication(r, files); err != nil {
		t.Fatal(err)
	}
	for i := range files {
		missing := append(append([]PublicationFile{}, files[:i]...), files[i+1:]...)
		if err := ValidateTemplatePublication(r, missing); err == nil {
			t.Fatalf("accepted missing %s", files[i].Name)
		}
	}
	files[0].SHA256 = strings.Repeat("0", 64)
	if err := ValidateTemplatePublication(r, files); err == nil {
		t.Fatal("placeholder digest accepted")
	}
}
func TestTemplatePublicationOutboxRetainsPathsAcrossProducerRestart(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	task := writeTask(t, t.TempDir())
	task.TemplateID = "example-template"
	task.BuildID = "build-example"
	task.SandboxID = ""
	task.BuildIncarnation = "example-incarnation"
	task.Files[0].BasePath = ""
	for _, name := range []string{"mem.bin", "build.meta.json"} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		task.Files = append(task.Files, TaskFile{Name: name, Path: path, SHA256: digestOf([]byte(name)), Size: int64(len(name))})
	}
	for i := range task.Files {
		task.Files[i].RuntimePath = task.Files[i].Path
		task.Files[i].AllocatedBytes = int64(i+1) * 4096
	}
	task.TemplateRuntime = &TemplateRuntime{RootfsPath: task.Files[0].RuntimePath, SnapshotPath: task.Files[1].RuntimePath, MemPath: task.Files[2].RuntimePath}
	task.Generation = GenerationKey(task.Files)
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	calls := 0
	u := &Uploader{Journal: j, Store: store, OnVerified: func(Task) error { calls++; return errors.New("control plane unavailable") }}
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if calls == 0 {
		t.Fatal("verified generation not outboxed")
	}
	// A new uploader instance reconciles solely from the persistent journal.
	var reported Task
	restarted := &Uploader{Journal: j, Store: store, OnVerified: func(task Task) error { reported = task; return nil }}
	restarted.flushNotifications()
	if reported.TemplateRuntime == nil || reported.TemplateRuntime.RootfsPath != task.Files[0].RuntimePath || reported.BuildIncarnation != task.BuildIncarnation {
		t.Fatalf("lost runtime ownership: %+v", reported)
	}
	if !reported.FilesFinal || reported.Files[0].RuntimePath != task.Files[0].RuntimePath || reported.Files[0].SHA256 != task.Files[0].SHA256 {
		t.Fatal("outbox lost integrity/path mapping")
	}
	manifest, _ := TemplateObject(task.TemplateID, task.BuildID, task.Generation, ManifestObject)
	var decoded GenerationManifest
	if err := json.Unmarshal(store.objects[manifest], &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.TemplateRuntime == nil || decoded.Files[0].RuntimePath != task.Files[0].RuntimePath || decoded.Files[0].AllocatedBytes != reported.Files[0].AllocatedBytes {
		t.Fatal("durable manifest lost runtime mapping")
	}
	_, recovered, _, err := FindTemplatePublication(context.Background(), templateReconcileStore{object: manifest, data: string(store.objects[manifest])}, task.TemplateID, task.BuildID)
	if err != nil || len(recovered) != len(reported.Files) {
		t.Fatalf("recover publication: %d files, %v", len(recovered), err)
	}
	for i := range recovered {
		if reported.Files[i].AllocatedBytes != task.Files[i].AllocatedBytes || recovered[i].AllocatedBytes != reported.Files[i].AllocatedBytes {
			t.Fatalf("artifact %s: source allocation %d, reported %d, recovered %d", recovered[i].Name, task.Files[i].AllocatedBytes, reported.Files[i].AllocatedBytes, recovered[i].AllocatedBytes)
		}
	}
}

func TestInterruptedTemplateUploadCannotNotifyReady(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	task := writeTask(t, t.TempDir())
	task.TemplateID = "example-template"
	task.BuildID = "build-interrupted"
	task.SandboxID = ""
	task.TemplateRuntime = &TemplateRuntime{RootfsPath: "/runtime/rootfs", SnapshotPath: "/runtime/snapshot", MemPath: "/runtime/memory"}
	object, _ := TemplateObject(task.TemplateID, task.BuildID, task.Generation, task.Files[1].Name)
	// Packing adds the fingerprint to the plain object name.
	object = object[:len(object)-len(task.Files[1].Name)] + packedName(t, task.Files[1].Path, task.Files[1].Name)
	store.fail[object] = errors.New("storage temporarily unavailable")
	notifications := 0
	u := &Uploader{Journal: j, Store: store, OnVerified: func(Task) error { notifications++; return nil }}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if store.creates[object] != 1 {
		t.Fatal("upload interruption not injected")
	}
	if notifications != 0 {
		t.Fatal("partial upload reported verified")
	}
	manifest, _ := TemplateObject(task.TemplateID, task.BuildID, task.Generation, ManifestObject)
	if _, exists := store.objects[manifest]; exists {
		t.Fatal("partial generation has a completion manifest")
	}
	delete(store.fail, object)
	if _, err := u.drainOne(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if notifications != 1 {
		t.Fatalf("recovery notifications=%d", notifications)
	}
}
