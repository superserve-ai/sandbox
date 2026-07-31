package backup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// memStore records created objects and enforces create-only semantics the
// way the bucket precondition does: second create of a name is a no-op.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	fail    map[string]error
}

func newMemStore() *memStore {
	return &memStore{objects: map[string][]byte{}, fail: map[string]error{}}
}

func (m *memStore) Create(_ context.Context, object string, r io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.fail[object]; ok {
		return err
	}
	if _, exists := m.objects[object]; exists {
		return nil // create-only dedupe, mirrors the 412-as-success path
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.objects[object] = data
	return nil
}

func writeTask(t *testing.T, dir string) Task {
	t.Helper()
	overlay := filepath.Join(dir, "overlay.ext4")
	if err := os.WriteFile(overlay, []byte("diskdata"), 0o644); err != nil {
		t.Fatal(err)
	}
	vmstate := filepath.Join(dir, "vmstate.snap")
	if err := os.WriteFile(vmstate, []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}
	return Task{
		SandboxID:  "sb-1",
		Generation: "gen-abc",
		Priority:   PriorityPause,
		EnqueuedAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
		Files: []TaskFile{
			{Name: "overlay.ext4", Path: overlay, SHA256: "aa", Size: 8},
			{Name: "vmstate.snap", Path: vmstate, SHA256: "bb", Size: 5},
		},
	}
}

func TestUploaderShipsGenerationAndAcks(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	var verified []Task
	u := &Uploader{Journal: j, Store: store, OnVerified: func(task Task) { verified = append(verified, task) }}

	task := writeTask(t, t.TempDir())
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	worked, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute))
	if err != nil || !worked {
		t.Fatalf("drain: worked=%v err=%v", worked, err)
	}

	// Both artifacts plus the manifest object, packed content intact.
	if got := string(store.objects["sandboxes/sb-1/gen-abc/overlay.ext4"]); got != "diskdata" {
		t.Fatalf("overlay object = %q", got)
	}
	if got := string(store.objects["sandboxes/sb-1/gen-abc/vmstate.snap"]); got != "state" {
		t.Fatalf("vmstate object = %q", got)
	}
	var gen GenerationManifest
	if err := json.Unmarshal(store.objects["sandboxes/sb-1/gen-abc/manifest.json"], &gen); err != nil {
		t.Fatalf("manifest object: %v", err)
	}
	if gen.SandboxID != "sb-1" || len(gen.Files) != 2 || gen.Files[0].SHA256 != "aa" {
		t.Fatalf("manifest = %+v", gen)
	}
	if len(verified) != 1 || verified[0].Generation != "gen-abc" {
		t.Fatalf("verified hook = %+v", verified)
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("task not acked: %v", counts)
	}
}

func TestUploaderRetriesOnStoreFailure(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	store.fail["sandboxes/sb-1/gen-abc/vmstate.snap"] = errors.New("transient")
	u := &Uploader{Journal: j, Store: store}

	task := writeTask(t, t.TempDir())
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	now := task.EnqueuedAt.Add(time.Minute)
	if _, err := u.drainOne(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	// Nacked with backoff, manifest never written.
	if _, ok := store.objects["sandboxes/sb-1/gen-abc/manifest.json"]; ok {
		t.Fatal("manifest written despite failed artifact")
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 1 {
		t.Fatalf("task not retained for retry: %v", counts)
	}

	// Clear the fault; after backoff the retry completes and dedupes the
	// already-written overlay object.
	delete(store.fail, "sandboxes/sb-1/gen-abc/vmstate.snap")
	if _, err := u.drainOne(context.Background(), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.objects["sandboxes/sb-1/gen-abc/manifest.json"]; !ok {
		t.Fatal("manifest missing after retry")
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("task not acked after retry: %v", counts)
	}
}

func TestUploaderAbandonsVanishedSource(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	var verified []Task
	u := &Uploader{Journal: j, Store: store, OnVerified: func(task Task) { verified = append(verified, task) }}

	task := writeTask(t, t.TempDir())
	if err := os.Remove(task.Files[0].Path); err != nil {
		t.Fatal(err)
	}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Acked (not retried forever) but never verified: nothing durable landed.
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("abandoned task still pending: %v", counts)
	}
	if len(verified) != 0 {
		t.Fatalf("verification hook fired for abandoned generation: %+v", verified)
	}
	if _, ok := store.objects["sandboxes/sb-1/gen-abc/manifest.json"]; ok {
		t.Fatal("manifest written for abandoned generation")
	}
}
