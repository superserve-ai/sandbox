package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
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

func (m *memStore) Create(_ context.Context, object string, r io.Reader) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.fail[object]; ok {
		return false, err
	}
	if _, exists := m.objects[object]; exists {
		// Dedupe consumes the stream anyway, mirroring the small-object
		// case where the writer buffers everything before the 412: stream
		// consumption must prove nothing about what is stored.
		_, _ = io.Copy(io.Discard, r)
		return false, nil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return false, err
	}
	m.objects[object] = data
	return true, nil
}

// packedName is the fingerprint-suffixed object name uploadFile derives.
func packedName(t *testing.T, path, name string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	extents, apparent, err := Extents(f)
	if err != nil {
		t.Fatal(err)
	}
	return name + ".p" + PackFingerprint(extents, apparent)
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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
			{Name: "overlay.ext4", Path: overlay, SHA256: digestOf([]byte("diskdata")), Size: 8, BasePath: "/snapshots/templates/tpl/build/base.ext4"},
			{Name: "vmstate.snap", Path: vmstate, SHA256: digestOf([]byte("state")), Size: 5},
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
	overlayObj := "sandboxes/sb-1/gen-abc/" + packedName(t, task.Files[0].Path, "overlay.ext4")
	vmstateObj := "sandboxes/sb-1/gen-abc/" + packedName(t, task.Files[1].Path, "vmstate.snap")
	if got := string(store.objects[overlayObj]); got != "diskdata" {
		t.Fatalf("overlay object = %q", got)
	}
	if got := string(store.objects[vmstateObj]); got != "state" {
		t.Fatalf("vmstate object = %q", got)
	}
	var gen GenerationManifest
	if err := json.Unmarshal(store.objects["sandboxes/sb-1/gen-abc/manifest.json"], &gen); err != nil {
		t.Fatalf("manifest object: %v", err)
	}
	if gen.SandboxID != "sb-1" || len(gen.Files) != 2 || gen.Files[0].SHA256 != digestOf([]byte("diskdata")) {
		t.Fatalf("manifest = %+v", gen)
	}
	if gen.Files[0].Object != packedName(t, task.Files[0].Path, "overlay.ext4") {
		t.Fatalf("manifest object binding = %q", gen.Files[0].Object)
	}
	if gen.Files[0].BasePath != "/snapshots/templates/tpl/build/base.ext4" {
		t.Fatalf("overlay base dependency dropped from manifest: %+v", gen.Files[0])
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
	u := &Uploader{Journal: j, Store: store}

	task := writeTask(t, t.TempDir())
	store.fail["sandboxes/sb-1/gen-abc/"+packedName(t, task.Files[1].Path, "vmstate.snap")] = errors.New("transient")
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
	delete(store.fail, "sandboxes/sb-1/gen-abc/"+packedName(t, task.Files[1].Path, "vmstate.snap"))
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

func TestUploaderAbandonsMutatedSource(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	var verified []Task
	u := &Uploader{Journal: j, Store: store, OnVerified: func(task Task) { verified = append(verified, task) }}

	task := writeTask(t, t.TempDir())
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	// The sandbox resumed and dirtied the disk before the drain: content no
	// longer matches the pause-time digest.
	if err := os.WriteFile(task.Files[0].Path, []byte("MUTATED!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(store.objects) != 0 {
		t.Fatalf("objects shipped for mutated source: %v", keysOf(store.objects))
	}
	if len(verified) != 0 {
		t.Fatal("verification hook fired for mutated source")
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("mutated task still pending: %v", counts)
	}
}

func TestJournalSelfHealsCorruptEntries(t *testing.T) {
	j, _ := testJournal(t)
	task := Task{SandboxID: "sb", Generation: "good", Priority: PriorityPause,
		EnqueuedAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	// Plant a corrupt entry that sorts FIRST so it would wedge a naive scan.
	if err := j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(journalBucket).Put([]byte("0/0000000000000000000/corrupt"), []byte("{not json"))
	}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := j.Next(task.EnqueuedAt.Add(time.Minute))
	if err != nil || !ok || got.Generation != "good" {
		t.Fatalf("next past corrupt entry: ok=%v gen=%q err=%v", ok, got.Generation, err)
	}
	// The corrupt entry was dropped, not left to rot.
	counts, err := j.Pending()
	if err != nil || counts[PriorityPause] != 1 {
		t.Fatalf("pending after self-heal = %v err=%v", counts, err)
	}
}

func TestJournalEnqueueDedupesPendingGeneration(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	first := Task{SandboxID: "sb", Generation: "gen", Priority: PriorityPause, EnqueuedAt: base}
	dup := Task{SandboxID: "sb", Generation: "gen", Priority: PriorityPause, EnqueuedAt: base.Add(time.Minute)}
	if err := j.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	if err := j.Enqueue(dup); err != nil {
		t.Fatal(err)
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 1 {
		t.Fatalf("duplicate generation enqueued twice: %v", counts)
	}
}

func keysOf(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// midStreamMutator reads half of an object's stream, invokes the hook (the
// test mutates the source file there), then reads the rest: the shape of a
// sandbox resuming while the bandwidth-capped upload is in flight.
type midStreamMutator struct {
	*memStore
	target string
	hook   func()
	fired  bool
}

func (m *midStreamMutator) Create(ctx context.Context, object string, r io.Reader) (bool, error) {
	if object != m.target || m.fired {
		return m.memStore.Create(ctx, object, r)
	}
	m.fired = true
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, 4); err != nil {
		return false, err
	}
	m.hook()
	if _, err := io.Copy(&buf, r); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[object] = buf.Bytes()
	return true, nil
}

func TestUploaderWithholdsManifestOnMidStreamMutation(t *testing.T) {
	j, _ := testJournal(t)
	task := writeTask(t, t.TempDir())
	store := &midStreamMutator{
		memStore: newMemStore(),
		target:   "sandboxes/sb-1/gen-abc/" + packedName(t, task.Files[0].Path, "overlay.ext4"),
		hook: func() {
			// Mutate AFTER the pre-check passed and mid-upload: the second
			// half of the stream ships different bytes.
			if err := os.WriteFile(task.Files[0].Path, []byte("diskMUTA"), 0o644); err != nil {
				t.Error(err)
			}
		},
	}
	var verified []Task
	u := &Uploader{Journal: j, Store: store, OnVerified: func(task Task) { verified = append(verified, task) }}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The artifact object may exist (inert orphan), but the completion
	// marker must not, the hook must not fire, and the task is done.
	if _, ok := store.objects["sandboxes/sb-1/gen-abc/manifest.json"]; ok {
		t.Fatal("manifest written despite mid-stream mutation")
	}
	if len(verified) != 0 {
		t.Fatal("verification hook fired despite mid-stream mutation")
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("task still pending: %v", counts)
	}
}

func TestUploaderAbandonsTruncatedSource(t *testing.T) {
	j, _ := testJournal(t)
	task := writeTask(t, t.TempDir())
	store := &midStreamMutator{
		memStore: newMemStore(),
		target:   "sandboxes/sb-1/gen-abc/" + packedName(t, task.Files[0].Path, "overlay.ext4"),
		hook: func() {
			// A newer pause rewrote the file smaller mid-stream.
			if err := os.Truncate(task.Files[0].Path, 2); err != nil {
				t.Error(err)
			}
		},
	}
	u := &Uploader{Journal: j, Store: store}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.objects["sandboxes/sb-1/gen-abc/manifest.json"]; ok {
		t.Fatal("manifest written despite truncated source")
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("truncated task still pending: %v", counts)
	}
}

func TestJournalStaleIndexHeals(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	task := Task{SandboxID: "sb", Generation: "gen", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	// Simulate a corrupt-entry drop that removed the queue row but left
	// the index entry behind: re-enqueue must heal, not stay blocked.
	if err := j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(journalBucket).Delete(task.key())
	}); err != nil {
		t.Fatal(err)
	}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 1 {
		t.Fatalf("stale index blocked re-enqueue: %v", counts)
	}
}

func TestUploaderAbandonsUnverifiedDedupedObject(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	task := writeTask(t, t.TempDir())
	// Residue of a crash between finalize and verification: the object
	// exists (with bytes nothing can vouch for; simulate corruption), but
	// this task's journal entry records no verification of it.
	overlayObj := "sandboxes/sb-1/gen-abc/" + packedName(t, task.Files[0].Path, "overlay.ext4")
	store.objects[overlayObj] = []byte("CORRUPT!")
	var verified []Task
	u := &Uploader{Journal: j, Store: store, OnVerified: func(task Task) { verified = append(verified, task) }}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.objects["sandboxes/sb-1/gen-abc/manifest.json"]; ok {
		t.Fatal("manifest published over an unverified deduped object")
	}
	if len(verified) != 0 {
		t.Fatal("verification hook fired")
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("task still pending: %v", counts)
	}
}

func TestUploaderTrustsHistoryForUnchangedRepause(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	var verified []Task
	u := &Uploader{Journal: j, Store: store, OnVerified: func(task Task) { verified = append(verified, task) }}

	// First pause: full upload, verified, acked.
	task := writeTask(t, t.TempDir())
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(verified) != 1 {
		t.Fatalf("first pause not verified: %+v", verified)
	}

	// Unchanged re-pause: same content, same generation, fresh task after
	// the original was acked. Every object dedupes; the durable history
	// must let it complete instead of abandoning it as crash residue.
	repause := task
	repause.EnqueuedAt = task.EnqueuedAt.Add(time.Hour)
	repause.VerifiedObjects = nil
	if err := j.Enqueue(repause); err != nil {
		t.Fatal(err)
	}
	if _, err := u.drainOne(context.Background(), repause.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(verified) != 2 {
		t.Fatalf("unchanged re-pause abandoned instead of completing: %+v", verified)
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("re-pause task still pending: %v", counts)
	}
}

func TestJournalSameContentSandboxesDoNotCollide(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	// Two untouched clones of one template: identical content-addressed
	// generation, identical enqueue tick. Both backups must survive.
	a := Task{SandboxID: "sb-a", Generation: "samegen", Priority: PriorityPause, EnqueuedAt: base}
	b := Task{SandboxID: "sb-b", Generation: "samegen", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(a); err != nil {
		t.Fatal(err)
	}
	if err := j.Enqueue(b); err != nil {
		t.Fatal(err)
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 2 {
		t.Fatalf("same-tick same-content enqueues collided: %v", counts)
	}
}

func TestJournalPruneSweepsHistoryAcrossAcks(t *testing.T) {
	j, _ := testJournal(t)
	old := time.Now().Add(-30 * 24 * time.Hour)
	for i := 0; i < 200; i++ {
		if err := j.MarkVerified(fmt.Sprintf("sandboxes/sb/gen/obj-%03d", i), old); err != nil {
			t.Fatal(err)
		}
	}
	// Each ack examines a bounded slice; successive acks sweep the rest.
	task := Task{SandboxID: "sb", Generation: "g", Priority: PriorityPause,
		EnqueuedAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)}
	for i := 0; i < 5; i++ {
		if err := j.Ack(task, false); err != nil {
			t.Fatal(err)
		}
	}
	remaining := 0
	if err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(verifiedBucket).ForEach(func(k, _ []byte) error {
			if string(k) != string(pruneCursorKey) {
				remaining++
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("expired history not fully swept: %d entries remain", remaining)
	}
}

// A crash between the ack transaction and the OnVerified callback must
// not lose the completion signal: the outbox entry written inside the
// ack is redelivered by the next process's startup flush.
func TestVerifiedNotificationSurvivesCrashBeforeDelivery(t *testing.T) {
	j, _ := testJournal(t)
	task := Task{SandboxID: "sb", Generation: "gen", EnqueuedAt: time.Unix(1, 0)}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	// Simulate the first process: ack with notification owed, then crash
	// before any delivery (no flush runs).
	if err := j.Ack(task, true); err != nil {
		t.Fatal(err)
	}

	var delivered []Task
	u := &Uploader{Journal: j, OnVerified: func(t Task) { delivered = append(delivered, t) }}
	u.flushNotifications()
	if len(delivered) != 1 || delivered[0].SandboxID != "sb" || delivered[0].Generation != "gen" {
		t.Fatalf("delivered = %+v, want the acked task once", delivered)
	}
	// Confirmed delivery is not repeated.
	u.flushNotifications()
	if len(delivered) != 1 {
		t.Fatalf("redelivered after confirmation: %+v", delivered)
	}
}

// An abandoned task acks without a notification: nothing was made
// durable, so no completion signal may ever fire, before or after a
// restart.
func TestAbandonedAckLeavesNoNotification(t *testing.T) {
	j, _ := testJournal(t)
	task := Task{SandboxID: "sb", Generation: "gen", EnqueuedAt: time.Unix(1, 0)}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	if err := j.Ack(task, false); err != nil {
		t.Fatal(err)
	}
	pending, err := j.PendingNotifications()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("outbox = %+v, want empty", pending)
	}
}

// A verification write that never reached disk must not ride into the
// Nack inside the task's VerifiedObjects: the retry would then trust a
// dedupe against durable history that does not exist.
func TestFailedVerificationWriteNotCarriedIntoTask(t *testing.T) {
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "backup.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("artifact bytes")
	path := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	task := Task{
		SandboxID:  "sb",
		Generation: "gen",
		EnqueuedAt: time.Unix(1, 0),
		Files:      []TaskFile{{Name: "rootfs.ext4", Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}},
	}

	// Force the durable verification write to fail after the object
	// itself uploads and verifies cleanly.
	db.Close()

	u := &Uploader{Journal: j, Store: newMemStore()}
	_, err = u.uploadFile(context.Background(), &task, task.Files[0])
	if err == nil {
		t.Fatal("uploadFile succeeded despite a failed verification write")
	}
	if len(task.VerifiedObjects) != 0 {
		t.Fatalf("task carries unverified trust %v after failed verification write", task.VerifiedObjects)
	}
}
