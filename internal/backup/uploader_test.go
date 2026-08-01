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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
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
	fake := now
	u.Now = func() time.Time { return fake }
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
	fake = now.Add(time.Hour)
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
	if err := j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(verifiedBucket)
		for i := 0; i < 200; i++ {
			if err := b.Put([]byte(fmt.Sprintf("sandboxes/sb/gen/obj-%03d", i)),
				[]byte(fmt.Sprintf("%d", old.UnixNano()))); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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

// Cancellation must land inside a dense extent, not only between
// extents: the shutdown join waits on this hash, and a single large
// extent would otherwise be read to completion after cancel.
func TestHashApparentCancelsMidExtent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dense.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = hashApparent(ctx, f, []Extent{{Offset: 0, Length: 1 << 20}}, 1<<20)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled from inside the extent read", err)
	}
}

// A canceled context must stop the drain loop before it touches the
// backlog: each canceled upload nacks successfully (worked, nil), so
// without a per-iteration check the whole queue gets drained and nacked
// before the idle select ever sees the cancellation.
func TestRunStopsPromptlyWhenCanceled(t *testing.T) {
	j, _ := testJournal(t)
	for _, id := range []string{"sb-1", "sb-2"} {
		if err := j.Enqueue(Task{SandboxID: id, Generation: "gen", EnqueuedAt: time.Unix(1, 0)}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u := &Uploader{Journal: j, Store: newMemStore()}
	if err := u.Run(ctx); err != nil {
		t.Fatal(err)
	}
	task, ok, err := j.Next(time.Unix(2, 0))
	if err != nil || !ok {
		t.Fatalf("backlog should be untouched: ok=%v err=%v", ok, err)
	}
	if task.Attempts != 0 {
		t.Fatalf("task attempts = %d, want 0 (nothing drained after cancel)", task.Attempts)
	}
}

// A destroy racing a queued upload unlinks the original artifacts; the
// staged hard links must carry the upload to completion anyway, and the
// ack must clear the staging directory.
func TestStagedUploadSurvivesSourceDeletion(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, "staging")
	data := []byte("artifact bytes that outlive the sandbox")
	orig := filepath.Join(src, "rootfs.ext4")
	if err := os.WriteFile(orig, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	task := Task{
		SandboxID:  "sb",
		Generation: "gen",
		EnqueuedAt: time.Unix(1, 0),
		Files:      []TaskFile{{Name: "rootfs.ext4", Path: orig, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}},
	}
	if err := StageTask(staging, &task); err != nil {
		t.Fatal(err)
	}
	if task.Files[0].Path == orig {
		t.Fatal("staging did not rewrite the task path")
	}

	j, _ := testJournal(t)
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	// The teardown race: originals gone before the drain.
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}

	store := newMemStore()
	u := &Uploader{Journal: j, Store: store, StagingRoot: staging}
	worked, err := u.drainOne(context.Background(), time.Unix(2, 0))
	if err != nil || !worked {
		t.Fatalf("drainOne = %v/%v", worked, err)
	}
	if len(store.objects) == 0 {
		t.Fatal("nothing uploaded from the staged links")
	}
	if _, err := os.Stat(filepath.Join(staging, "sb", "gen")); !os.IsNotExist(err) {
		t.Fatalf("staged generation not cleaned after ack: %v", err)
	}
}

// The startup sweep removes staged residue with no journal task and
// keeps generations that are still queued.
func TestSweepStagingKeepsOnlyPending(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	for _, g := range []string{"sb1/gen-pending", "sb2/gen-orphan"} {
		if err := os.MkdirAll(filepath.Join(staging, g), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staging, g, "rootfs.ext4"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	j, _ := testJournal(t)
	if err := j.Enqueue(Task{SandboxID: "sb1", Generation: "gen-pending", EnqueuedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}

	SweepStaging(staging, j, zerolog.Nop())

	if _, err := os.Stat(filepath.Join(staging, "sb1", "gen-pending")); err != nil {
		t.Fatalf("pending generation swept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(staging, "sb2")); !os.IsNotExist(err) {
		t.Fatalf("orphan generation kept: %v", err)
	}
}

// Backoff must count from the failure, not the drain start: a drain that
// began long ago but fails now schedules its retry in the real future.
func TestNackBackoffCountsFromFailureTime(t *testing.T) {
	j, _ := testJournal(t)
	store := newMemStore()
	u := &Uploader{Journal: j, Store: store}

	task := writeTask(t, t.TempDir())
	store.fail["sandboxes/sb-1/gen-abc/"+packedName(t, task.Files[1].Path, "vmstate.snap")] = errors.New("transient")
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	// Drain "started" at the ancient enqueue time; the failure happens at
	// failTime. The retry must be scheduled after failTime, so the task
	// is NOT runnable immediately after the failure.
	failTime := task.EnqueuedAt.Add(48 * time.Hour)
	u.Now = func() time.Time { return failTime }
	if _, err := u.drainOne(context.Background(), task.EnqueuedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := j.Next(failTime); err != nil || ok {
		t.Fatalf("task runnable immediately after a late failure (ok=%v err=%v)", ok, err)
	}
	if _, ok, err := j.Next(failTime.Add(time.Hour)); err != nil || !ok {
		t.Fatalf("task not runnable after backoff elapsed (ok=%v err=%v)", ok, err)
	}
}

// A deferred high-priority task must not hide runnable lower-priority
// work, and finding it must not require scanning the deferred backlog:
// readiness-ordered keys let Next seek straight to the next priority.
func TestNextSkipsDeferredPriorityWithoutScanning(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	pause := Task{SandboxID: "sb-a", Generation: "g1", EnqueuedAt: base, Priority: PriorityPause}
	if err := j.Enqueue(pause); err != nil {
		t.Fatal(err)
	}
	if err := j.Nack(pause, base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ckpt := Task{SandboxID: "sb-b", Generation: "g2", EnqueuedAt: base, Priority: PriorityCheckpoint}
	if err := j.Enqueue(ckpt); err != nil {
		t.Fatal(err)
	}

	// Nack at +60s with attempt-1 backoff (2s) defers until +62s.
	got, ok, err := j.Next(base.Add(61 * time.Second))
	if err != nil || !ok {
		t.Fatalf("Next = %v/%v", ok, err)
	}
	if got.SandboxID != "sb-b" {
		t.Fatalf("Next = %s, want the runnable checkpoint task", got.SandboxID)
	}
	// After the pause task's backoff elapses it outranks the checkpoint.
	got, ok, err = j.Next(base.Add(time.Hour))
	if err != nil || !ok || got.SandboxID != "sb-a" {
		t.Fatalf("Next after backoff = %+v/%v/%v, want the pause task", got, ok, err)
	}
	// The nack re-keyed the row; ack through the same task state must
	// clear it (index and queue agree on the new key).
	nacked := got
	if err := j.Ack(nacked, false); err != nil {
		t.Fatal(err)
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("nacked task not acked cleanly: %v", counts)
	}
}

// The staged snapshot must be immutable: a resume writing through the
// original inode after staging must not change what uploads. A hard
// link would fail this test; a copy or reflink passes.
func TestStagedBytesImmuneToSourceMutation(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	data := []byte("pause-time artifact bytes")
	orig := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(orig, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	task := Task{
		SandboxID:  "sb",
		Generation: "gen",
		EnqueuedAt: time.Unix(1, 0),
		Files:      []TaskFile{{Name: "rootfs.ext4", Path: orig, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}},
	}
	if err := StageTask(staging, &task); err != nil {
		t.Fatal(err)
	}

	// The resume race: guest writes land through the original name.
	if err := os.WriteFile(orig, []byte("post-resume guest writes!!"), 0o644); err != nil {
		t.Fatal(err)
	}

	j, _ := testJournal(t)
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	store := newMemStore()
	u := &Uploader{Journal: j, Store: store, StagingRoot: staging}
	if _, err := u.drainOne(context.Background(), time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.objects["sandboxes/sb/gen/manifest.json"]; !ok {
		t.Fatal("upload did not complete from the staged snapshot (mutation leaked through)")
	}
}

// An overlay generation must ship its base bytes: the bucket is the only
// copy that survives host loss, and the base uploads as one bucket-wide
// content-addressed object that a second sandbox on the same base
// dedupes against instead of re-uploading.
func TestOverlayGenerationUploadsSharedBase(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.ext4")
	baseData := []byte("base image bytes shared by the template")
	if err := os.WriteFile(base, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	baseSum := sha256.Sum256(baseData)
	baseSHA := hex.EncodeToString(baseSum[:])

	makeTask := func(id string) Task {
		data := []byte("overlay bytes for " + id)
		p := filepath.Join(dir, id+".overlay")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		return Task{
			SandboxID:  id,
			Generation: "gen-" + id,
			EnqueuedAt: time.Unix(1, 0),
			Files: []TaskFile{{
				Name: "rootfs.ext4", Path: p,
				SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
				BasePath: base, BaseSHA256: baseSHA,
			}},
		}
	}

	j, _ := testJournal(t)
	store := newMemStore()
	u := &Uploader{Journal: j, Store: store}
	for _, id := range []string{"sb-x", "sb-y"} {
		if err := j.Enqueue(makeTask(id)); err != nil {
			t.Fatal(err)
		}
		if _, err := u.drainOne(context.Background(), time.Unix(2, 0)); err != nil {
			t.Fatal(err)
		}
	}

	var baseObjects, manifests int
	for name := range store.objects {
		if strings.HasPrefix(name, "bases/"+baseSHA+".p") {
			baseObjects++
		}
		if strings.HasSuffix(name, "/manifest.json") {
			manifests++
		}
	}
	if baseObjects != 1 {
		t.Fatalf("base objects = %d, want exactly one shared upload", baseObjects)
	}
	if manifests != 2 {
		t.Fatalf("manifests = %d, want both generations complete", manifests)
	}
	// Both manifests reference the shared base object by full path.
	var gen GenerationManifest
	if err := json.Unmarshal(store.objects["sandboxes/sb-y/gen-sb-y/manifest.json"], &gen); err != nil {
		t.Fatal(err)
	}
	foundBase := false
	for _, f := range gen.Files {
		if f.Name == "base.ext4" && strings.HasPrefix(f.Object, "bases/"+baseSHA) {
			foundBase = true
		}
	}
	if !foundBase {
		t.Fatalf("manifest lacks the shared base entry: %+v", gen.Files)
	}
}

// A base rebuilt since the pause abandons the generation exactly like
// any mutated source: its recorded digest no longer matches the bytes.
func TestRebuiltBaseAbandonsGeneration(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(base, []byte("original base"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("original base"))
	overlay := filepath.Join(dir, "rootfs.ext4")
	odata := []byte("overlay bytes")
	if err := os.WriteFile(overlay, odata, 0o644); err != nil {
		t.Fatal(err)
	}
	osum := sha256.Sum256(odata)
	task := Task{
		SandboxID: "sb", Generation: "gen", EnqueuedAt: time.Unix(1, 0),
		Files: []TaskFile{{
			Name: "rootfs.ext4", Path: overlay,
			SHA256: hex.EncodeToString(osum[:]), Size: int64(len(odata)),
			BasePath: base, BaseSHA256: hex.EncodeToString(sum[:]),
		}},
	}
	if err := os.WriteFile(base, []byte("REBUILT base!"), 0o644); err != nil {
		t.Fatal(err)
	}

	j, _ := testJournal(t)
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	store := newMemStore()
	u := &Uploader{Journal: j, Store: store}
	if _, err := u.drainOne(context.Background(), time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.objects["sandboxes/sb/gen/manifest.json"]; ok {
		t.Fatal("manifest published over a rebuilt base")
	}
	if counts, _ := j.Pending(); counts[PriorityPause] != 0 {
		t.Fatalf("abandoned generation not acked: %v", counts)
	}
}

// A second HOST (fresh journal, no verification history) deduping
// against a shared base object another host uploaded must complete its
// generation: shared-object trust is structural (content-addressed
// name), not host-local history.
func TestSharedBaseDedupeAcrossHosts(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.ext4")
	baseData := []byte("base bytes uploaded by host one")
	if err := os.WriteFile(base, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	baseSum := sha256.Sum256(baseData)
	baseSHA := hex.EncodeToString(baseSum[:])

	overlay := filepath.Join(dir, "rootfs.ext4")
	odata := []byte("host two overlay")
	if err := os.WriteFile(overlay, odata, 0o644); err != nil {
		t.Fatal(err)
	}
	osum := sha256.Sum256(odata)
	task := Task{
		SandboxID: "sb-host2", Generation: "gen", EnqueuedAt: time.Unix(1, 0),
		Files: []TaskFile{{
			Name: "rootfs.ext4", Path: overlay,
			SHA256: hex.EncodeToString(osum[:]), Size: int64(len(odata)),
			BasePath: base, BaseSHA256: baseSHA,
		}},
	}

	// The store already holds the base object (host one uploaded it);
	// host two's journal is fresh.
	store := newMemStore()
	bf, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	extents, apparent, err := Extents(bf)
	bf.Close()
	if err != nil {
		t.Fatal(err)
	}
	store.objects[SharedBaseObject(baseSHA, PackFingerprint(extents, apparent))] = baseData

	j, _ := testJournal(t)
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	u := &Uploader{Journal: j, Store: store}
	if _, err := u.drainOne(context.Background(), time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.objects["sandboxes/sb-host2/gen/manifest.json"]; !ok {
		t.Fatal("cross-host base dedupe abandoned the generation")
	}
}

// The staged base must carry the upload when template GC deletes the
// original: one snapshot per base content serves every generation.
func TestStagedBaseSurvivesTemplateGC(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	base := filepath.Join(dir, "base.ext4")
	baseData := []byte("template base bytes")
	if err := os.WriteFile(base, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	baseSum := sha256.Sum256(baseData)
	overlay := filepath.Join(dir, "rootfs.ext4")
	odata := []byte("overlay bytes")
	if err := os.WriteFile(overlay, odata, 0o644); err != nil {
		t.Fatal(err)
	}
	osum := sha256.Sum256(odata)
	task := Task{
		SandboxID: "sb", Generation: "gen", EnqueuedAt: time.Unix(1, 0),
		Files: []TaskFile{{
			Name: "rootfs.ext4", Path: overlay,
			SHA256: hex.EncodeToString(osum[:]), Size: int64(len(odata)),
			BasePath: base, BaseSHA256: hex.EncodeToString(baseSum[:]),
		}},
	}
	if err := StageTask(staging, &task); err != nil {
		t.Fatal(err)
	}
	if task.Files[0].BasePath == base {
		t.Fatal("base path not staged")
	}
	// Template GC deletes the original base and the sandbox artifacts.
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(overlay); err != nil {
		t.Fatal(err)
	}

	j, _ := testJournal(t)
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	store := newMemStore()
	u := &Uploader{Journal: j, Store: store, StagingRoot: staging}
	if _, err := u.drainOne(context.Background(), time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.objects["sandboxes/sb/gen/manifest.json"]; !ok {
		t.Fatal("generation abandoned despite staged base")
	}

	// The sweep keeps a base referenced by pending work and clears it
	// once nothing references it.
	if err := j.Enqueue(Task{SandboxID: "sb2", Generation: "g2", EnqueuedAt: time.Unix(3, 0),
		Files: []TaskFile{{Name: "rootfs.ext4", Path: "/gone", SHA256: "x", BaseSHA256: hex.EncodeToString(baseSum[:])}}}); err != nil {
		t.Fatal(err)
	}
	SweepStaging(staging, j, zerolog.Nop())
	if _, err := os.Stat(filepath.Join(staging, "bases", hex.EncodeToString(baseSum[:]))); err != nil {
		t.Fatalf("referenced staged base swept: %v", err)
	}
	if err := j.Ack(Task{SandboxID: "sb2", Generation: "g2", EnqueuedAt: time.Unix(3, 0)}, false); err != nil {
		t.Fatal(err)
	}
	SweepStaging(staging, j, zerolog.Nop())
	if _, err := os.Stat(filepath.Join(staging, "bases", hex.EncodeToString(baseSum[:]))); !os.IsNotExist(err) {
		t.Fatalf("unreferenced staged base kept: %v", err)
	}
}

// A deduped re-enqueue upgrades the queued task's paths (mutable
// originals to staged snapshots) while keeping the row's scheduling.
func TestEnqueueDedupeUpgradesPaths(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	orig := Task{SandboxID: "sb", Generation: "gen", EnqueuedAt: base,
		Files: []TaskFile{{Name: "rootfs.ext4", Path: "/live/rootfs.ext4", SHA256: "aa"}}}
	if err := j.Enqueue(orig); err != nil {
		t.Fatal(err)
	}
	staged := orig
	staged.Staged = true
	staged.Files = []TaskFile{{Name: "rootfs.ext4", Path: "/staging/sb/gen/rootfs.ext4", SHA256: "aa"}}
	if err := j.Enqueue(staged); err != nil {
		t.Fatal(err)
	}
	got, ok, err := j.Next(base.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("Next = %v/%v", ok, err)
	}
	if got.Files[0].Path != "/staging/sb/gen/rootfs.ext4" || !got.Staged {
		t.Fatalf("queued task = %+v, want the staged upgrade", got)
	}
	// The upgrade is one-way: a later mutable-path enqueue of the same
	// generation must not downgrade the staged row.
	if err := j.Enqueue(orig); err != nil {
		t.Fatal(err)
	}
	got, ok, err = j.Next(base.Add(time.Minute))
	if err != nil || !ok || got.Files[0].Path != "/staging/sb/gen/rootfs.ext4" {
		t.Fatalf("staged row downgraded: %+v", got)
	}
}

// Clone-only staging on a filesystem without reflink support degrades
// cleanly: nothing staged, original paths untouched, no error.
func TestStageTaskCloneFallsBackWithoutReflink(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(orig, []byte("bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	task := Task{SandboxID: "sb", Generation: "gen",
		Files: []TaskFile{{Name: "rootfs.ext4", Path: orig, SHA256: "aa"}}}
	all, err := StageTaskClone(filepath.Join(dir, "staging"), &task)
	if err != nil {
		t.Fatalf("clone-only staging errored: %v", err)
	}
	// This test tree may or may not sit on a reflink filesystem; either
	// every file staged or none did, and unstaged files keep originals.
	if !all && task.Files[0].Path != orig {
		t.Fatalf("unstaged file path rewritten to %s", task.Files[0].Path)
	}
	if all && task.Files[0].Path == orig {
		t.Fatal("allStaged reported but path not rewritten")
	}
}
