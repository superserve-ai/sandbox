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
)

// memBlobs is a map-backed store implementing both sides of the pipeline:
// BlobStore for the uploader (create-only) and BlobReader plus BlobLister
// for restore. It is deliberately separate from uploader_test.go's fixture
// so the round-trip tests own their whole world.
type memBlobs struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemBlobs() *memBlobs {
	return &memBlobs{objects: map[string][]byte{}}
}

func (m *memBlobs) Create(_ context.Context, object string, r io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.objects[object]; exists {
		return nil // create-only dedupe
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.objects[object] = data
	return nil
}

func (m *memBlobs) NewReader(_ context.Context, object string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[object]
	if !ok {
		return nil, fmt.Errorf("%s: %w", object, ErrObjectNotFound)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *memBlobs) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for name := range m.objects {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
}

// writeRestoreFixture builds the source artifacts: a genuinely sparse disk
// overlay (data runs separated by holes, trailing hole via Truncate) and a
// small dense vmstate. Digests are of the full apparent content, matching
// what the pause manifest records.
func writeRestoreFixture(t *testing.T, dir string) Task {
	t.Helper()
	overlay := filepath.Join(dir, "overlay.ext4")
	f, err := os.Create(overlay)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xAA}, 64<<10), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xBB}, 32<<10), 2<<20); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(4 << 20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	vmstate := filepath.Join(dir, "vmstate.snap")
	if err := os.WriteFile(vmstate, []byte("register file and device state"), 0o644); err != nil {
		t.Fatal(err)
	}
	task := Task{
		SandboxID:  "sb-restore",
		Generation: "gen-r1",
		Priority:   PriorityPause,
		EnqueuedAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
	}
	for _, name := range []string{"overlay.ext4", "vmstate.snap"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) // full apparent content, holes as zeros
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		task.Files = append(task.Files, TaskFile{
			Name: name, Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
		})
	}
	return task
}

// uploadFixture ships the task through the real Uploader into the store so
// restore reads exactly what production writes: packed objects plus the
// manifest completion object.
func uploadFixture(t *testing.T, store *memBlobs, task Task) {
	t.Helper()
	u := &Uploader{Store: store}
	completed, err := u.uploadTask(context.Background(), task)
	if err != nil || !completed {
		t.Fatalf("upload fixture: completed=%v err=%v", completed, err)
	}
}

func TestRestoreGenerationRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	task := writeRestoreFixture(t, srcDir)
	store := newMemBlobs()
	uploadFixture(t, store, task)

	destDir := filepath.Join(t.TempDir(), "restored")
	manifest, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if manifest.SandboxID != task.SandboxID || manifest.Generation != task.Generation {
		t.Fatalf("manifest identity = %s/%s", manifest.SandboxID, manifest.Generation)
	}
	if len(manifest.Files) != len(task.Files) {
		t.Fatalf("manifest files = %d, want %d", len(manifest.Files), len(task.Files))
	}
	for i, tf := range task.Files {
		orig, err := os.ReadFile(tf.Path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(destDir, tf.Name))
		if err != nil {
			t.Fatalf("restored %s: %v", tf.Name, err)
		}
		if !bytes.Equal(orig, got) {
			t.Fatalf("restored %s differs from original (%d vs %d bytes)", tf.Name, len(got), len(orig))
		}
		if manifest.Files[i].SHA256 != tf.SHA256 {
			t.Fatalf("digest for %s = %s, want %s", tf.Name, manifest.Files[i].SHA256, tf.SHA256)
		}
	}
}

func TestRestoreGenerationFailsOnCorruptObject(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)

	// Flip one byte inside the packed overlay object: the rebuilt file's
	// apparent digest can no longer match the manifest. The object name
	// embeds the packing fingerprint, so find it by its stem.
	var object string
	for name := range store.objects {
		if strings.HasPrefix(name, "sandboxes/sb-restore/gen-r1/overlay.ext4.p") {
			object = name
		}
	}
	if object == "" {
		t.Fatal("packed overlay object not found in store")
	}
	corrupted := bytes.Clone(store.objects[object])
	corrupted[10] ^= 0xFF
	store.objects[object] = corrupted

	destDir := filepath.Join(t.TempDir(), "restored")
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir)
	if err == nil {
		t.Fatal("restore of corrupted object succeeded")
	}
	if !strings.Contains(err.Error(), "overlay.ext4") || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("error does not name the corrupt file and cause: %v", err)
	}
	// All-or-nothing: nothing half-verified is left behind.
	entries, readErr := os.ReadDir(destDir)
	if readErr == nil && len(entries) != 0 {
		t.Fatalf("failed restore left %d files in dest", len(entries))
	}
}

func TestRestoreGenerationMissingManifestIsIncomplete(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	// Artifacts present, manifest gone: exactly what an interrupted upload
	// leaves behind.
	delete(store.objects, "sandboxes/sb-restore/gen-r1/manifest.json")

	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"))
	if !errors.Is(err, ErrGenerationIncomplete) {
		t.Fatalf("err = %v, want ErrGenerationIncomplete", err)
	}
}

func TestRestoreGenerationRejectsMisplacedManifest(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)

	// Copy the whole generation under another sandbox's prefix, the way a
	// bucket-side mistake would: every digest still verifies, so only the
	// manifest's recorded identity can catch the misplacement.
	for name, data := range store.objects {
		store.objects[strings.Replace(name, "sb-restore", "sb-victim", 1)] = data
	}
	_, err := RestoreGeneration(context.Background(), store, "sb-victim", task.Generation, filepath.Join(t.TempDir(), "restored"))
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("err = %v, want manifest identity mismatch", err)
	}
}

func TestRestoreGenerationRejectsEntryWithoutObject(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)

	// A manifest entry without its recorded object name cannot be fetched
	// safely: deriving the name from the file name would break the binding
	// between extent table and packing.
	manifestObject := "sandboxes/sb-restore/gen-r1/manifest.json"
	var manifest GenerationManifest
	if err := json.Unmarshal(store.objects[manifestObject], &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Files[0].Object = ""
	mutated, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[manifestObject] = mutated

	_, err = RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"))
	if err == nil || !strings.Contains(err.Error(), "no object name") {
		t.Fatalf("err = %v, want rejection of entry without object name", err)
	}
}

func TestRestoreGenerationRefusesPopulatedDest(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)

	// A reused recovery directory holding a name-colliding file: restore
	// must refuse rather than truncate it (or delete it during cleanup).
	destDir := t.TempDir()
	existing := filepath.Join(destDir, "overlay.ext4")
	if err := os.WriteFile(existing, []byte("operator's earlier restore"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("err = %v, want refusal of non-empty dest", err)
	}
	got, readErr := os.ReadFile(existing)
	if readErr != nil || string(got) != "operator's earlier restore" {
		t.Fatalf("pre-existing file disturbed: %q err=%v", got, readErr)
	}
}

func TestRestoreFileNeverOpensExistingDest(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	var manifest GenerationManifest
	if err := json.Unmarshal(store.objects["sandboxes/sb-restore/gen-r1/manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}

	// A file that appears between the emptiness check and the open (a
	// concurrent restore, or a planted symlink): O_EXCL must refuse it,
	// report the file as not created, and leave it untouched.
	dest := filepath.Join(t.TempDir(), "overlay.ext4")
	if err := os.WriteFile(dest, []byte("someone else's file"), 0o644); err != nil {
		t.Fatal(err)
	}
	madeFile, err := restoreFile(context.Background(), store, task.SandboxID, task.Generation, manifest.Files[0], dest)
	if err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v, want ErrExist", err)
	}
	if madeFile {
		t.Fatal("restoreFile claims to have created a pre-existing file")
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "someone else's file" {
		t.Fatalf("pre-existing file disturbed: %q err=%v", got, err)
	}
}

func TestHashApparentHonorsCancellationMidExtent(t *testing.T) {
	// A dense file is a single extent; cancellation must interrupt hashing
	// inside it, not only at hole boundaries.
	path := filepath.Join(t.TempDir(), "dense")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xCC}, 4<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hashApparent(ctx, f, []Extent{{Offset: 0, Length: 4 << 20}}, 4<<20); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestListGenerationsReportsOnlyComplete(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	// A second, incomplete generation: artifact object but no manifest.
	store.objects["sandboxes/sb-restore/gen-r2/overlay.ext4"] = []byte("partial")
	// Another sandbox entirely.
	store.objects["sandboxes/sb-other/gen-x/manifest.json"] = []byte("{}")

	generations, err := ListGenerations(context.Background(), store, "sb-restore")
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 1 || generations[0] != "gen-r1" {
		t.Fatalf("generations = %v, want [gen-r1]", generations)
	}
}
