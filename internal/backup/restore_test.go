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

func (m *memBlobs) Create(_ context.Context, object string, r io.Reader) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.objects[object]; exists {
		return false, nil // create-only dedupe
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return false, err
	}
	m.objects[object] = data
	return true, nil
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
	// The generation is its content address, exactly as the pause hook
	// derives it; restore verifies the manifest reproduces this key.
	task.Generation = GenerationKey(task.Files)
	return task
}

// genObject names an object under the fixture task's generation prefix.
func genObject(task Task, name string) string {
	return "sandboxes/" + task.SandboxID + "/" + task.Generation + "/" + name
}

// uploadFixture ships the task through the real Uploader into the store so
// restore reads exactly what production writes: packed objects plus the
// manifest completion object. The uploader persists per-object
// verification state, so it gets a real journal.
func uploadFixture(t *testing.T, store *memBlobs, task Task) {
	t.Helper()
	j, _ := testJournal(t)
	u := &Uploader{Journal: j, Store: store}
	completed, err := u.uploadTask(context.Background(), &task)
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
		if strings.HasPrefix(name, genObject(task, "overlay.ext4.p")) {
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
	delete(store.objects, genObject(task, ManifestObject))

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

func TestRestoreGenerationRejectsManifestMissingEntries(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)

	// Drop one entry from the stored manifest: the identity fields still
	// match and every remaining artifact verifies, so only recomputing the
	// generation key from the file set catches the incomplete manifest.
	manifestObject := genObject(task, ManifestObject)
	var manifest GenerationManifest
	if err := json.Unmarshal(store.objects[manifestObject], &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Files = manifest.Files[:1]
	mutated, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[manifestObject] = mutated

	_, err = RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"))
	if err == nil || !strings.Contains(err.Error(), "generation key") {
		t.Fatalf("err = %v, want generation key mismatch", err)
	}
}

func TestVerifyFileDetectsDataWrittenIntoDeclaredHole(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	destDir := filepath.Join(t.TempDir(), "restored")
	if _, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir); err != nil {
		t.Fatalf("restore: %v", err)
	}
	var manifest GenerationManifest
	if err := json.Unmarshal(store.objects[genObject(task, ManifestObject)], &manifest); err != nil {
		t.Fatal(err)
	}

	// Bytes landing inside a manifest-declared hole (the fixture overlay is
	// hole from 64KiB to 2MiB): verification must hash what is actually in
	// the file, so this cannot pass as synthetic zeros.
	f, err := os.OpenFile(filepath.Join(destDir, "overlay.ext4"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xEE}, 4096), 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(destDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	verr := verifyFile(context.Background(), root, manifest.Files[0])
	if verr == nil || !strings.Contains(verr.Error(), "sha256 mismatch") {
		t.Fatalf("err = %v, want sha256 mismatch for data written into a declared hole", verr)
	}
	// The untouched file still verifies against the same manifest entry.
	if err := verifyFile(context.Background(), root, manifest.Files[1]); err != nil {
		t.Fatalf("untouched file failed verification: %v", err)
	}
}

func TestOpenRootNoFollowRejectsSymlinkLeaf(t *testing.T) {
	// The leaf being a symlink at open time must be rejected by the open
	// itself (kernel-atomic O_NOFOLLOW on linux; Lstat approximation
	// elsewhere), exactly the swap a raced check would miss.
	parent := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(parent, "leaf")); err != nil {
		t.Fatal(err)
	}
	root, err := openRootNoFollow(parent, "leaf")
	if err == nil {
		root.Close()
		t.Fatal("openRootNoFollow followed a symlink leaf")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink rejection", err)
	}
	// A real directory leaf opens fine and the root is usable.
	if err := os.Mkdir(filepath.Join(parent, "realdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, err = openRootNoFollow(parent, "realdir")
	if err != nil {
		t.Fatalf("open real directory: %v", err)
	}
	defer root.Close()
	f, err := root.OpenFile("probe", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("create through no-follow root: %v", err)
	}
	f.Close()
	if _, err := os.Stat(filepath.Join(parent, "realdir", "probe")); err != nil {
		t.Fatalf("probe file not in the opened directory: %v", err)
	}
}

func TestRestoreRootPinsDirAcrossSwap(t *testing.T) {
	// Once the destination Root is open it tracks the directory itself: a
	// symlink swapped in at the path afterwards must not redirect writes,
	// and anything the swap points at must stay untouched.
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	var manifest GenerationManifest
	if err := json.Unmarshal(store.objects[genObject(task, ManifestObject)], &manifest); err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	destDir := filepath.Join(base, "dest")
	root, err := openFreshDir(destDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	moved := filepath.Join(base, "moved")
	elsewhere := t.TempDir()
	if err := os.Rename(destDir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, destDir); err != nil {
		t.Fatal(err)
	}
	madeFile, err := restoreFile(context.Background(), store, task.SandboxID, task.Generation, manifest.Files[1], root)
	if err != nil || !madeFile {
		t.Fatalf("restoreFile after dir swap: made=%v err=%v", madeFile, err)
	}
	if _, err := os.Stat(filepath.Join(moved, manifest.Files[1].Name)); err != nil {
		t.Fatalf("file not written into the pinned directory: %v", err)
	}
	entries, err := os.ReadDir(elsewhere)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlink target written to: %d entries err=%v", len(entries), err)
	}
}

func TestRestoreGenerationRejectsEntryWithoutObject(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)

	// A manifest entry without its recorded object name cannot be fetched
	// safely: deriving the name from the file name would break the binding
	// between extent table and packing.
	manifestObject := genObject(task, ManifestObject)
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

func TestRestoreGenerationRefusesSymlinkDest(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)

	// destDir itself is a pre-planted symlink: following it would redirect
	// the restore outside the requested path.
	target := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "dest")
	if err := os.Symlink(target, destDir); err != nil {
		t.Fatal(err)
	}
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink refusal", err)
	}
	entries, readErr := os.ReadDir(target)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("symlink target written to: %d entries, err=%v", len(entries), readErr)
	}
}

func TestRestoreFileNeverOpensExistingDest(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	var manifest GenerationManifest
	if err := json.Unmarshal(store.objects[genObject(task, ManifestObject)], &manifest); err != nil {
		t.Fatal(err)
	}

	// A file that appears between the emptiness check and the open (a
	// concurrent restore, or a planted symlink): O_EXCL must refuse it,
	// report the file as not created, and leave it untouched.
	destDir := t.TempDir()
	dest := filepath.Join(destDir, "overlay.ext4")
	if err := os.WriteFile(dest, []byte("someone else's file"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(destDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	madeFile, err := restoreFile(context.Background(), store, task.SandboxID, task.Generation, manifest.Files[0], root)
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

func TestRestoreGenerationRestoresSharedBasePair(t *testing.T) {
	// An overlay generation ships its base image as a bucket-wide shared
	// object; restore must fetch and verify it as part of the consistency
	// pair, since the overlay's holes are meaningless without it.
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base-image.ext4")
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writeRestoreFixture(t, dir)
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	store := newMemBlobs()
	uploadFixture(t, store, task)

	destDir := filepath.Join(t.TempDir(), "restored")
	manifest, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(manifest.Files) != 3 {
		t.Fatalf("manifest files = %d, want overlay+vmstate+base", len(manifest.Files))
	}
	got, err := os.ReadFile(filepath.Join(destDir, "base.ext4"))
	if err != nil {
		t.Fatalf("restored base: %v", err)
	}
	if !bytes.Equal(got, baseData) {
		t.Fatalf("restored base differs from original (%d vs %d bytes)", len(got), len(baseData))
	}
}

func TestRestoreGenerationRejectsMissingSharedBaseEntry(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base-image.ext4")
	baseData := bytes.Repeat([]byte{0x22}, 64<<10)
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writeRestoreFixture(t, dir)
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	store := newMemBlobs()
	uploadFixture(t, store, task)

	// Drop the shared base entry: the generation key still reproduces
	// (base entries are synthesized outside it), so only the
	// consistency-pair check catches the unrestorable manifest.
	manifestObject := genObject(task, ManifestObject)
	var manifest GenerationManifest
	if err := json.Unmarshal(store.objects[manifestObject], &manifest); err != nil {
		t.Fatal(err)
	}
	kept := manifest.Files[:0]
	for _, mf := range manifest.Files {
		if !strings.HasPrefix(mf.Object, "bases/") {
			kept = append(kept, mf)
		}
	}
	manifest.Files = kept
	mutated, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[manifestObject] = mutated

	_, err = RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"))
	if err == nil || !strings.Contains(err.Error(), "consistency pair") {
		t.Fatalf("err = %v, want consistency pair incomplete", err)
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
	if len(generations) != 1 || generations[0] != task.Generation {
		t.Fatalf("generations = %v, want [%s]", generations, task.Generation)
	}
}
