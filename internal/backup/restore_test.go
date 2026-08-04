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
	"io/fs"
	"math"
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
	created map[string]time.Time
	clock   time.Time
}

func newMemBlobs() *memBlobs {
	return &memBlobs{
		objects: map[string][]byte{},
		created: map[string]time.Time{},
		clock:   time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
	}
}

func (m *memBlobs) Identity() string { return "test-bucket" }

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
	m.clock = m.clock.Add(time.Minute)
	m.created[object] = m.clock
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

func (m *memBlobs) List(_ context.Context, prefix string) ([]ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var objects []ObjectInfo
	for name := range m.objects {
		if strings.HasPrefix(name, prefix) {
			objects = append(objects, ObjectInfo{Name: name, Created: m.created[name]})
		}
	}
	return objects, nil
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
	manifest, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
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
	// The completion marker is written last and is the completeness
	// authority: it must exist, parse, and record this generation. The
	// destination holds exactly the manifest's files plus the marker.
	markerData, err := os.ReadFile(filepath.Join(destDir, ManifestObject))
	if err != nil {
		t.Fatalf("completion marker: %v", err)
	}
	var marker GenerationManifest
	if err := json.Unmarshal(markerData, &marker); err != nil {
		t.Fatalf("completion marker parse: %v", err)
	}
	if marker.SandboxID != task.SandboxID || marker.Generation != task.Generation {
		t.Fatalf("marker identity = %s/%s", marker.SandboxID, marker.Generation)
	}
	entries, err := os.ReadDir(destDir)
	if err != nil || len(entries) != len(task.Files)+1 {
		t.Fatalf("dest entries = %d err=%v, want files plus marker", len(entries), err)
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
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
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

	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
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
	_, err := RestoreGeneration(context.Background(), store, "sb-victim", task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
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

	_, err = RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
	if err == nil || !strings.Contains(err.Error(), "generation key") {
		t.Fatalf("err = %v, want generation key mismatch", err)
	}
}

func TestVerifyFileDetectsDataWrittenIntoDeclaredHole(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	destDir := filepath.Join(t.TempDir(), "restored")
	if _, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil); err != nil {
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

	_, err = RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
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
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
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
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
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
	manifest, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(manifest.Files) != 3 {
		t.Fatalf("manifest files = %d, want overlay+vmstate+base", len(manifest.Files))
	}
	got, err := os.ReadFile(filepath.Join(destDir, SharedBaseName(digestOf(baseData))))
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

	_, err = RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
	if err == nil || !strings.Contains(err.Error(), "consistency pair") {
		t.Fatalf("err = %v, want consistency pair incomplete", err)
	}
}

func TestListGenerationsReportsOnlyCompleteNewestFirst(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	// A second, incomplete generation: artifact object but no manifest.
	store.objects["sandboxes/sb-restore/gen-r2/overlay.ext4"] = []byte("partial")
	// Another sandbox entirely.
	store.objects["sandboxes/sb-other/gen-x/manifest.json"] = []byte("{}")
	// An older and a newer complete generation: an operator under DR
	// pressure needs the newest first, with its manifest creation time.
	older := store.created[genObject(task, ManifestObject)].Add(-time.Hour)
	newer := older.Add(2 * time.Hour)
	store.objects["sandboxes/sb-restore/gen-older/manifest.json"] = []byte("{}")
	store.created["sandboxes/sb-restore/gen-older/manifest.json"] = older
	store.objects["sandboxes/sb-restore/gen-newer/manifest.json"] = []byte("{}")
	store.created["sandboxes/sb-restore/gen-newer/manifest.json"] = newer

	generations, err := ListGenerations(context.Background(), store, "sb-restore")
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 3 {
		t.Fatalf("generations = %+v, want 3 complete", generations)
	}
	if generations[0].Generation != "gen-newer" || generations[1].Generation != task.Generation || generations[2].Generation != "gen-older" {
		t.Fatalf("order = %+v, want newest first", generations)
	}
	if !generations[0].Created.Equal(newer) {
		t.Fatalf("created = %v, want manifest object creation time %v", generations[0].Created, newer)
	}
}

// rewriteManifest parses the stored manifest, applies mutate, and stores
// it back: the tamper primitive for manifest-integrity tests.
func rewriteManifest(t *testing.T, store *memBlobs, task Task, mutate func(*GenerationManifest)) {
	t.Helper()
	obj := genObject(task, ManifestObject)
	var manifest GenerationManifest
	if err := json.Unmarshal(store.objects[obj], &manifest); err != nil {
		t.Fatal(err)
	}
	mutate(&manifest)
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[obj] = data
}

// baseFixture writes a base image, binds the fixture overlay to it, and
// returns the uploaded task plus the base bytes.
func baseFixture(t *testing.T, fill byte) (Task, *memBlobs, []byte) {
	t.Helper()
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base-image.ext4")
	baseData := bytes.Repeat([]byte{fill}, 64<<10)
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writeRestoreFixture(t, dir)
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	store := newMemBlobs()
	uploadFixture(t, store, task)
	return task, store, baseData
}

func TestRestoreTwoDistinctBasesRoundTrip(t *testing.T) {
	// A generation with two overlays on two DIFFERENT bases: the shared
	// entry names derive from the digests, so both bases must upload,
	// restore to distinct files, and match byte for byte. A fixed name
	// would make this generation complete-but-unrestorable.
	dir := t.TempDir()
	baseA := bytes.Repeat([]byte{0x33}, 96<<10)
	baseB := bytes.Repeat([]byte{0x44}, 80<<10)
	basePathA := filepath.Join(dir, "baseA.ext4")
	basePathB := filepath.Join(dir, "baseB.ext4")
	if err := os.WriteFile(basePathA, baseA, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePathB, baseB, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writeRestoreFixture(t, dir)
	overlay2 := filepath.Join(dir, "overlay2.ext4")
	overlay2Data := bytes.Repeat([]byte{0x55}, 16<<10)
	if err := os.WriteFile(overlay2, overlay2Data, 0o644); err != nil {
		t.Fatal(err)
	}
	task.Files[0].BasePath = basePathA
	task.Files[0].BaseSHA256 = digestOf(baseA)
	task.Files = append(task.Files, TaskFile{
		Name: "overlay2.ext4", Path: overlay2, SHA256: digestOf(overlay2Data), Size: int64(len(overlay2Data)),
		BasePath: basePathB, BaseSHA256: digestOf(baseB),
	})
	task.Generation = GenerationKey(task.Files)
	store := newMemBlobs()
	uploadFixture(t, store, task)

	destDir := filepath.Join(t.TempDir(), "restored")
	manifest, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(manifest.Files) != 5 {
		t.Fatalf("manifest files = %d, want 3 artifacts plus 2 bases", len(manifest.Files))
	}
	for _, want := range []struct {
		name string
		data []byte
	}{
		{SharedBaseName(digestOf(baseA)), baseA},
		{SharedBaseName(digestOf(baseB)), baseB},
	} {
		got, err := os.ReadFile(filepath.Join(destDir, want.name))
		if err != nil {
			t.Fatalf("restored %s: %v", want.name, err)
		}
		if !bytes.Equal(got, want.data) {
			t.Fatalf("restored %s differs from original", want.name)
		}
	}
}

func TestRestoreRejectsDuplicateSharedEntries(t *testing.T) {
	task, store, _ := baseFixture(t, 0x66)
	// Duplicate the shared base entry under a fresh name: without the
	// duplicate check this restores and verifies an extra copy of the
	// base, silent disk exhaustion inside a "verified" restore.
	rewriteManifest(t, store, task, func(m *GenerationManifest) {
		for _, mf := range m.Files {
			if strings.HasPrefix(mf.Object, "bases/") {
				dup := mf
				dup.Name = "base-extra-copy.ext4"
				m.Files = append(m.Files, dup)
				return
			}
		}
		t.Fatal("no shared entry in fixture manifest")
	})
	destDir := filepath.Join(t.TempDir(), "restored")
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("err = %v, want duplicate shared entry rejection", err)
	}
	// Rejected before any file was restored: the destination was never
	// even created.
	if _, serr := os.Stat(destDir); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("dest created despite pre-restore rejection: %v", serr)
	}
}

func TestRestoreRejectsDuplicateNames(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	rewriteManifest(t, store, task, func(m *GenerationManifest) {
		m.Files = append(m.Files, m.Files[1])
	})
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("err = %v, want duplicate name rejection", err)
	}
}

func TestRestoreRejectsInflatedSize(t *testing.T) {
	// Size is covered by the generation key: inflating it must fail the
	// key check instead of driving an effectively unbounded zero hash
	// during verification.
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	rewriteManifest(t, store, task, func(m *GenerationManifest) {
		m.Files[0].Size = 1 << 60
	})
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
	if err == nil || !strings.Contains(err.Error(), "generation key") {
		t.Fatalf("err = %v, want generation key mismatch for inflated size", err)
	}
}

func TestValidExtentsRejectsMalformedTables(t *testing.T) {
	bad := []ManifestFile{
		// Offset+Length wraps negative and previously passed both checks.
		{Size: 1 << 20, Extents: []Extent{{Offset: math.MaxInt64 - 10, Length: 100}}},
		// First extent wraps, resetting the cursor so {0,50} passed ordering.
		{Size: 1 << 20, Extents: []Extent{{Offset: 1 << 62, Length: 1 << 62}, {Offset: 0, Length: 50}}},
		{Size: -1},
		{Size: math.MaxInt64},
		{Size: 100, Extents: []Extent{{Offset: -5, Length: 10}}},
		{Size: 100, Extents: []Extent{{Offset: 0, Length: 0}}},
		{Size: 100, Extents: []Extent{{Offset: 50, Length: 10}, {Offset: 40, Length: 10}}},
		{Size: 100, Extents: []Extent{{Offset: 0, Length: 200}}},
	}
	for i, mf := range bad {
		if err := validExtents(mf); err == nil {
			t.Fatalf("case %d accepted: %+v", i, mf)
		}
	}
	good := ManifestFile{Size: 200, Extents: []Extent{{Offset: 0, Length: 100}, {Offset: 150, Length: 50}}}
	if err := validExtents(good); err != nil {
		t.Fatalf("valid table rejected: %v", err)
	}
}

func TestRestoreFailsOnTruncatedPackedObject(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	var object string
	for name := range store.objects {
		if strings.HasPrefix(name, genObject(task, "overlay.ext4.p")) {
			object = name
		}
	}
	if object == "" {
		t.Fatal("packed overlay object not found")
	}
	store.objects[object] = store.objects[object][:len(store.objects[object])-5]

	destDir := filepath.Join(t.TempDir(), "restored")
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
	if err == nil || !strings.Contains(err.Error(), "extent at") {
		t.Fatalf("err = %v, want mid-extent EOF failure", err)
	}
	entries, readErr := os.ReadDir(destDir)
	if readErr == nil && len(entries) != 0 {
		t.Fatalf("failed restore left %d files in dest", len(entries))
	}
}

func TestRestoreRejectsUnboundSharedObjectName(t *testing.T) {
	task, store, _ := baseFixture(t, 0x77)
	otherSha := digestOf([]byte("a different base entirely"))
	rewriteManifest(t, store, task, func(m *GenerationManifest) {
		for i, mf := range m.Files {
			if strings.HasPrefix(mf.Object, "bases/") {
				// Same digest claim, object pointed elsewhere: the name
				// must embed the entry's digest or fetching is refused.
				m.Files[i].Object = SharedBaseObject(otherSha, "deadbeef1234")
				return
			}
		}
		t.Fatal("no shared entry in fixture manifest")
	})
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
	if err == nil || !strings.Contains(err.Error(), "not bound to digest") {
		t.Fatalf("err = %v, want digest-binding rejection", err)
	}
}

func TestRestoreRejectsUnreferencedSharedEntry(t *testing.T) {
	task, store, _ := baseFixture(t, 0x88)
	orphanSha := digestOf([]byte("orphan base"))
	rewriteManifest(t, store, task, func(m *GenerationManifest) {
		m.Files = append(m.Files, ManifestFile{
			Name:   SharedBaseName(orphanSha),
			Object: SharedBaseObject(orphanSha, "deadbeef1234"),
			SHA256: orphanSha,
			Size:   16,
		})
	})
	_, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, filepath.Join(t.TempDir(), "restored"), nil)
	if err == nil || !strings.Contains(err.Error(), "no entry depends on") {
		t.Fatalf("err = %v, want unreferenced shared entry rejection", err)
	}
}

// cancelingBlobs cancels the restore context partway through: after the
// configured number of NewReader calls, later calls cancel first.
type cancelingBlobs struct {
	*memBlobs
	cancel context.CancelFunc
	after  int
	calls  int
}

func (c *cancelingBlobs) NewReader(ctx context.Context, object string) (io.ReadCloser, error) {
	c.calls++
	if c.calls > c.after {
		c.cancel()
	}
	return c.memBlobs.NewReader(ctx, object)
}

func TestRestoreCancellationCleansUp(t *testing.T) {
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Manifest is call 1, first artifact call 2; the context dies before
	// the second artifact streams.
	reader := &cancelingBlobs{memBlobs: store, cancel: cancel, after: 2}

	destDir := filepath.Join(t.TempDir(), "restored")
	_, err := RestoreGeneration(ctx, reader, task.SandboxID, task.Generation, destDir, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	entries, readErr := os.ReadDir(destDir)
	if readErr == nil && len(entries) != 0 {
		t.Fatalf("canceled restore left %d files in dest", len(entries))
	}
}

func TestRestoreRejectsTraversalName(t *testing.T) {
	// A hand-built manifest whose key genuinely covers a traversal name:
	// the key check passes, so the name validation itself must refuse to
	// let the entry escape the destination.
	files := []TaskFile{{Name: "../evil", SHA256: digestOf([]byte("x")), Size: 1}}
	gen := GenerationKey(files)
	manifest := GenerationManifest{
		SandboxID:  "sb-evil",
		Generation: gen,
		Files: []ManifestFile{{
			Name: "../evil", Object: "evil.pdeadbeef1234", SHA256: digestOf([]byte("x")), Size: 1,
			Extents: []Extent{{Offset: 0, Length: 1}},
		}},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemBlobs()
	store.objects["sandboxes/sb-evil/"+gen+"/"+ManifestObject] = payload

	parent := t.TempDir()
	destDir := filepath.Join(parent, "restored")
	_, err = RestoreGeneration(context.Background(), store, "sb-evil", gen, destDir, nil)
	if err == nil || !strings.Contains(err.Error(), "manifest file name") {
		t.Fatalf("err = %v, want traversal name rejection", err)
	}
	if _, serr := os.Stat(filepath.Join(parent, "evil")); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatal("traversal name escaped the destination")
	}
}

func TestConcurrentRestoresSameDest(t *testing.T) {
	// Two restores racing into one destination: exclusive per-name
	// creation means exactly one wins, the loser removes nothing it did
	// not create, and the surviving destination is complete and verified.
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	destDir := filepath.Join(t.TempDir(), "restored")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, destDir, nil)
		}(i)
	}
	wg.Wait()
	winners := 0
	for _, err := range errs {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d (errs %v), want exactly one", winners, errs)
	}
	// The surviving destination is complete: marker present, files intact.
	if _, err := os.Stat(filepath.Join(destDir, ManifestObject)); err != nil {
		t.Fatalf("completion marker missing after concurrent restore: %v", err)
	}
	orig, err := os.ReadFile(task.Files[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, task.Files[0].Name))
	if err != nil || !bytes.Equal(orig, got) {
		t.Fatalf("winner's restore incomplete: err=%v equal=%v", err, bytes.Equal(orig, got))
	}
}

// legacyFixture re-homes an uploaded generation under the legacy pre-size
// key: exactly what a bucket written before Size joined the key holds.
func legacyFixture(t *testing.T, store *memBlobs, task Task) Task {
	t.Helper()
	legacy := task
	legacy.Generation = generationKeyLegacy(task.Files)
	oldPrefix := "sandboxes/" + task.SandboxID + "/" + task.Generation + "/"
	newPrefix := "sandboxes/" + legacy.SandboxID + "/" + legacy.Generation + "/"
	var names []string
	for name := range store.objects {
		if strings.HasPrefix(name, oldPrefix) {
			names = append(names, name)
		}
	}
	for _, name := range names {
		store.objects[newPrefix+strings.TrimPrefix(name, oldPrefix)] = store.objects[name]
		delete(store.objects, name)
	}
	rewriteManifest(t, store, legacy, func(m *GenerationManifest) {
		m.Generation = legacy.Generation
	})
	return legacy
}

func TestRestoreAcceptsLegacyKeyGeneration(t *testing.T) {
	// Buckets hold generations uploaded before Size joined the key, and
	// journal tasks carrying legacy keys survive vmd upgrades: restore
	// must verify them under the legacy derivation and say so.
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	legacy := legacyFixture(t, store, task)

	var lines []string
	progress := func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	destDir := filepath.Join(t.TempDir(), "restored")
	manifest, err := RestoreGeneration(context.Background(), store, legacy.SandboxID, legacy.Generation, destDir, progress)
	if err != nil {
		t.Fatalf("legacy restore: %v", err)
	}
	if manifest.Generation != legacy.Generation {
		t.Fatalf("manifest generation = %s, want %s", manifest.Generation, legacy.Generation)
	}
	orig, err := os.ReadFile(task.Files[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, task.Files[0].Name))
	if err != nil || !bytes.Equal(orig, got) {
		t.Fatalf("legacy restore content mismatch: err=%v", err)
	}
	sawLegacy := false
	for _, l := range lines {
		if strings.Contains(l, "legacy") {
			sawLegacy = true
		}
	}
	if !sawLegacy {
		t.Fatalf("progress never reported the legacy derivation: %q", lines)
	}
}

func TestRestoreLegacyGenerationBoundsInflatedSize(t *testing.T) {
	// A legacy key does not cover Size, so the per-entry cap is the only
	// bound between a tampered size and an effectively unbounded zero
	// hash during verification.
	task := writeRestoreFixture(t, t.TempDir())
	store := newMemBlobs()
	uploadFixture(t, store, task)
	legacy := legacyFixture(t, store, task)
	rewriteManifest(t, store, legacy, func(m *GenerationManifest) {
		m.Files[0].Size = maxApparentSize + 1
	})
	_, err := RestoreGeneration(context.Background(), store, legacy.SandboxID, legacy.Generation, filepath.Join(t.TempDir(), "restored"), nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want size bound rejection", err)
	}
}

// A copy-fallback staged task uploads from staged snapshots while the
// manifest records the pause-time BasePath identity: the generation key
// recomputation at restore must accept it. This pins the contract that
// staging never mutates key-covered fields.
func TestRestoreValidatesStagedCopyFallbackGeneration(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	base := filepath.Join(dir, "base.ext4")
	overlay := filepath.Join(dir, "overlay.ext4")
	if err := os.WriteFile(base, []byte("base image bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, []byte("overlay bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseSum := sha256.Sum256([]byte("base image bytes"))
	osum := sha256.Sum256([]byte("overlay bytes"))

	files := []TaskFile{{
		Name: "rootfs.ext4", Path: overlay,
		SHA256: hex.EncodeToString(osum[:]), Size: int64(len("overlay bytes")),
		BasePath: base, BaseSHA256: hex.EncodeToString(baseSum[:]),
	}}
	task := Task{
		SandboxID: "sb", Generation: GenerationKey(files), Files: files,
		EnqueuedAt: time.Unix(1, 0),
	}
	// Key computed, THEN staged: the copy-fallback ordering.
	if err := StageTask(staging, &task); err != nil {
		t.Fatal(err)
	}

	j, _ := testJournal(t)
	store := newMemStore()
	u := &Uploader{Journal: j, Store: store}
	if completed, err := u.uploadTask(context.Background(), &task); err != nil || !completed {
		t.Fatalf("upload: completed=%v err=%v", completed, err)
	}

	dest := filepath.Join(dir, "restored")
	if _, err := RestoreGeneration(context.Background(), &memBlobs{objects: store.objects}, "sb", task.Generation, dest, nil); err != nil {
		t.Fatalf("restore of staged generation rejected: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "rootfs.ext4"))
	if err != nil || string(got) != "overlay bytes" {
		t.Fatalf("restored overlay = %q err=%v", got, err)
	}
}
