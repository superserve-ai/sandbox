package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func writePauseFixture(t *testing.T, dir, state string) Task {
	t.Helper()
	disk := filepath.Join(dir, "rootfs.ext4")
	f, err := os.Create(disk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xAA}, 64<<10), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmstate.snap"), []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}
	task := Task{SandboxID: "sb-fetch", Priority: PriorityPause, EnqueuedAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)}
	for _, name := range []string{"rootfs.ext4", "vmstate.snap"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		task.Files = append(task.Files, TaskFile{Name: name, Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	task.Generation = GenerationKey(task.Files)
	return task
}

func TestFetchGenerationPicksTheRecordedGenerationNotTheNewest(t *testing.T) {
	store := newMemBlobs()
	older := writePauseFixture(t, t.TempDir(), "pause A")
	uploadFixture(t, store, older)
	newer := writePauseFixture(t, t.TempDir(), "pause B")
	uploadFixture(t, store, newer)

	dest := filepath.Join(t.TempDir(), older.SandboxID)
	got, err := FetchGeneration(context.Background(), store, older.SandboxID, older.Generation, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Generation != older.Generation {
		t.Fatalf("restored generation %s, want the recorded %s", got.Manifest.Generation, older.Generation)
	}
	if !got.Standalone || got.Disk != filepath.Join(dest, "rootfs.ext4") || got.BlockMap != "" {
		t.Fatalf("restored = %+v", got)
	}
}

func TestFetchGenerationFailsClosed(t *testing.T) {
	store := newMemBlobs()
	task := writePauseFixture(t, t.TempDir(), "pause A")
	uploadFixture(t, store, task)
	dest := filepath.Join(t.TempDir(), "x")

	if _, err := FetchGeneration(context.Background(), store, task.SandboxID, "", dest, nil); !errors.Is(err, ErrNoMatchingBackup) {
		t.Fatalf("no recorded generation: err = %v, want ErrNoMatchingBackup", err)
	}
	unfinished := digestOf([]byte("pause never uploaded"))
	if _, err := FetchGeneration(context.Background(), store, task.SandboxID, unfinished, dest, nil); !errors.Is(err, ErrNoMatchingBackup) {
		t.Fatalf("generation not in the bucket: err = %v, want ErrNoMatchingBackup", err)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed match must leave no restore dir behind")
	}
}

func TestFetchGenerationReusesACompletedRestore(t *testing.T) {
	store := newMemBlobs()
	task := writePauseFixture(t, t.TempDir(), "pause A")
	uploadFixture(t, store, task)
	dest := filepath.Join(t.TempDir(), task.SandboxID)
	if _, err := FetchGeneration(context.Background(), store, task.SandboxID, task.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}
	counter := &countingReader{inner: store}
	if _, err := FetchGeneration(context.Background(), counter, task.SandboxID, task.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}
	if len(counter.reads) != 0 {
		t.Fatalf("a completed restore was fetched again: %v", counter.reads)
	}
}

func TestFetchGenerationOverlayWithBaseThroughLimiter(t *testing.T) {
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir, "pause A")
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	blockMap := filepath.Join(dir, BlockMapName)
	if err := os.WriteFile(blockMap, []byte("saved block map"), 0o644); err != nil {
		t.Fatal(err)
	}
	task.Files = append(task.Files, TaskFile{Name: BlockMapName, Path: blockMap, SHA256: digestOf([]byte("saved block map")), Size: 15})
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	root := t.TempDir()
	limited := &LimitedReader{Inner: store, Limiter: rate.NewLimiter(rate.Limit(64<<20), 1<<20)}
	cache := &CachingBaseReader{Inner: limited, Dir: filepath.Join(root, ".base-cache")}
	dest := filepath.Join(root, task.SandboxID)
	got, err := FetchGeneration(context.Background(), cache, task.SandboxID, task.Generation, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Standalone || got.Base == "" {
		t.Fatalf("overlay restored without its base: %+v", got)
	}
	have, _ := os.ReadFile(got.Base)
	if !bytes.Equal(have, baseData) {
		t.Fatal("restored base differs")
	}
	if got.BlockMap != filepath.Join(dest, BlockMapName) {
		t.Fatalf("block map = %q, want it beside the restored disk", got.BlockMap)
	}
	if have, _ := os.ReadFile(got.BlockMap); string(have) != "saved block map" {
		t.Fatalf("restored block map = %q", have)
	}
	// A completed restore whose block map went missing is not reusable.
	if err := os.Remove(got.BlockMap); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoredDisk(context.Background(), dest); err == nil {
		t.Fatal("a restore missing its block map must not pass as complete")
	}
}

func TestPruneBaseCacheDropsOldestCachedObjectsAndSparesPromotedBases(t *testing.T) {
	dir := t.TempDir()
	oldSpool := filepath.Join(dir, "bases_aaaa_fp")
	master := filepath.Join(dir, ".unpacked-bbbb")
	promoted := filepath.Join(dir, "base-cccc.ext4")
	for _, p := range []string{oldSpool, master, promoted} {
		if err := os.WriteFile(p, bytes.Repeat([]byte{1}, 1024), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oldSpool, past, past); err != nil {
		t.Fatal(err)
	}
	removed, err := PruneBaseCache(dir, 1500)
	if err != nil || removed != 1 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if _, err := os.Stat(oldSpool); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the oldest cached object must go first, spools included")
	}
	if _, err := os.Stat(master); err != nil {
		t.Fatal("the newer master must stay")
	}
	if _, err := os.Stat(promoted); err != nil {
		t.Fatal("a promoted base is never the cache's to drop")
	}
}

func TestFetchGenerationUsesTheHostBaseWithoutDownloadingIt(t *testing.T) {
	for _, clone := range []struct {
		name string
		fn   func(dst, src *os.File) error
	}{{"reflink", copyClone}, {"no reflink", noClone}} {
		t.Run(clone.name, func(t *testing.T) {
			stubClone(t, clone.fn)
			store := newMemBlobs()
			dir := t.TempDir()
			baseData := bytes.Repeat([]byte{0x11}, 128<<10)
			basePath := filepath.Join(dir, "base.ext4")
			if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
				t.Fatal(err)
			}
			task := writePauseFixture(t, dir, "pause A")
			task.Files[0].BasePath = basePath
			task.Files[0].BaseSHA256 = digestOf(baseData)
			task.Generation = GenerationKey(task.Files)
			uploadFixture(t, store, task)

			counter := &countingReader{inner: store}
			dest := filepath.Join(t.TempDir(), task.SandboxID)
			got, err := FetchGeneration(context.Background(), counter, task.SandboxID, task.Generation, dest, nil)
			if err != nil {
				t.Fatal(err)
			}
			for object := range counter.reads {
				if strings.HasPrefix(object, "bases/") {
					t.Fatalf("downloaded %s although the host holds the base", object)
				}
			}
			own := filepath.Join(dest, SharedBaseName(task.Files[0].BaseSHA256))
			if got.Base != own {
				t.Fatalf("base = %s, want the restore's own %s", got.Base, own)
			}

			// The template is rebuilt in place, and the restore is unmoved
			// by it: what was hashed is what the guest reads.
			if err := os.WriteFile(basePath, bytes.Repeat([]byte{0x22}, 128<<10), 0o644); err != nil {
				t.Fatal(err)
			}
			again, err := RestoredDisk(context.Background(), dest)
			if err != nil {
				t.Fatal(err)
			}
			if again.Base != own {
				t.Fatalf("base = %s, want %s", again.Base, own)
			}
			held, err := os.ReadFile(again.Base)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(held, baseData) {
				t.Fatal("the restore's base no longer holds the bytes the pause recorded")
			}
		})
	}
}

func TestCacheTemporariesAreSweptAndCounted(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, ".spool-123")
	candidate := filepath.Join(dir, ".candidate-abcd-456")
	master := filepath.Join(dir, ".unpacked-abcd")
	for _, p := range []string{spool, candidate, master} {
		if err := os.WriteFile(p, bytes.Repeat([]byte{1}, 1024), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := SweepCacheTemporaries(dir)
	if err != nil || removed != 2 {
		t.Fatalf("swept %d err=%v, want the two temporaries", removed, err)
	}
	if _, err := os.Stat(master); err != nil {
		t.Fatal("the sweep must leave finished masters alone")
	}
	if err := os.WriteFile(spool, bytes.Repeat([]byte{1}, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(spool, past, past); err != nil {
		t.Fatal(err)
	}
	if removed, err := PruneBaseCache(dir, 1500); err != nil || removed != 1 {
		t.Fatalf("prune removed %d err=%v, want the stale temporary counted and evicted first", removed, err)
	}
	if _, err := os.Stat(spool); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the stale temporary must be the first to go")
	}
}

// A base rebuilt in place keeps its path, its size and its recorded
// digest, and holds different bytes. Trusting the path would boot the
// overlay over the wrong filesystem, so the object must be fetched.
func TestFetchGenerationRefusesAHostBaseWhoseContentChanged(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(*testing.T, string)
	}{
		{
			name: "rebuilt in place",
			spoil: func(t *testing.T, path string) {
				if err := os.WriteFile(path, bytes.Repeat([]byte{0x22}, 128<<10), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "left short by an interrupted fetch",
			spoil: func(t *testing.T, path string) {
				if err := os.Truncate(path, 64<<10); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		for _, clone := range []struct {
			name string
			fn   func(dst, src *os.File) error
		}{{"reflink", copyClone}, {"no reflink", noClone}} {
			t.Run(tc.name+", "+clone.name, func(t *testing.T) {
				stubClone(t, clone.fn)
				store := newMemBlobs()
				dir := t.TempDir()
				baseData := bytes.Repeat([]byte{0x11}, 128<<10)
				basePath := filepath.Join(dir, "base.ext4")
				if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
					t.Fatal(err)
				}
				task := writePauseFixture(t, dir, "pause A")
				task.Files[0].BasePath = basePath
				task.Files[0].BaseSHA256 = digestOf(baseData)
				task.Generation = GenerationKey(task.Files)
				uploadFixture(t, store, task)

				tc.spoil(t, basePath)

				counter := &countingReader{inner: store}
				dest := filepath.Join(t.TempDir(), task.SandboxID)
				got, err := FetchGeneration(context.Background(), counter, task.SandboxID, task.Generation, dest, nil)
				if err != nil {
					t.Fatal(err)
				}
				if got.Base == basePath {
					t.Fatal("restore honoured the host base although its contents no longer match")
				}
				fetched := false
				for object := range counter.reads {
					if strings.HasPrefix(object, "bases/") {
						fetched = true
					}
				}
				if !fetched {
					t.Fatal("the base was neither trusted nor downloaded")
				}
				restored, err := os.ReadFile(got.Base)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(restored, baseData) {
					t.Fatal("the downloaded base does not hold the bytes the pause recorded")
				}
			})
		}
	}
}

// The reuse fast path reads a completed restore back. A host base that
// changed since must not be handed to the boot as if it still matched.
func TestRestoredDiskRejectsAHostBaseWhoseContentChanged(t *testing.T) {
	stubClone(t, copyClone)
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir, "pause A")
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	dest := filepath.Join(t.TempDir(), task.SandboxID)
	if _, err := FetchGeneration(context.Background(), store, task.SandboxID, task.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}
	// A restore holding no copy of its base, as every restore made before
	// this one does: the recorded template is all it has to go on.
	if err := os.Remove(filepath.Join(dest, SharedBaseName(task.Files[0].BaseSHA256))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePath, bytes.Repeat([]byte{0x22}, 128<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := RestoredDisk(context.Background(), dest); err == nil {
		t.Fatalf("base = %s, want a refusal so the caller restores again", got.Base)
	}
}

// The reuse check clears the destination when it cannot reuse it, so a
// check the context cut short must be reported rather than read as a
// restore worth replacing.
func TestFetchGenerationKeepsACompleteRestoreWhenTheReuseCheckIsCancelled(t *testing.T) {
	stubClone(t, copyClone)
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir, "pause A")
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	dest := filepath.Join(t.TempDir(), task.SandboxID)
	if _, err := FetchGeneration(context.Background(), store, task.SandboxID, task.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}

	// Without its own copy, resolving the restore has to materialize and
	// hash the base, which is the work the context cuts short.
	if err := os.Remove(filepath.Join(dest, SharedBaseName(task.Files[0].BaseSHA256))); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FetchGeneration(ctx, store, task.SandboxID, task.Generation, dest, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation reported", err)
	}
	if _, err := os.Stat(filepath.Join(dest, ManifestObject)); err != nil {
		t.Fatalf("the completed restore was discarded: %v", err)
	}
}

// The inventory that reports what would move reads the marker only: it
// neither hashes a base (a multi-gigabyte read per row) nor leaves a copy
// behind in a restore it was only asked about.
func TestRestoredGenerationReadsTheMarkerWithoutTouchingTheBase(t *testing.T) {
	stubClone(t, copyClone)
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir, "pause A")
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	// A restore the host base was never materialized into, as every
	// restore made before this existed is.
	dest := filepath.Join(t.TempDir(), task.SandboxID)
	if _, err := RestoreGeneration(context.Background(), store, task.SandboxID, task.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(dest, SharedBaseName(task.Files[0].BaseSHA256))
	if err := os.Remove(own); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}

	m, err := RestoredGeneration(dest)
	if err != nil {
		t.Fatal(err)
	}
	if m.Generation != task.Generation {
		t.Fatalf("generation = %s, want %s", m.Generation, task.Generation)
	}
	after, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("the restore gained %d entries from being listed", len(after)-len(before))
	}
}

// One manifest request per restore: a second identical read would be an
// extra round trip, and a transient failure of it would abort a restore
// whose manifest had already arrived.
func TestFetchGenerationReadsTheManifestOnce(t *testing.T) {
	store := newMemBlobs()
	dir := t.TempDir()
	task := writePauseFixture(t, dir, "pause A")
	uploadFixture(t, store, task)

	counter := &countingReader{inner: store}
	dest := filepath.Join(t.TempDir(), task.SandboxID)
	if _, err := FetchGeneration(context.Background(), counter, task.SandboxID, task.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}
	for object, n := range counter.reads {
		if strings.HasSuffix(object, ManifestObject) && n != 1 {
			t.Fatalf("read %s %d times, want once", object, n)
		}
	}
}

// A copy that fails its digest is never published under the name a later
// resolution trusts on sight, and leaves nothing half-done behind.
func TestHostBaseLeavesNothingBehindWhenTheCopyFailsItsDigest(t *testing.T) {
	stubClone(t, copyClone)
	dir := t.TempDir()
	src := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(src, bytes.Repeat([]byte{0x11}, 64<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := t.TempDir()

	// The digest of something else: what the template held at pause time.
	base, err := hostBase(context.Background(), restore, digestOf(bytes.Repeat([]byte{0x22}, 64<<10)), src)
	if err != nil || base != "" {
		t.Fatalf("base = %q (%v), want no base and no error", base, err)
	}
	entries, err := os.ReadDir(restore)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("left %v in the restore", names)
	}
}

// A restore of another generation is cleared, so resolving its base first
// would materialize and hash gigabytes for nothing.
func TestFetchGenerationDoesNotResolveAStaleRestoresBase(t *testing.T) {
	clones := 0
	stubClone(t, func(dst, src *os.File) error {
		clones++
		return copyClone(dst, src)
	})
	store := newMemBlobs()

	// A completed restore of one generation, holding no copy of its base.
	stale := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(stale, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	old := writePauseFixture(t, stale, "pause A")
	old.Files[0].BasePath = basePath
	old.Files[0].BaseSHA256 = digestOf(baseData)
	old.Generation = GenerationKey(old.Files)
	uploadFixture(t, store, old)
	dest := filepath.Join(t.TempDir(), old.SandboxID)
	if _, err := FetchGeneration(context.Background(), store, old.SandboxID, old.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dest, SharedBaseName(old.Files[0].BaseSHA256))); err != nil {
		t.Fatal(err)
	}

	// A newer generation of the same sandbox, depending on no base at all.
	next := t.TempDir()
	fresh := writePauseFixture(t, next, "pause B")
	uploadFixture(t, store, fresh)
	clones = 0

	if _, err := FetchGeneration(context.Background(), store, fresh.SandboxID, fresh.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}
	if clones != 0 {
		t.Fatalf("materialized %d base copies for a restore that was about to be cleared", clones)
	}
}

// The inventory that previews a migration must report a restore whose
// dependencies it cannot reach, rather than queueing it for a boot that
// then rejects it.
func TestRestoredDependenciesReportsAnUnreachableBase(t *testing.T) {
	stubClone(t, copyClone)
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir, "pause A")
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	dest := filepath.Join(t.TempDir(), task.SandboxID)
	if _, err := FetchGeneration(context.Background(), store, task.SandboxID, task.Generation, dest, nil); err != nil {
		t.Fatal(err)
	}
	// Its own copy answers for it.
	if err := RestoredDependencies(dest); err != nil {
		t.Fatalf("a restore holding its base reported %v", err)
	}
	// Without that copy the recorded template answers for it.
	if err := os.Remove(filepath.Join(dest, SharedBaseName(task.Files[0].BaseSHA256))); err != nil {
		t.Fatal(err)
	}
	if err := RestoredDependencies(dest); err != nil {
		t.Fatalf("a restore whose template is still there reported %v", err)
	}
	// With neither, there is nothing to boot over and the preview says so.
	if err := os.Remove(basePath); err != nil {
		t.Fatal(err)
	}
	if err := RestoredDependencies(dest); err == nil {
		t.Fatal("a restore with no reachable base was reported as movable")
	}
}

// breakingReader fails reads of one object, so a restore can be made to
// abort after earlier entries have already been put in place.
type breakingReader struct {
	inner BlobReader
	named string
}

func (b breakingReader) NewReader(ctx context.Context, object string) (io.ReadCloser, error) {
	if strings.Contains(object, b.named) {
		return nil, errors.New("object unavailable")
	}
	return b.inner.NewReader(ctx, object)
}

// Nothing boots from a failed restore, so a base it materialized from the
// host must not be left occupying the disk.
func TestFetchGenerationDiscardsAMaterializedBaseWhenTheRestoreFails(t *testing.T) {
	stubClone(t, copyClone)
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 128<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	task := writePauseFixture(t, dir, "pause A")
	task.Files[0].BasePath = basePath
	task.Files[0].BaseSHA256 = digestOf(baseData)
	task.Generation = GenerationKey(task.Files)
	uploadFixture(t, store, task)

	dest := filepath.Join(t.TempDir(), task.SandboxID)
	broken := breakingReader{inner: store, named: "vmstate"}
	if _, err := FetchGeneration(context.Background(), broken, task.SandboxID, task.Generation, dest, nil); err == nil {
		t.Fatal("want the restore to fail on the unavailable artifact")
	}
	if _, err := os.Stat(filepath.Join(dest, SharedBaseName(task.Files[0].BaseSHA256))); err == nil {
		t.Fatal("the failed restore kept the base it materialized")
	}
}

// Concurrent resolutions of one restore materialize its base once, and
// none of them reports a failure the caller would read as a restore worth
// clearing.
func TestHostBaseResolvesOnceUnderConcurrentCallers(t *testing.T) {
	var mu sync.Mutex
	clones := 0
	stubClone(t, func(dst, src *os.File) error {
		mu.Lock()
		clones++
		mu.Unlock()
		return copyClone(dst, src)
	})

	dir := t.TempDir()
	data := bytes.Repeat([]byte{0x11}, 128<<10)
	src := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	restore := t.TempDir()
	want := filepath.Join(restore, SharedBaseName(digestOf(data)))

	var wg sync.WaitGroup
	got := make([]string, 8)
	errs := make([]error, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = hostBase(context.Background(), restore, digestOf(data), src)
		}(i)
	}
	wg.Wait()

	for i := range got {
		if errs[i] != nil || got[i] != want {
			t.Fatalf("caller %d got %q (%v), want %q", i, got[i], errs[i], want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if clones != 1 {
		t.Fatalf("materialized the base %d times, want once", clones)
	}
}
