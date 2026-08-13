package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The bulk restorer's job: every enumerated owner lands in the ledger
// with an honest verdict, dry-run classifies without touching disk, and
// execute materializes byte-identical artifacts through the single-owner
// path's full verification.
func TestHostRestoreBulk(t *testing.T) {
	store := newMemBlobs()
	srcA := t.TempDir()
	taskA := writeRestoreFixture(t, srcA)
	uploadFixture(t, store, taskA)
	srcB := t.TempDir()
	taskB := writeRestoreFixture(t, srcB)
	// Identical content in a second owner: distinct sandboxes sharing a
	// content-addressed generation is legitimate, and the fixture's
	// determinism makes this the cheap way to get a second owner.
	taskB.SandboxID = "sandbox-b"
	uploadFixture(t, store, taskB)

	root := t.TempDir()
	items := []HostRestoreItem{
		{SandboxID: taskA.SandboxID, Dest: filepath.Join(root, taskA.SandboxID)},
		{SandboxID: taskB.SandboxID, Dest: filepath.Join(root, taskB.SandboxID)},
		{SandboxID: "sandbox-lost", Dest: filepath.Join(root, "sandbox-lost")},
	}

	dry := &HostRestorer{Reader: store, Lister: store, DryRun: true, Concurrency: 2}
	report := dry.Run(context.Background(), items)
	if report.Coverable != 2 || report.Uncovered != 1 || report.Restored != 0 || report.Failed != 0 {
		t.Fatalf("dry-run report = %+v, want 2 coverable, 1 uncovered", report)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("dry run wrote %d entries to disk", len(entries))
	}

	real := &HostRestorer{Reader: store, Lister: store, Concurrency: 2}
	report = real.Run(context.Background(), items)
	if report.Restored != 2 || report.Uncovered != 1 || report.Failed != 0 {
		t.Fatalf("execute report = %+v, want 2 restored, 1 uncovered", report)
	}
	// Results stay in input order regardless of completion order.
	if report.Results[0].SandboxID != taskA.SandboxID || report.Results[2].Outcome != HostRestoreUncovered {
		t.Fatalf("results order = %+v", report.Results)
	}
	for _, task := range []Task{taskA, taskB} {
		for _, tf := range task.Files {
			orig, err := os.ReadFile(tf.Path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(root, task.SandboxID, tf.Name))
			if err != nil || !bytes.Equal(orig, got) {
				t.Fatalf("restored %s/%s differs (err %v)", task.SandboxID, tf.Name, err)
			}
		}
	}
}

// A canceled run reports every unstarted item as failed-by-cancel: a DR
// ledger with silently absent rows would read as coverage.
func TestHostRestoreCancelKeepsLedgerComplete(t *testing.T) {
	store := newMemBlobs()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	items := []HostRestoreItem{{SandboxID: "a", Dest: t.TempDir()}, {SandboxID: "b", Dest: t.TempDir()}}
	report := (&HostRestorer{Reader: store, Lister: store, Concurrency: 1}).Run(ctx, items)
	if len(report.Results) != 2 {
		t.Fatalf("ledger has %d rows, want every item accounted", len(report.Results))
	}
}

// Reruns after interruption skip destinations whose completion marker
// records the target generation, and the base cache streams a shared
// base from the store exactly once however many sandboxes depend on it.
func TestHostRestoreRerunAndBaseCache(t *testing.T) {
	store := newMemBlobs()
	src := t.TempDir()
	task := writeRestoreFixture(t, src)
	uploadFixture(t, store, task)
	root := t.TempDir()
	items := []HostRestoreItem{{SandboxID: task.SandboxID, Dest: filepath.Join(root, task.SandboxID)}}

	counter := &countingReader{inner: store}
	cache := &CachingBaseReader{Inner: counter, Dir: filepath.Join(root, ".base-cache")}
	r := &HostRestorer{Reader: cache, Lister: store, Concurrency: 1}
	report := r.Run(context.Background(), items)
	if report.Restored != 1 {
		t.Fatalf("first run = %+v", report)
	}
	report = r.Run(context.Background(), items)
	if report.Restored != 1 || report.Results[0].Reason != "already restored by a prior run" {
		t.Fatalf("rerun = %+v, want marker-based skip", report.Results[0])
	}
	for object, n := range counter.reads {
		if strings.HasPrefix(object, "bases/") && n != 1 {
			t.Fatalf("shared base %s streamed %d times, want once", object, n)
		}
	}
}

type countingReader struct {
	inner BlobReader
	mu    sync.Mutex
	reads map[string]int
}

func (c *countingReader) NewReader(ctx context.Context, object string) (io.ReadCloser, error) {
	c.mu.Lock()
	if c.reads == nil {
		c.reads = map[string]int{}
	}
	c.reads[object]++
	c.mu.Unlock()
	return c.inner.NewReader(ctx, object)
}

// Bucket object times are upload-completion times: a retry-delayed old
// upload finishing after a newer pause must not outrank it. The digest
// anchor selects the control plane's latest pause; an absent match
// falls back to newest-completed with the reason recorded.
func TestHostRestoreSelectsByVMStateDigest(t *testing.T) {
	store := newMemBlobs()
	srcOld := t.TempDir()
	oldTask := writeRestoreFixture(t, srcOld)
	// A second, content-distinct generation for the same sandbox: mutate
	// the vmstate before fixturing.
	srcNew := t.TempDir()
	newTask := writeRestoreFixture(t, srcNew)
	if err := os.WriteFile(filepath.Join(srcNew, "vmstate.snap"), []byte("newer pause vmstate"), 0o600); err != nil {
		t.Fatal(err)
	}
	newTask = refreshFixtureDigests(t, newTask)
	// Upload the NEWER pause first, the OLDER one second: completion
	// order now inverts capture order.
	uploadFixture(t, store, newTask)
	uploadFixture(t, store, oldTask)

	var newSHA string
	for _, f := range newTask.Files {
		if f.Name == "vmstate.snap" {
			newSHA = f.SHA256
		}
	}
	root := t.TempDir()
	r := &HostRestorer{Reader: store, Lister: store, Concurrency: 1}
	report := r.Run(context.Background(), []HostRestoreItem{{
		SandboxID: newTask.SandboxID, Dest: filepath.Join(root, "a"), WantVMStateSHAs: []string{newSHA},
	}})
	if report.Restored != 1 || report.Results[0].Generation != newTask.Generation {
		t.Fatalf("digest anchor picked %+v, want the newer pause %s", report.Results[0], newTask.Generation)
	}

	// No matching digest (the latest pause never uploaded): newest
	// completed wins with the fallback recorded.
	report = r.Run(context.Background(), []HostRestoreItem{{
		SandboxID: newTask.SandboxID, Dest: filepath.Join(root, "b"),
		WantVMStateSHAs: []string{"0000000000000000000000000000000000000000000000000000000000000000"},
	}})
	if report.Restored != 1 || report.Results[0].Reason == "" {
		t.Fatalf("fallback = %+v, want newest-completed with recorded reason", report.Results[0])
	}
}

// refreshFixtureDigests re-derives digests, sizes, and the generation
// key after a fixture file was mutated on disk.
func refreshFixtureDigests(t *testing.T, task Task) Task {
	t.Helper()
	for i := range task.Files {
		data, err := os.ReadFile(task.Files[i].Path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		task.Files[i].SHA256 = hex.EncodeToString(sum[:])
		task.Files[i].Size = int64(len(data))
	}
	task.Generation = GenerationKey(task.Files)
	return task
}
