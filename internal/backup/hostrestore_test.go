package backup

import (
	"bytes"
	"context"
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
