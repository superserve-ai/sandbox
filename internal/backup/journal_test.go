package backup

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func testJournal(t *testing.T) (*Journal, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backup.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	j, err := NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	return j, path
}

func TestJournalPriorityAndFIFO(t *testing.T) {
	j, _ := testJournal(t)
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)

	// Enqueue out of order: checkpoint first, then two pauses.
	for _, task := range []Task{
		{SandboxID: "sb-c", Generation: "ccc", Priority: PriorityCheckpoint, EnqueuedAt: base},
		{SandboxID: "sb-a", Generation: "aaa", Priority: PriorityPause, EnqueuedAt: base.Add(2 * time.Second)},
		{SandboxID: "sb-b", Generation: "bbb", Priority: PriorityPause, EnqueuedAt: base.Add(time.Second)},
	} {
		if err := j.Enqueue(task); err != nil {
			t.Fatal(err)
		}
	}

	now := base.Add(time.Minute)
	var got []string
	for {
		task, ok, err := j.Next(now)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		got = append(got, task.Generation)
		if err := j.Ack(task, false); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"bbb", "aaa", "ccc"} // pauses first (FIFO within), checkpoint last
	if len(got) != len(want) {
		t.Fatalf("drained %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("drained %v, want %v", got, want)
		}
	}
}

func TestJournalNackBackoffAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	j, err := NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	task := Task{SandboxID: "sb", Generation: "gen1", Priority: PriorityPause, EnqueuedAt: base}
	if err := j.Enqueue(task); err != nil {
		t.Fatal(err)
	}
	got, ok, err := j.Next(base)
	if err != nil || !ok {
		t.Fatalf("next: ok=%v err=%v", ok, err)
	}
	if err := j.Nack(got, base); err != nil {
		t.Fatal(err)
	}
	// Immediately after a nack the task is in backoff: not runnable.
	if _, ok, _ := j.Next(base.Add(time.Second)); ok {
		t.Fatal("task runnable during backoff window")
	}

	// Survives a reopen (vmd restart), and becomes runnable after backoff.
	db.Close()
	db, err = bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j, err = NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err = j.Next(base.Add(time.Hour))
	if err != nil || !ok {
		t.Fatalf("after reopen: ok=%v err=%v", ok, err)
	}
	if got.Attempts != 1 || got.Generation != "gen1" {
		t.Fatalf("task after reopen = %+v", got)
	}
	counts, err := j.Pending()
	if err != nil || counts[PriorityPause] != 1 {
		t.Fatalf("pending = %v err=%v", counts, err)
	}
}
