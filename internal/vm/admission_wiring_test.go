package vm

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/admission"
)

// A rebuild that could not read the store must report it, and its caller
// must leave the gate closed. Opening on an empty or partial ledger is not
// a weaker limit — it is no limit at all, which is the exact failure the
// gate exists to prevent.
func TestReconstructAdmissionReportsStoreFailure(t *testing.T) {
	// A closed store fails every read the way an unavailable or corrupt one
	// does, without needing to corrupt a file on disk.
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		log:       zerolog.Nop(),
		admission: admission.NewGate(true, 10),
		state:     store,
	}

	if err := m.reconstructAdmission(); err == nil {
		t.Fatal("reconstruction reported success against an unreadable store; the caller would open an empty ledger")
	}
	if got := m.admission.State(); got != admission.StateReconstructing {
		t.Fatalf("gate state = %v, want reconstructing — a failed rebuild must not leave it open", got)
	}
	if got := m.admission.Charged(); got != 0 {
		t.Fatalf("charged %d after a failed rebuild, want 0", got)
	}
}

// With no store configured at all the rebuild is trivially complete, so it
// must succeed rather than fail closed forever — that is the shape every
// test-constructed Manager and every host without persisted state has.
func TestReconstructAdmissionSucceedsWithNoStore(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), admission: admission.NewGate(true, 10)}
	if err := m.reconstructAdmission(); err != nil {
		t.Fatalf("reconstruction failed with no store configured: %v", err)
	}
}

func TestAdmissionStartupRetriesTransientReconstruction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{log: zerolog.Nop(), admission: admission.NewGate(true, 10)}
	var attempts atomic.Int32
	m.startAdmission(ctx, func() bool { return true }, func() error {
		if attempts.Add(1) == 1 {
			return fmt.Errorf("transient store error")
		}
		return nil
	})
	deadline := time.Now().Add(2 * time.Second)
	for m.admission.State() != admission.StateOpen && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.admission.State() != admission.StateOpen || attempts.Load() < 2 {
		t.Fatal("startup did not retry reconstruction", attempts.Load())
	}
}
