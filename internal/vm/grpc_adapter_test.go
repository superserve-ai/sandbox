package vm

import (
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/network"
)

// ipOwnerCheck gates credential-bearing /init retries. It must be read-only:
// in DestroyVM's window between the in-memory delete and the record delete, a
// reattaching lookup would resurrect the instance, rebind the freed slot, and
// certify the ownership the destroy just revoked.
func TestIPOwnerCheckDoesNotResurrectMidDestroy(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// The destroy gap: record still durable, instance already removed.
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, IP: "10.11.0.5"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}, netMgr: &network.Manager{}}
	a := &GRPCAdapter{mgr: m}

	if a.ipOwnerCheck("vm-1", "10.11.0.5")() {
		t.Fatal("mid-destroy (record present, instance gone) must read as not-owner")
	}
	if _, tracked := m.vms["vm-1"]; tracked {
		t.Fatal("the ownership check must not resurrect the destroyed instance")
	}
}

// abortResumeLocked must also be non-resurrecting: mid-destroy (record
// durable, instance gone) it must do nothing — not republish the instance,
// not flip the record to Paused over the destroy's teardown.
func TestAbortResumeLockedDoesNotResurrectMidDestroy(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, IP: "10.11.0.5"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}, netMgr: &network.Manager{}}

	m.abortResumeLocked("vm-1")

	if _, tracked := m.vms["vm-1"]; tracked {
		t.Fatal("abort must not resurrect the destroyed instance")
	}
	rec, err := store.Get("vm-1")
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	if rec.Status != StatusRunning {
		t.Fatalf("abort must not touch the record mid-destroy, got status %s", rec.Status)
	}
}

// The remaining veto legs: IP mismatch, non-Running status, a released slot
// (destroy frees the slot before the instance), and an untracked VM.
func TestIPOwnerCheckVetoes(t *testing.T) {
	m := &Manager{log: zerolog.Nop(), netMgr: &network.Manager{}, vms: map[string]*VMInstance{
		"wrongip": {ID: "wrongip", Status: StatusRunning, IP: "10.11.0.9"},
		"paused":  {ID: "paused", Status: StatusPaused, IP: "10.11.0.5"},
		"noslot":  {ID: "noslot", Status: StatusRunning, IP: "10.11.0.5"},
	}}
	a := &GRPCAdapter{mgr: m}

	if a.ipOwnerCheck("wrongip", "10.11.0.5")() {
		t.Fatal("IP mismatch must veto the retry")
	}
	if a.ipOwnerCheck("paused", "10.11.0.5")() {
		t.Fatal("a non-Running instance must veto the retry")
	}
	if a.ipOwnerCheck("noslot", "10.11.0.5")() {
		t.Fatal("a released network slot must veto the retry")
	}
	if a.ipOwnerCheck("absent", "10.11.0.5")() {
		t.Fatal("an untracked VM must veto the retry")
	}
}
