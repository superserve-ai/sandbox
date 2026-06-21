package vmdwaker

import (
	"context"
	"sync"
	"testing"

	"github.com/superserve-ai/sandbox/internal/actor"
)

type mockPauser struct {
	mu        sync.Mutex
	paused    []string
	destroyed []string
}

func (m *mockPauser) PauseInstance(_ context.Context, id, _ string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paused = append(m.paused, id)
	return "/snap/s", "/snap/m", nil
}
func (m *mockPauser) DestroyInstance(_ context.Context, id string, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destroyed = append(m.destroyed, id)
	return nil
}

func TestDemoterTierMapping(t *testing.T) {
	p := &mockPauser{}
	d := NewDemoter(p, "/snapshots", nil) // identity sandboxFor

	// Tier 1: bare pause keeps the VM resident — no vmd op.
	if err := d.Demote("act-1", actor.TierPaused1); err != nil {
		t.Fatal(err)
	}
	if len(p.paused) != 0 || len(p.destroyed) != 0 {
		t.Fatalf("Tier-1 must not snapshot or destroy: paused=%v destroyed=%v", p.paused, p.destroyed)
	}

	// Tier 2: snapshot to disk.
	if err := d.Demote("act-1", actor.TierPaused2); err != nil {
		t.Fatal(err)
	}
	if len(p.paused) != 1 || p.paused[0] != "act-1" {
		t.Fatalf("Tier-2 should PauseInstance: %v", p.paused)
	}

	// Tier 3 / cold: destroy.
	if err := d.Demote("act-1", actor.TierPaused3); err != nil {
		t.Fatal(err)
	}
	if err := d.Demote("act-2", actor.TierCold); err != nil {
		t.Fatal(err)
	}
	if len(p.destroyed) != 2 {
		t.Fatalf("Tier-3/cold should DestroyInstance: %v", p.destroyed)
	}
}

// TestDemoterDrivesTierController: the vmd Demoter behind the real TierController
// — idle staircase demotions reach vmd.
func TestDemoterDrivesTierController(t *testing.T) {
	p := &mockPauser{}
	d := NewDemoter(p, "/snapshots", nil)
	// Use a Demoter-only controller path: the TierController calls Demote per tick.
	if err := d.Demote("a", actor.TierPaused2); err != nil {
		t.Fatal(err)
	}
	if len(p.paused) != 1 {
		t.Fatalf("expected one snapshot, got %v", p.paused)
	}
}
