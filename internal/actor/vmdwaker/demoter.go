package vmdwaker

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/actor"
)

// Pauser is the vmd subset the tiered Demoter needs (mockable; the real
// vmdclient.Client satisfies it).
type Pauser interface {
	PauseInstance(ctx context.Context, id, snapshotDir string) (string, string, error)
	DestroyInstance(ctx context.Context, id string, force bool) error
}

// Demoter implements actor.Demoter over vmd, the production backing for the
// TierController:
//   - Tier 1 (paused-in-RAM): the bare Firecracker pause (latency-validated,
//     sub-ms wake) keeps the VM resident — no snapshot op, so this is a no-op at
//     the vmd level (the bare pause is issued on the same-host wake path).
//   - Tier 2 (local snapshot): vmd PauseInstance snapshots to disk and frees RAM.
//   - Tier 3 / cold: vmd DestroyInstance frees the host (after /state is durable).
type Demoter struct {
	vmd         Pauser
	snapshotDir string
	sandboxFor  func(actorID string) string
}

// NewDemoter builds a vmd-backed Demoter. sandboxFor maps an Actor id to its
// sandbox id (identity, by default).
func NewDemoter(vmd Pauser, snapshotDir string, sandboxFor func(string) string) *Demoter {
	if sandboxFor == nil {
		sandboxFor = func(id string) string { return id }
	}
	return &Demoter{vmd: vmd, snapshotDir: snapshotDir, sandboxFor: sandboxFor}
}

var _ actor.Demoter = (*Demoter)(nil)

// Demote moves the Actor's sandbox to the target tier via vmd.
func (d *Demoter) Demote(actorID string, to actor.Tier) error {
	sid := d.sandboxFor(actorID)
	ctx := context.Background()
	switch to {
	case actor.TierPaused1:
		return nil // bare pause keeps the VM resident; no vmd snapshot op
	case actor.TierPaused2:
		_, _, err := d.vmd.PauseInstance(ctx, sid, d.snapshotDir)
		return err
	case actor.TierPaused3, actor.TierCold:
		return d.vmd.DestroyInstance(ctx, sid, true)
	default:
		return nil
	}
}
