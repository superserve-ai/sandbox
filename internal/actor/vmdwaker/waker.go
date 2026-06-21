// Package vmdwaker is the production actor.Waker: it brings an Actor's compute
// live by restoring its sandbox VM through vmd, and delivers each event into the
// in-guest harness. It is the real backing for the wake-on-reference Router —
// the same role the cmd/actor-e2e demo Waker played against raw Firecracker,
// but going through vmd's higher-level API (which the e2e already validated at
// the Firecracker layer) and the harness delivery path.
//
// Dependencies are narrow interfaces (SandboxBooter, Deliverer, Resolver) so the
// orchestration is unit-tested with mocks; in production SandboxBooter is the
// vmd gRPC client and Deliverer is a boxd exec/stream call against the sandbox.
package vmdwaker

import (
	"context"
	"fmt"
	"sync"

	"github.com/superserve-ai/sandbox/internal/actor"
)

// SandboxBooter is the subset of vmd's API the waker needs. The real
// vmdclient.Client satisfies this shape (RestoreSnapshot / DestroyInstance).
type SandboxBooter interface {
	RestoreSnapshot(ctx context.Context, id, snapshotPath, memPath, basePath, deltaDir, teamID, ownerID string, env map[string]string) (string, uint32, uint32, error)
	DestroyInstance(ctx context.Context, id string, force bool) error
}

// Deliverer delivers one event to the running in-guest harness and returns when
// the turn completes. Production: a boxd exec/stream call against the sandbox
// (write the event to the harness transport, stream its output to the outbox).
// Tests: a recording mock.
type Deliverer interface {
	Deliver(ctx context.Context, sandboxID string, ev actor.Event) error
}

// Target is how an Actor maps onto a bootable sandbox: the template snapshot to
// restore from plus the team/owner/env binding. The control plane resolves this
// from the Actor's template and /state identity.
type Target struct {
	SnapshotPath string
	MemPath      string
	BasePath     string
	DeltaDir     string
	TeamID       string
	OwnerID      string
	Env          map[string]string
}

// Resolver maps an Actor to its boot Target.
type Resolver func(a actor.Actor) (Target, error)

// Waker implements actor.Waker over vmd.
type Waker struct {
	boot    SandboxBooter
	deliver Deliverer
	resolve Resolver

	mu   sync.Mutex
	live map[string]string // actorID → sandboxID
}

// New builds a vmd-backed Waker.
func New(boot SandboxBooter, deliver Deliverer, resolve Resolver) *Waker {
	return &Waker{boot: boot, deliver: deliver, resolve: resolve, live: map[string]string{}}
}

var _ actor.Waker = (*Waker)(nil)

// Wake restores the Actor's sandbox via vmd and returns a Handler that delivers
// each event into the in-guest harness. The sandbox id is the Actor id — one
// durable sandbox per Actor identity, so /state and routing stay stable.
func (w *Waker) Wake(ctx context.Context, a actor.Actor, _ *actor.Lease) (actor.Handler, error) {
	tgt, err := w.resolve(a)
	if err != nil {
		return nil, fmt.Errorf("resolve actor %q: %w", a.Name, err)
	}
	sandboxID := a.ID
	if _, _, _, err := w.boot.RestoreSnapshot(ctx, sandboxID,
		tgt.SnapshotPath, tgt.MemPath, tgt.BasePath, tgt.DeltaDir, tgt.TeamID, tgt.OwnerID, tgt.Env); err != nil {
		return nil, fmt.Errorf("restore sandbox for actor %q: %w", a.Name, err)
	}
	w.mu.Lock()
	w.live[a.ID] = sandboxID
	w.mu.Unlock()

	return func(ctx context.Context, ev actor.Event) error {
		return w.deliver.Deliver(ctx, sandboxID, ev)
	}, nil
}

// Destroy tears down the Actor's sandbox (cold demotion / Tier-3). Idempotent.
func (w *Waker) Destroy(ctx context.Context, actorID string) error {
	w.mu.Lock()
	sid, ok := w.live[actorID]
	delete(w.live, actorID)
	w.mu.Unlock()
	if !ok {
		return nil
	}
	return w.boot.DestroyInstance(ctx, sid, true)
}

// SandboxID returns the live sandbox id for an Actor (or "" if not live).
func (w *Waker) SandboxID(actorID string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.live[actorID]
}
