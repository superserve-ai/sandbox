// Package state defines the durable, versioned /state contract for Actors and
// provides a local reference implementation plus pluggable SaaS adapters.
//
// Per the Open Agent Infra spec (§3, §9.1), every Actor mounts a durable,
// versioned filesystem at /state. It is the only path guaranteed to persist:
// it survives crash, hibernation, and host migration, and is addressed by a
// stable durable *identity* (not by VM instance) so it can be remounted on any
// host. The model is git-like:
//
//	checkpoint <name>             immutable point-in-time snapshot (≈ git commit)
//	branch <name> --from <ckpt>   writable COW fork (≈ git branch)
//	rollback --to <ckpt>          re-home current onto an earlier checkpoint
//
// A Provider is the backend that realizes this contract. The interface is
// stable regardless of which backend implements it (LocalProvider for dev/test;
// Archil or Mesa once creds land — see §9.1, decision pending). The Actor
// runtime consumes only this interface, so the backend can be swapped without
// touching Actor lifecycle code.
package state

import (
	"context"
	"errors"
	"time"
)

// ErrNotConfigured is returned by a Provider whose backend has not been wired
// up (e.g. the Archil/Mesa adapters before their credentials are present in
// .context/secrets.env). Callers can use errors.Is to fall back to the local
// reference provider while a SaaS backend is still a stub.
var ErrNotConfigured = errors.New("state: provider not configured")

// ErrInvalidIdentity is returned when a durable identity is empty or contains a
// path-traversal element. Identities address on-disk state, so they are
// validated before being joined to any base directory.
var ErrInvalidIdentity = errors.New("state: invalid identity")

// ErrCheckpointNotFound is returned when a named checkpoint does not exist for
// the given identity.
var ErrCheckpointNotFound = errors.New("state: checkpoint not found")

// Mount is a handle to an identity's durable state made available on the host
// filesystem. The handle is closed (unmounted) when the Actor's compute is torn
// down; the underlying durable state is unaffected and can be remounted later
// from any host by the same identity.
type Mount struct {
	// Identity is the durable identity this mount belongs to.
	Identity string
	// Path is the resolved host path at which the identity's live, writable
	// state is available. The Actor's runtime maps this onto /state.
	Path string

	// unmount releases mount resources without touching durable state. It is
	// supplied by the Provider that produced the Mount.
	unmount func() error
}

// Close releases the mount (the durable state persists). It is idempotent.
func (m *Mount) Close() error {
	if m == nil || m.unmount == nil {
		return nil
	}
	f := m.unmount
	m.unmount = nil
	return f()
}

// Checkpoint is an immutable, named point-in-time snapshot of an identity's
// state — the analog of a git commit.
type Checkpoint struct {
	// Name is the caller-supplied checkpoint name, unique per identity.
	Name string
	// ID is a backend-assigned identifier for the snapshot. For backends that
	// expose content-addressed snapshots this is the snapshot/commit id; the
	// local provider uses the timestamped on-disk directory name.
	ID string
	// CreatedAt is when the snapshot was taken.
	CreatedAt time.Time
}

// Provider is the durable /state backend abstraction. Implementations must
// preserve the semantics documented here; LocalProvider is the reference.
//
// All methods take a durable identity string that addresses the state. An
// identity must be non-empty and free of path-traversal elements (no "..",
// no leading "/"); implementations validate it and return ErrInvalidIdentity
// otherwise.
type Provider interface {
	// Mount makes the identity's durable, writable state available at (or
	// resolvable from) mountpoint and returns a handle to it. State persists
	// across mounts: terminating compute and remounting the same identity —
	// even on a different host — yields the same data. The mountpoint is a
	// hint; the resolved location is reported on Mount.Path. Backends that
	// bind/NFS/FUSE-mount honor mountpoint directly; the local reference
	// provider returns a stable on-disk directory whose path persists state
	// without a real mount.
	Mount(ctx context.Context, identity, mountpoint string) (*Mount, error)

	// Checkpoint records an immutable, named snapshot of the identity's current
	// state and returns it. Re-using a name replaces the prior snapshot of that
	// name. The operation must be atomic: a failure leaves no partial snapshot.
	Checkpoint(ctx context.Context, identity, name string) (Checkpoint, error)

	// Branch creates an independent, writable fork named newBranch starting from
	// fromCheckpoint (copy-on-write conceptually). Writes on the branch must not
	// affect the source state or any other branch. Returns ErrCheckpointNotFound
	// if fromCheckpoint does not exist.
	Branch(ctx context.Context, identity, fromCheckpoint, newBranch string) error

	// Rollback re-homes the identity's current state onto toCheckpoint,
	// discarding intervening changes. It must be atomic: on failure the prior
	// current state is left intact. Returns ErrCheckpointNotFound if the
	// checkpoint does not exist.
	Rollback(ctx context.Context, identity, toCheckpoint string) error

	// ListCheckpoints returns the identity's checkpoints, ordered oldest-first
	// by creation time. It returns an empty slice (not an error) when there are
	// none.
	ListCheckpoints(ctx context.Context, identity string) ([]Checkpoint, error)
}
