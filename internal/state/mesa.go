package state

import "context"

// MesaConfig configures the Mesa adapter. Values are sourced from
// .context/secrets.env (see secrets.env.example):
//
//	MESA_API_KEY -> APIKey
//
// Mesa is in private beta and its backing store / region knobs are undisclosed,
// so the API key is the only modeled field today; add more as the SDK surface
// firms up.
type MesaConfig struct {
	// APIKey authenticates against the Mesa SDK/API. Empty => stub.
	APIKey string
}

// MesaProvider is the Mesa-backed durable /state adapter.
//
// Mesa is a versioned, git-compatible filesystem for agents: every write is
// captured in history automatically, with named checkpoints, branches, diffs,
// rollback/replay, and millisecond COW forks. It mounts via FUSE *or* an
// in-process SDK (@mesadev/sdk — no FUSE/container required), and Mesa has
// announced a partnership with Superserve to bring versioned filesystems to our
// sandboxes, which makes it the likely blessed integration path (see .context
// transcript + SPEC §3/§9.1).
//
// This is a STUB: every method returns ErrNotConfigured until the adapter is
// wired up. To make it real:
//
//   - Mount: mount the identity's Mesa volume at `mountpoint` (FUSE) or attach
//     it via the SDK and expose it under `mountpoint`. Map one Mesa volume per
//     durable identity so state follows compute. Mount.unmount must detach the
//     FUSE mount / close the SDK handle without destroying the volume. Validate
//     `identity` with validateName (it maps to a volume-name segment).
//   - Checkpoint: create a named checkpoint via the SDK; because Mesa versions
//     every write automatically, a named checkpoint is a label over the live
//     history head. Map its id/time onto Checkpoint.ID/CreatedAt.
//   - Branch: create a branch from `fromCheckpoint` (millisecond COW fork);
//     surface a missing checkpoint as ErrCheckpointNotFound. Branches are how
//     Mesa avoids locking for parallel agents — writes stay per-branch.
//   - Rollback: roll the identity's branch back to `toCheckpoint` via the SDK's
//     rollback/replay primitive (Mesa exposes this first-class), keeping the
//     atomicity the local provider guarantees.
//   - ListCheckpoints: list the volume's named checkpoints, oldest-first.
//
// Validate before trusting on the hot path (transcript §"Things to validate"):
// fsync durability semantics, the multi-writer/branch-merge consistency model,
// in-VM mount latency, and whether the backing store is self-hostable on our
// infra for the data-residency story.
type MesaProvider struct {
	cfg MesaConfig
}

// NewMesaProvider returns the Mesa adapter. It always succeeds; the adapter
// reports ErrNotConfigured from its methods until APIKey is wired up.
func NewMesaProvider(cfg MesaConfig) *MesaProvider {
	return &MesaProvider{cfg: cfg}
}

// MesaProvider implements Provider.
var _ Provider = (*MesaProvider)(nil)

func (p *MesaProvider) Mount(ctx context.Context, identity, mountpoint string) (*Mount, error) {
	return nil, ErrNotConfigured
}

func (p *MesaProvider) Checkpoint(ctx context.Context, identity, name string) (Checkpoint, error) {
	return Checkpoint{}, ErrNotConfigured
}

func (p *MesaProvider) Branch(ctx context.Context, identity, fromCheckpoint, newBranch string) error {
	return ErrNotConfigured
}

func (p *MesaProvider) Rollback(ctx context.Context, identity, toCheckpoint string) error {
	return ErrNotConfigured
}

func (p *MesaProvider) ListCheckpoints(ctx context.Context, identity string) ([]Checkpoint, error) {
	return nil, ErrNotConfigured
}
