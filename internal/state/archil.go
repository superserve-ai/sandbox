package state

import "context"

// ArchilConfig configures the Archil adapter. Values are sourced from
// .context/secrets.env (see secrets.env.example):
//
//	ARCHIL_API_KEY         -> APIKey
//	ARCHIL_REGION          -> Region
//	ARCHIL_DISK_OR_BUCKET  -> DiskID   (the disk id / backing bucket mounted at /state)
//
// When the disk is backed by the customer's own object store, the
// ARCHIL_BACKING_S3_ENDPOINT / ARCHIL_BACKING_ACCESS_KEY / ARCHIL_BACKING_SECRET_KEY
// keys configure that bucket; they belong on the disk-provisioning path, not on
// the per-mount hot path, so they are not modeled here.
type ArchilConfig struct {
	// APIKey authenticates against the Archil control API/CLI. Empty => stub.
	APIKey string
	// Region is the Archil region hosting the disk (e.g. "gcp-us-central1").
	Region string
	// DiskID is the Archil disk id mounted to expose an identity's /state.
	DiskID string
}

// ArchilProvider is the Archil-backed durable /state adapter.
//
// Archil is a GA, strongly read-after-write consistent POSIX filesystem
// (NFSv3) that is a durable caching layer over S3/GCS/R2, with git-style
// checkpoints and branches. It is the fastest path to a real /state layer and
// ships a Firecracker mount guide, so mounting into our microVMs is documented
// rather than research (see .context transcript + SPEC §3/§9.1).
//
// This is a STUB: every method returns ErrNotConfigured until the adapter is
// wired up. To make it real:
//
//   - Mount: NFSv3-mount the disk for `identity` at `mountpoint`. One Archil
//     disk per durable identity (not per VM), so state is location-independent
//     and remountable on any host. The mount itself is performed on the host
//     and passed into Firecracker via virtio-fs/vsock (the guest's netns +
//     egress firewall must permit the NFS path). Mount.unmount must run the
//     NFS unmount but must NOT delete the disk. Validate `identity` with
//     validateName as the local provider does (it maps to a disk-name segment).
//   - Checkpoint: `archil checkpoints create <mountpoint> <name>` (or the REST
//     equivalent); map the returned checkpoint id onto Checkpoint.ID and its
//     timestamp onto CreatedAt.
//   - Branch: `archil branches create <disk> <newBranch> --from-checkpoint
//     <fromCheckpoint>` — a COW writable fork; surface a missing checkpoint as
//     ErrCheckpointNotFound.
//   - Rollback: Archil has no destructive in-place revert verb; emulate it by
//     branching off `toCheckpoint` and re-homing the identity's mount onto that
//     branch (git-style recovery), preserving the atomicity the local provider
//     guarantees.
//   - ListCheckpoints: list the disk's checkpoints via CLI/API, oldest-first.
//
// Validate before trusting on the hot path (transcript §"Things to validate"):
// in-VM mount latency through netns, fsync durability semantics, and that
// destroy -> recreate-on-another-host -> remount recovers state.
type ArchilProvider struct {
	cfg ArchilConfig
}

// NewArchilProvider returns the Archil adapter. It always succeeds; the adapter
// reports ErrNotConfigured from its methods until APIKey/DiskID are wired up.
func NewArchilProvider(cfg ArchilConfig) *ArchilProvider {
	return &ArchilProvider{cfg: cfg}
}

// ArchilProvider implements Provider.
var _ Provider = (*ArchilProvider)(nil)

func (p *ArchilProvider) Mount(ctx context.Context, identity, mountpoint string) (*Mount, error) {
	return nil, ErrNotConfigured
}

func (p *ArchilProvider) Checkpoint(ctx context.Context, identity, name string) (Checkpoint, error) {
	return Checkpoint{}, ErrNotConfigured
}

func (p *ArchilProvider) Branch(ctx context.Context, identity, fromCheckpoint, newBranch string) error {
	return ErrNotConfigured
}

func (p *ArchilProvider) Rollback(ctx context.Context, identity, toCheckpoint string) error {
	return ErrNotConfigured
}

func (p *ArchilProvider) ListCheckpoints(ctx context.Context, identity string) ([]Checkpoint, error) {
	return nil, ErrNotConfigured
}
