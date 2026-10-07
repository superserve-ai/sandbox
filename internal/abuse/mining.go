package abuse

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// MutationLockKey serializes policy mutations with change-feed commit order.
const MutationLockKey int64 = 0x53534142555345

// TeamPolicy is projected from current authoritative state in the background.
// Unknown policy must never be interpreted as a confirmed untrusted team.
type TeamPolicy struct {
	TeamID     uuid.UUID
	Known      bool
	Trusted    bool
	Restricted bool
	Mode       ComputeMode
	Generation int64
}

type TeamPolicySource interface {
	TeamPolicy(uuid.UUID) TeamPolicy
}

// SandboxPolicy binds policy to a host-owned network assignment. Assignment
// must change when a slot is reused, even when the address remains the same.
type SandboxPolicy struct {
	TeamPolicy
	SandboxID  uuid.UUID
	HostID     string
	HostIP     string
	Assignment string
}

type MiningPolicySource interface {
	MiningPolicy(sandboxID uuid.UUID, hostIP string) (SandboxPolicy, bool)
}

// MiningEvidence contains private operator data, never a tenant identity.
type MiningEvidence struct {
	Kind           string `json:"kind"`
	Indicator      string `json:"indicator"`
	PolicyRevision string `json:"policy_revision"`
}

type MiningIncident struct {
	ID         uuid.UUID      `json:"id"`
	SandboxID  uuid.UUID      `json:"sandbox_id"`
	TeamID     uuid.UUID      `json:"team_id"`
	HostID     string         `json:"host_id"`
	HostIP     string         `json:"host_ip"`
	Assignment string         `json:"assignment"`
	Generation int64          `json:"generation"`
	ObservedAt time.Time      `json:"observed_at"`
	Evidence   MiningEvidence `json:"evidence"`
}

type IncidentDisposition string

const (
	IncidentApplied  IncidentDisposition = "applied"
	IncidentReleased IncidentDisposition = "released"
	IncidentExempt   IncidentDisposition = "exempt"
	IncidentIgnored  IncidentDisposition = "ignored"
)

type IncidentReceipt struct {
	IncidentID    uuid.UUID
	Disposition   IncidentDisposition
	RestrictionID uuid.UUID
}

// MiningIncidentStore is used by a background delivery worker. Implementations
// authenticate/bind the host and re-check current ownership, trust and mode.
// Retrying an incident must not resurrect a released restriction.
type MiningIncidentStore interface {
	RecordIncident(context.Context, MiningIncident) (IncidentReceipt, error)
	IncidentStatus(context.Context, uuid.UUID) (IncidentReceipt, error)
}

// RefreshingComputeSource retains the existing admission read interface.
// Refresh is called only by a serialized background owner.
type RefreshingComputeSource interface {
	ComputeSource
	Refresh(context.Context)
}

// ErrMiningCleanupPending retains delivery while another restriction needs the gate.
var ErrMiningCleanupPending = errors.New("mining containment still required")

// ErrMiningLocalCleanupComplete retires host delivery for a confirmed ended
// assignment without changing its durable team restriction.
var ErrMiningLocalCleanupComplete = errors.New("mining local assignment retired")
