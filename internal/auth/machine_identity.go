package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// MachineOperation is an explicit machine permission. The zero value is not
// an operation and is never allowed by a MachinePolicy.
type MachineOperation string

const (
	MachineOperationCreate        MachineOperation = "sandbox:create"
	MachineOperationList          MachineOperation = "sandbox:list"
	MachineOperationRead          MachineOperation = "sandbox:read"
	MachineOperationMetadata      MachineOperation = "sandbox:metadata"
	MachineOperationPause         MachineOperation = "sandbox:pause"
	MachineOperationResume        MachineOperation = "sandbox:resume"
	MachineOperationActivate      MachineOperation = "sandbox:activate"
	MachineOperationDelete        MachineOperation = "sandbox:delete"
	MachineOperationPatch         MachineOperation = "sandbox:patch"
	MachineOperationToken         MachineOperation = "sandbox:token"
	MachineOperationReconnect     MachineOperation = "sandbox:reconnect"
	MachineOperationCommandRun    MachineOperation = "command:run"
	MachineOperationCommandSpawn  MachineOperation = "command:spawn"
	MachineOperationCommandRead   MachineOperation = "command:read"
	MachineOperationCommandWrite  MachineOperation = "command:write"
	MachineOperationCommandSignal MachineOperation = "command:signal"
	MachineOperationFileRead      MachineOperation = "file:read"
	MachineOperationFileWrite     MachineOperation = "file:write"
	MachineOperationFileList      MachineOperation = "file:list"
	MachineOperationFileImport    MachineOperation = "file:import"
	MachineOperationFileExport    MachineOperation = "file:export"
)

type PrincipalStatus string

const (
	PrincipalActive   PrincipalStatus = "active"
	PrincipalDisabled PrincipalStatus = "disabled"
	PrincipalDeleted  PrincipalStatus = "deleted"
)

type CredentialState string

const (
	CredentialActive  CredentialState = "active"
	CredentialRevoked CredentialState = "revoked"
)

// MachinePrincipal is the durable identity for one hosted tenant. It is
// deliberately separate from a human membership or creator identifier.
type MachinePrincipal struct {
	PrincipalID    uuid.UUID
	TeamID         uuid.UUID
	HostedTenantID uuid.UUID
	Status         PrincipalStatus
	Generation     uint64
}

// MachineCredential is the non-secret authority record. Secret material is
// issued and delivered by an owning workflow and must not cross this seam.
type MachineCredential struct {
	CredentialID         uuid.UUID
	PrincipalID          uuid.UUID
	LineageID            uuid.UUID
	State                CredentialState
	ExpiresAt            time.Time
	RevocationGeneration uint64
}

// CallerContext is the canonical verified identity passed from API auth to
// resource handlers, proxy routing, logging, and attribution consumers.
type CallerContext struct {
	PrincipalID          uuid.UUID
	CredentialID         uuid.UUID
	LineageID            uuid.UUID
	TeamID               uuid.UUID
	HostedTenantID       uuid.UUID
	Permissions          []MachineOperation
	Policy               MachinePolicy
	Audience             string
	ExpiresAt            time.Time
	RevocationGeneration uint64
}

// SandboxOwnership is server-controlled state written with sandbox creation.
// It is never populated from request metadata and is immutable after creation.
type SandboxOwnership struct {
	SandboxID        uuid.UUID
	OwnerPrincipalID uuid.UUID
	TeamID           uuid.UUID
}

// MachineCapability is a server-issued, lineage-bound capability for a
// sandbox operation. Legacy sandbox-only tokens cannot be represented here.
type MachineCapability struct {
	PrincipalID          uuid.UUID
	CredentialID         uuid.UUID
	LineageID            uuid.UUID
	TeamID               uuid.UUID
	SandboxID            uuid.UUID
	Operations           []MachineOperation
	Audience             string
	ExpiresAt            time.Time
	RevocationGeneration uint64
}

var (
	ErrInvalidMachineIdentity  = errors.New("auth: invalid machine identity")
	ErrMachineCapabilityDenied = errors.New("auth: machine capability denied")
)

func (p MachinePrincipal) Validate() error {
	if p.PrincipalID == uuid.Nil || p.TeamID == uuid.Nil || p.HostedTenantID == uuid.Nil || p.Generation == 0 {
		return fmt.Errorf("%w: principal, team, tenant, and generation are required", ErrInvalidMachineIdentity)
	}
	if p.Status != PrincipalActive && p.Status != PrincipalDisabled && p.Status != PrincipalDeleted {
		return fmt.Errorf("%w: unknown principal status %q", ErrInvalidMachineIdentity, p.Status)
	}
	return nil
}

func (c MachineCredential) ValidateAt(now time.Time, principal MachinePrincipal) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	if c.CredentialID == uuid.Nil || c.PrincipalID != principal.PrincipalID || c.LineageID == uuid.Nil || c.RevocationGeneration == 0 {
		return fmt.Errorf("%w: credential lineage is incomplete", ErrInvalidMachineIdentity)
	}
	if c.State != CredentialActive || principal.Status != PrincipalActive {
		return fmt.Errorf("%w: credential or principal is not active", ErrInvalidMachineIdentity)
	}
	if c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) {
		return fmt.Errorf("%w: credential is expired", ErrInvalidMachineIdentity)
	}
	return nil
}

func (c CallerContext) ValidateAt(now time.Time) error {
	if c.PrincipalID == uuid.Nil || c.CredentialID == uuid.Nil || c.LineageID == uuid.Nil || c.TeamID == uuid.Nil || c.HostedTenantID == uuid.Nil || c.RevocationGeneration == 0 || c.Audience == "" || c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) {
		return ErrInvalidMachineIdentity
	}
	if len(c.Permissions) == 0 {
		return ErrInvalidMachineIdentity
	}
	for _, operation := range c.Permissions {
		if !c.Policy.Allows(operation) {
			return ErrInvalidMachineIdentity
		}
	}
	return nil
}

func (o SandboxOwnership) Validate() error {
	if o.SandboxID == uuid.Nil || o.OwnerPrincipalID == uuid.Nil || o.TeamID == uuid.Nil {
		return fmt.Errorf("%w: sandbox ownership is incomplete", ErrInvalidMachineIdentity)
	}
	return nil
}

func (c MachineCapability) ValidateAt(now time.Time) error {
	if c.PrincipalID == uuid.Nil || c.CredentialID == uuid.Nil || c.LineageID == uuid.Nil || c.TeamID == uuid.Nil || c.SandboxID == uuid.Nil || c.RevocationGeneration == 0 || c.Audience == "" || c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) || len(c.Operations) == 0 {
		return ErrMachineCapabilityDenied
	}
	for _, operation := range c.Operations {
		if !isKnownMachineOperation(operation) {
			return ErrMachineCapabilityDenied
		}
	}
	return nil
}

func (c MachineCapability) Allows(operation MachineOperation) bool {
	return operation != "" && slices.Contains(c.Operations, operation)
}

// DeriveCapability narrows a verified caller to one sandbox. It cannot change
// identity, audience, lineage, generation, or expiry, and every child scope
// must be a subset of the caller's explicit permissions.
func DeriveCapability(caller CallerContext, ownership SandboxOwnership, sandboxID uuid.UUID, audience string, operations []MachineOperation, expiresAt, now time.Time) (MachineCapability, error) {
	if err := caller.ValidateAt(now); err != nil {
		return MachineCapability{}, err
	}
	if err := ownership.Validate(); err != nil || ownership.SandboxID != sandboxID || ownership.OwnerPrincipalID != caller.PrincipalID || ownership.TeamID != caller.TeamID || audience == "" || audience != caller.Audience || len(operations) == 0 || sandboxID == uuid.Nil {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	if expiresAt.IsZero() || expiresAt.After(caller.ExpiresAt) || !now.Before(expiresAt) {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	for _, operation := range operations {
		if operation == "" || !caller.Policy.Allows(operation) || !slices.Contains(caller.Permissions, operation) {
			return MachineCapability{}, ErrMachineCapabilityDenied
		}
	}
	return MachineCapability{
		PrincipalID: caller.PrincipalID, CredentialID: caller.CredentialID, LineageID: caller.LineageID,
		TeamID: caller.TeamID, SandboxID: sandboxID, Operations: slices.Clone(operations), Audience: caller.Audience,
		ExpiresAt: expiresAt, RevocationGeneration: caller.RevocationGeneration,
	}, nil
}

// MachinePolicy is intentionally default-deny. Callers must be granted each
// operation explicitly; future operations do not inherit human permissions.
type MachinePolicy struct{ allowed map[MachineOperation]struct{} }

func NewMachinePolicy(operations ...MachineOperation) MachinePolicy {
	allowed := make(map[MachineOperation]struct{}, len(operations))
	for _, operation := range operations {
		if isKnownMachineOperation(operation) {
			allowed[operation] = struct{}{}
		}
	}
	return MachinePolicy{allowed: allowed}
}

func (p MachinePolicy) Allows(operation MachineOperation) bool {
	_, ok := p.allowed[operation]
	return isKnownMachineOperation(operation) && ok
}

func isKnownMachineOperation(operation MachineOperation) bool {
	switch operation {
	case MachineOperationCreate, MachineOperationList, MachineOperationRead,
		MachineOperationMetadata, MachineOperationPause, MachineOperationResume,
		MachineOperationActivate, MachineOperationDelete, MachineOperationPatch,
		MachineOperationToken, MachineOperationReconnect, MachineOperationCommandRun,
		MachineOperationCommandSpawn, MachineOperationCommandRead, MachineOperationCommandWrite,
		MachineOperationCommandSignal, MachineOperationFileRead, MachineOperationFileWrite,
		MachineOperationFileList, MachineOperationFileImport, MachineOperationFileExport:
		return true
	default:
		return false
	}
}

// PrincipalLifecycle is the sandbox-side handoff to the authorized control
// plane. Implementations must fence retries and never accept runtime machine
// credentials as an administrator.
type PrincipalLifecycle interface {
	EnsurePrincipal(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string) (MachinePrincipal, error)
	IssueCredential(context.Context, uuid.UUID, string) (MachineCredential, error)
	RotateCredential(context.Context, uuid.UUID, string) (MachineCredential, error)
	RevokeCredential(context.Context, uuid.UUID, string) error
	DisablePrincipal(context.Context, uuid.UUID, string) error
	RestorePrincipal(context.Context, uuid.UUID, string) (MachineCredential, error)
}
