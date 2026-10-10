package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
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
	TeamOperationDesktopRead      MachineOperation = "desktop:read"
	TeamOperationDesktopWrite     MachineOperation = "desktop:write"
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
	// Nil when the principal predates template binding.
	ApprovedTemplateID *uuid.UUID
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
	AllowedAudiences     []string
	ExpiresAt            time.Time
	RevocationGeneration uint64
	CallerKind           string
	ActorID              uuid.UUID
	// ApprovedTemplateID is server-resolved policy state. A nil value is not
	// an invitation to accept a client-selected template: machine creation
	// must fail closed when the control plane has not supplied one.
	ApprovedTemplateID *uuid.UUID
}

// SandboxOwnership is server-controlled state written with sandbox creation.
// It is never populated from request metadata and is immutable after creation.
type SandboxOwnership struct {
	SandboxID        uuid.UUID
	OwnerPrincipalID uuid.UUID
	TeamID           uuid.UUID
}

// OwnershipState is an attested serving classification. Unknown is distinct
// from ordinary: old records, unsupported producers, and lookup failures must
// not silently regain legacy access.
type OwnershipState string

const (
	OwnershipUnknown  OwnershipState = "unknown"
	OwnershipOrdinary OwnershipState = "ordinary"
	OwnershipMachine  OwnershipState = "machine"
)

// IssuancePolicy is the trusted parent policy used when a control-plane
// credential is turned into a resource capability. Child audiences are
// explicit; callers cannot select arbitrary audiences or permissions.
type IssuancePolicy struct {
	Operations       []MachineOperation
	AllowedAudiences []string
}

func (p IssuancePolicy) AllowsAudience(audience string) bool {
	return audience != "" && slices.Contains(p.AllowedAudiences, audience)
}

func (p IssuancePolicy) Allows(operation MachineOperation) bool {
	return slices.Contains(p.Operations, operation) && isKnownMachineOperation(operation)
}

// MachineCapability is a server-issued, lineage-bound capability for a
// sandbox operation. Legacy sandbox-only tokens cannot be represented here.
type MachineCapability struct {
	PrincipalID          uuid.UUID          `json:"principal_id"`
	CredentialID         uuid.UUID          `json:"credential_id"`
	LineageID            uuid.UUID          `json:"lineage_id"`
	TeamID               uuid.UUID          `json:"team_id"`
	SandboxID            uuid.UUID          `json:"sandbox_id"`
	Operations           []MachineOperation `json:"operations"`
	Audience             string             `json:"audience"`
	ExpiresAt            time.Time          `json:"expires_at"`
	RevocationGeneration uint64             `json:"revocation_generation"`
	// CallerKind is "machine" for lineage-bound machine authority and
	// "human" for a verified human session, or "api_key" for a team key. Team claims
	// never impersonate the machine owner.
	CallerKind         string    `json:"caller_kind,omitempty"`
	ActorID            uuid.UUID `json:"actor_id,omitempty"`
	ParentCredentialID uuid.UUID `json:"parent_credential_id,omitempty"`
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
	if c.RevocationGeneration != principal.Generation {
		return fmt.Errorf("%w: credential generation is stale", ErrInvalidMachineIdentity)
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

// NewTrustedIssuancePolicy narrows the sandbox API root to the operations and
// audiences explicitly supplied by the control-plane adapter.
func NewTrustedIssuancePolicy(operations []MachineOperation, audiences ...string) IssuancePolicy {
	validOps := make([]MachineOperation, 0, len(operations))
	for _, op := range operations {
		if isKnownMachineOperation(op) && !slices.Contains(validOps, op) {
			validOps = append(validOps, op)
		}
	}
	validAudiences := make([]string, 0, len(audiences))
	for _, audience := range audiences {
		if audience != "" && !slices.Contains(validAudiences, audience) {
			validAudiences = append(validAudiences, audience)
		}
	}
	return IssuancePolicy{Operations: validOps, AllowedAudiences: validAudiences}
}

func (o SandboxOwnership) Validate() error {
	if o.SandboxID == uuid.Nil || o.OwnerPrincipalID == uuid.Nil || o.TeamID == uuid.Nil {
		return fmt.Errorf("%w: sandbox ownership is incomplete", ErrInvalidMachineIdentity)
	}
	return nil
}

func (c MachineCapability) ValidateAt(now time.Time) error {
	switch c.CallerKind {
	case "", "machine", "human", "api_key":
	default:
		return ErrMachineCapabilityDenied
	}
	if c.IsTeamCapability() && (c.PrincipalID != uuid.Nil || c.CredentialID != uuid.Nil || c.LineageID != uuid.Nil || c.RevocationGeneration != 0) {
		return ErrMachineCapabilityDenied
	}
	if c.CallerKind == "api_key" && (c.ParentCredentialID == uuid.Nil || c.ActorID != uuid.Nil) {
		return ErrMachineCapabilityDenied
	}

	human := (c.CallerKind == "human" && c.ActorID != uuid.Nil) || (c.CallerKind == "api_key" && c.ParentCredentialID != uuid.Nil)
	if (!human && (c.PrincipalID == uuid.Nil || c.CredentialID == uuid.Nil || c.LineageID == uuid.Nil || c.RevocationGeneration == 0)) || c.TeamID == uuid.Nil || c.SandboxID == uuid.Nil || c.Audience == "" || c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) || len(c.Operations) == 0 {
		return ErrMachineCapabilityDenied
	}
	for _, operation := range c.Operations {
		if !isKnownMachineOperation(operation) && !(c.IsTeamCapability() && isTeamDesktopOperation(operation)) {
			return ErrMachineCapabilityDenied
		}
	}
	return nil
}

// DeriveHumanCapability creates a typed child claim from an already verified
// human session. It carries the actor explicitly and can never be mistaken
// for machine-owner lineage.
func DeriveHumanCapability(actorID, teamID, sandboxID uuid.UUID, audience string, operations []MachineOperation, expiresAt, now time.Time) (MachineCapability, error) {
	if actorID == uuid.Nil || teamID == uuid.Nil || sandboxID == uuid.Nil || audience == "" || len(operations) == 0 || expiresAt.IsZero() || !now.Before(expiresAt) {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	for _, op := range operations {
		if !isKnownMachineOperation(op) && !isTeamDesktopOperation(op) {
			return MachineCapability{}, ErrMachineCapabilityDenied
		}
	}
	return MachineCapability{TeamID: teamID, SandboxID: sandboxID, Operations: slices.Clone(operations), Audience: audience, ExpiresAt: expiresAt, CallerKind: "human", ActorID: actorID}, nil
}

func DeriveHumanCapabilityWithParent(actorID, parentCredentialID, teamID, sandboxID uuid.UUID, audience string, operations []MachineOperation, expiresAt, now time.Time) (MachineCapability, error) {
	capability, err := DeriveHumanCapability(actorID, teamID, sandboxID, audience, operations, expiresAt, now)
	if err != nil || parentCredentialID == uuid.Nil {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	capability.ParentCredentialID = parentCredentialID
	return capability, nil
}

// IsTeamCapability distinguishes authenticated team authority from machine lineage.
func (c MachineCapability) IsTeamCapability() bool {
	return c.CallerKind == "human" || c.CallerKind == "api_key"
}

// DeriveAPIKeyCapability carries the authenticated key, not its creator as a
// verified human. A child cannot outlive a finite parent credential.
func DeriveAPIKeyCapability(parentID, teamID, sandboxID uuid.UUID, audience string, operations []MachineOperation, expiresAt, parentExpiresAt, now time.Time) (MachineCapability, error) {
	if !parentExpiresAt.IsZero() && parentExpiresAt.Before(expiresAt) {
		expiresAt = parentExpiresAt
	}
	c := MachineCapability{CallerKind: "api_key", ParentCredentialID: parentID,
		TeamID: teamID, SandboxID: sandboxID, Audience: audience,
		Operations: slices.Clone(operations), ExpiresAt: expiresAt}
	if err := c.ValidateAt(now); err != nil {
		return MachineCapability{}, err
	}
	return c, nil
}

// VerifyMachineCapability checks a signed, server-issued capability. The
// payload is deliberately versioned so a legacy sandbox-only token cannot be
// interpreted as machine authority during a mixed-version rollout.
func VerifyMachineCapability(token string, signingKey []byte, now time.Time) (MachineCapability, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "mcap" || parts[1] != "v1" || len(signingKey) == 0 {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte("mcap.v1."))
	_, _ = mac.Write([]byte(parts[2]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(got) != sha256.Size || !hmac.Equal(got, want) {
		// The signature is carried after the payload in the complete token. The
		// split above intentionally keeps malformed versions from reaching JSON.
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	var capability MachineCapability
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&capability); err != nil || capability.ValidateAt(now) != nil {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	return capability, nil
}

// SignMachineCapability serializes and signs a capability with an explicit
// transport version. Callers must validate the capability before issuing it.
func SignMachineCapability(capability MachineCapability, signingKey []byte, now time.Time) (string, error) {
	if len(signingKey) == 0 || capability.ValidateAt(now) != nil {
		return "", ErrMachineCapabilityDenied
	}
	payload, err := json.Marshal(capability)
	if err != nil {
		return "", ErrMachineCapabilityDenied
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte("mcap.v1."))
	_, _ = mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "mcap.v1." + encoded + "." + signature, nil
}

// RevocationAuthority is the canonical durable check used on cache refresh;
// an error is a denial, never permission to keep serving stale authority.
type RevocationAuthority func(context.Context, uuid.UUID, uuid.UUID) (uint64, error)

func VerifyMachineCapabilityWithAuthority(ctx context.Context, token string, signingKey []byte, now time.Time, authority RevocationAuthority) (MachineCapability, error) {
	capability, err := VerifyMachineCapability(token, signingKey, now)
	if err != nil || authority == nil {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	generation, err := authority(ctx, capability.PrincipalID, capability.CredentialID)
	if err != nil || generation != capability.RevocationGeneration {
		return MachineCapability{}, ErrMachineCapabilityDenied
	}
	return capability, nil
}

// RevocationState is a bounded local snapshot of durable authority. A serving
// instance refreshes it at most once per freshness window; request and frame
// checks are local and therefore do not add per-frame I/O.
type RevocationState struct {
	PrincipalID  uuid.UUID
	CredentialID uuid.UUID
	// LineageID is optional for compatibility with older in-process callers;
	// serving registrations populate it and then require an exact match.
	LineageID            uuid.UUID
	RevocationGeneration uint64
	ExpiresAt            time.Time
}

func (s RevocationState) Allows(capability MachineCapability, now time.Time) bool {
	lineageMatches := s.LineageID == uuid.Nil || capability.LineageID == s.LineageID
	return capability.PrincipalID == s.PrincipalID && capability.CredentialID == s.CredentialID &&
		lineageMatches && capability.RevocationGeneration == s.RevocationGeneration &&
		now.Before(s.ExpiresAt) && now.Before(capability.ExpiresAt)
}

// SessionRegistry bounds active stream registrations and makes revocation
// disconnect decisions independent of stream activity. Unregister is safe to
// call from every exit path, including cancellation and handshake failure.
type SessionRegistry struct {
	mu               sync.Mutex
	max              int
	sessions         map[string]sessionEntry
	credentialFences map[uuid.UUID]uint64
	principalFences  map[uuid.UUID]uint64
	epoch            uint64
}

type sessionEntry struct {
	state  RevocationState
	cancel context.CancelFunc
}

var ErrSessionLimit = errors.New("auth: machine session limit reached")

func NewSessionRegistry(max int) *SessionRegistry {
	if max < 1 {
		max = 1
	}
	return &SessionRegistry{max: max, sessions: make(map[string]sessionEntry), credentialFences: make(map[uuid.UUID]uint64), principalFences: make(map[uuid.UUID]uint64)}
}

func (r *SessionRegistry) Register(id string, state RevocationState) error {
	return r.register(id, state, nil)
}

// RegisterWithCancel associates a stream cancellation callback with the
// bounded registration. Revocation removes the registration and invokes the
// callback outside the registry lock so active transports can terminate
// without blocking other registrations.
func (r *SessionRegistry) RegisterWithCancel(id string, state RevocationState, cancel context.CancelFunc) error {
	return r.register(id, state, cancel)
}

// CurrentEpoch and RegisterWithCancelEpoch fence the verify/register race:
// an invalidation that wins between durable verification and registration
// makes the stale registration fail closed.
func (r *SessionRegistry) CurrentEpoch() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.epoch
}

func (r *SessionRegistry) RegisterWithCancelEpoch(id string, state RevocationState, cancel context.CancelFunc, epoch uint64) error {
	if r == nil {
		return ErrMachineCapabilityDenied
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registerLocked(id, state, cancel, epoch)
}

func (r *SessionRegistry) register(id string, state RevocationState, cancel context.CancelFunc) error {
	if r == nil || id == "" || state.PrincipalID == uuid.Nil || state.CredentialID == uuid.Nil {
		return ErrMachineCapabilityDenied
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registerLocked(id, state, cancel, r.epoch)
}

func (r *SessionRegistry) registerLocked(id string, state RevocationState, cancel context.CancelFunc, epoch uint64) error {
	if epoch != r.epoch {
		return ErrMachineCapabilityDenied
	}
	if fence := r.credentialFences[state.CredentialID]; fence >= state.RevocationGeneration {
		return ErrMachineCapabilityDenied
	}
	if fence := r.principalFences[state.PrincipalID]; fence >= state.RevocationGeneration {
		return ErrMachineCapabilityDenied
	}
	if _, exists := r.sessions[id]; !exists && len(r.sessions) >= r.max {
		return ErrSessionLimit
	}
	r.sessions[id] = sessionEntry{state: state, cancel: cancel}
	return nil
}

func (r *SessionRegistry) Unregister(id string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.sessions, id)
	r.mu.Unlock()
}

// Expire removes one capability session and cancels only that stream.  A
// child capability's expiry must not revoke sibling sessions issued from the
// same credential.
func (r *SessionRegistry) Expire(id string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	entry, ok := r.sessions[id]
	if ok {
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	if ok && entry.cancel != nil {
		entry.cancel()
	}
}

func (r *SessionRegistry) Allows(id string, capability MachineCapability, now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	entry, ok := r.sessions[id]
	r.mu.Unlock()
	return ok && entry.state.Allows(capability, now)
}

func (r *SessionRegistry) RevokeCredential(credentialID uuid.UUID, generation uint64) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	r.epoch++
	if generation > r.credentialFences[credentialID] {
		r.credentialFences[credentialID] = generation
	}
	if len(r.credentialFences)+len(r.principalFences) > 4096 {
		// Fence retention is bounded, while the epoch makes every verification
		// that began before this compaction fail registration. A fresh authority
		// lookup is therefore required before an old generation can re-enter.
		r.epoch++
		r.credentialFences = make(map[uuid.UUID]uint64)
		r.principalFences = make(map[uuid.UUID]uint64)
	}
	removed := 0
	var cancels []context.CancelFunc
	for id, entry := range r.sessions {
		if entry.state.CredentialID == credentialID && entry.state.RevocationGeneration <= generation {
			delete(r.sessions, id)
			if entry.cancel != nil {
				cancels = append(cancels, entry.cancel)
			}
			removed++
		}
	}
	r.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return removed
}

func (r *SessionRegistry) RevokePrincipal(principalID uuid.UUID, generation uint64) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	r.epoch++
	if generation > r.principalFences[principalID] {
		r.principalFences[principalID] = generation
	}
	if len(r.credentialFences)+len(r.principalFences) > 4096 {
		r.epoch++
		r.credentialFences = make(map[uuid.UUID]uint64)
		r.principalFences = make(map[uuid.UUID]uint64)
	}
	removed := 0
	var cancels []context.CancelFunc
	for id, entry := range r.sessions {
		if entry.state.PrincipalID == principalID && entry.state.RevocationGeneration <= generation {
			delete(r.sessions, id)
			if entry.cancel != nil {
				cancels = append(cancels, entry.cancel)
			}
			removed++
		}
	}
	r.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return removed
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
	if err := ownership.Validate(); err != nil || ownership.SandboxID != sandboxID || ownership.OwnerPrincipalID != caller.PrincipalID || ownership.TeamID != caller.TeamID || audience == "" || audience != caller.Audience && !slices.Contains(caller.AllowedAudiences, audience) || len(operations) == 0 || sandboxID == uuid.Nil {
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
		TeamID: caller.TeamID, SandboxID: sandboxID, Operations: slices.Clone(operations), Audience: audience,
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

// OperationForHTTP maps only the hosted-QM sandbox surface. Returning false
// for an unknown route is intentional: adding an endpoint must not silently
// grant machine authority.
func OperationForHTTP(method, path string) (MachineOperation, bool) {
	method = strings.ToUpper(method)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] == "sandboxes" {
		switch method {
		case "POST":
			return MachineOperationCreate, true
		case "GET":
			return MachineOperationList, true
		}
	}
	if len(parts) < 2 || parts[0] != "sandboxes" {
		return "", false
	}
	switch {
	case len(parts) == 2 && method == "GET":
		return MachineOperationRead, true
	case len(parts) == 2 && method == "PATCH":
		return MachineOperationPatch, true
	case len(parts) == 2 && method == "DELETE":
		return MachineOperationDelete, true
	case len(parts) == 3 && method == "POST":
		switch parts[2] {
		case "pause":
			return MachineOperationPause, true
		case "resume":
			return MachineOperationResume, true
		case "activate":
			return MachineOperationActivate, true
		case "preview-ports":
			return MachineOperationMetadata, true
		}
	case method == "POST" && len(parts) >= 5 && parts[2] == "preview-ports" && parts[len(parts)-1] == "token":
		return MachineOperationToken, true
	case method == "POST" && len(parts) >= 6 && parts[2] == "preview-ports" && parts[len(parts)-1] == "rotate":
		return MachineOperationToken, true
	case len(parts) == 3 && method == "GET" && parts[2] == "files":
		return MachineOperationFileList, true
	}
	return "", false
}

// ValidateMachineCreate rejects indirect authority sources before any
// privileged snapshot, template, or secret lookup occurs.
func ValidateMachineCreate(caller CallerContext, templateID *uuid.UUID, snapshotID *uuid.UUID, secretBindings int) error {
	if caller.ValidateAt(time.Now()) != nil || !caller.Policy.Allows(MachineOperationCreate) {
		return ErrMachineCapabilityDenied
	}
	if snapshotID != nil || secretBindings != 0 || caller.ApprovedTemplateID == nil || templateID == nil || *templateID != *caller.ApprovedTemplateID {
		return ErrMachineCapabilityDenied
	}
	return nil
}

func isTeamDesktopOperation(operation MachineOperation) bool {
	return operation == TeamOperationDesktopRead || operation == TeamOperationDesktopWrite
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

// FencedPrincipalLifecycle is the production form of the handoff. The
// expected generation and operation identity fence issuance and principal
// transitions; callers may not replay a completed transition against a
// newer disable/restore generation.
type FencedPrincipalLifecycle interface {
	PrincipalLifecycle
	IssueCredentialFenced(context.Context, uuid.UUID, string, int64, uuid.UUID) (MachineCredential, error)
	RotateCredentialFenced(context.Context, uuid.UUID, uuid.UUID, string, int64, uuid.UUID) (MachineCredential, error)
	RestorePrincipalFenced(context.Context, uuid.UUID, string, int64, uuid.UUID) (MachineCredential, error)
	DisablePrincipalFenced(context.Context, uuid.UUID, int64, uuid.UUID) error
}
