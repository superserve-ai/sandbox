package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
)

type controlPlaneActorKey struct{}

// WithControlPlaneAuthorization marks a context created by an authenticated
// provisioning/control-plane caller. Runtime machine credentials never carry
// this marker and therefore cannot administer their own authority.
func WithControlPlaneAuthorization(ctx context.Context) context.Context {
	return context.WithValue(ctx, controlPlaneActorKey{}, true)
}

func authorizedControlPlane(ctx context.Context) bool {
	v, _ := ctx.Value(controlPlaneActorKey{}).(bool)
	return v
}

// DBMachineAuthority is the concrete sandbox-side authority adapter. Secret
// payloads are hashed at the boundary and only the digest is compared in the
// durable store; callers receive verified identity, never stored secret data.
type DBMachineAuthority struct {
	Queries     *db.Queries
	Now         func() time.Time
	enabled     atomic.Bool
	eligibility atomic.Value // AuthorityEligibility
}

// AuthorityEligibility is the explicit, fail-closed activation input. Schema
// presence alone never enables authority-producing writes.
type AuthorityEligibility struct {
	ContractRevision      string
	Environment           string
	ConfiguredEnvironment string
	SchemaReady           bool
	OwnershipReady        bool
	VerifierReady         bool
	OperatorReady         bool
}

func (e AuthorityEligibility) Valid() bool {
	return e.ContractRevision == "machine-identity-v1" && e.Environment != "" && e.ConfiguredEnvironment != "" && e.Environment == e.ConfiguredEnvironment && e.SchemaReady && e.OwnershipReady && e.VerifierReady && e.OperatorReady
}

var ErrMachineAuthorityUnavailable = errors.New("machine authority unavailable")

func NewDBMachineAuthority(queries *db.Queries) *DBMachineAuthority {
	return &DBMachineAuthority{Queries: queries, Now: time.Now}
}

func (a *DBMachineAuthority) Ready(ctx context.Context) error {
	if a == nil || a.Queries == nil {
		return errors.New("machine authority is not configured")
	}
	return a.Queries.MachineIdentityReady(ctx)
}

func (a *DBMachineAuthority) Enable() {
	if a != nil {
		a.enabled.Store(true)
	}
}

func (a *DBMachineAuthority) SetEligibility(eligibility AuthorityEligibility) {
	if a != nil {
		a.eligibility.Store(eligibility)
	}
}

func (a *DBMachineAuthority) IssuanceReady() bool {
	if a == nil {
		return false
	}
	v := a.eligibility.Load()
	if v == nil {
		return false
	}
	return v.(AuthorityEligibility).Valid()
}

func (a *DBMachineAuthority) requireIssuanceReady() error {
	if !a.enabled.Load() || !a.IssuanceReady() {
		return ErrMachineAuthorityUnavailable
	}
	return nil
}
func (a *DBMachineAuthority) Disable() {
	if a != nil {
		a.enabled.Store(false)
	}
}

func (a *DBMachineAuthority) ResolveMachineCredential(ctx context.Context, raw string) (auth.CallerContext, error) {
	if a == nil || a.Queries == nil {
		return auth.CallerContext{}, ErrMachineAuthorityUnavailable
	}
	if !a.enabled.Load() {
		return auth.CallerContext{}, ErrMachineAuthorityUnavailable
	}
	if strings.TrimSpace(raw) == "" {
		return auth.CallerContext{}, auth.ErrInvalidMachineIdentity
	}
	// A delayed pre-revocation observation cannot authorize a request after
	// the freshness bound, even if the store ignores cancellation.
	lookupDeadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, lookupDeadline)
	defer cancel()
	digest := sha256.Sum256([]byte(raw))
	row, err := a.Queries.LookupMachineCredentialByHash(ctx, digest[:])
	if ctx.Err() != nil || !time.Now().Before(lookupDeadline) {
		return auth.CallerContext{}, ErrMachineAuthorityUnavailable
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.CallerContext{}, auth.ErrInvalidMachineIdentity
	}
	if err != nil {
		return auth.CallerContext{}, errors.Join(ErrMachineAuthorityUnavailable, err)
	}
	permissions := make([]auth.MachineOperation, 0, len(row.Credential.Permissions))
	for _, rawPermission := range row.Credential.Permissions {
		operation := auth.MachineOperation(rawPermission)
		if !auth.NewMachinePolicy(operation).Allows(operation) {
			return auth.CallerContext{}, auth.ErrInvalidMachineIdentity
		}
		permissions = append(permissions, operation)
	}
	var approved *uuid.UUID
	if row.Principal.ApprovedTemplateID.Valid {
		value := row.Principal.ApprovedTemplateID.Bytes
		id := uuid.UUID(value)
		approved = &id
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	caller := auth.CallerContext{
		PrincipalID: row.Principal.ID, CredentialID: row.Credential.ID,
		LineageID: row.Credential.LineageID, TeamID: row.Principal.TeamID,
		HostedTenantID: row.Principal.HostedTenantID, Permissions: permissions,
		Policy: auth.NewMachinePolicy(permissions...), Audience: row.Credential.Audience,
		AllowedAudiences: trustedChildAudiences(row.Credential.Audience),
		ExpiresAt:        row.Credential.ExpiresAt, RevocationGeneration: uint64(row.Credential.RevocationGeneration),
		ApprovedTemplateID: approved,
	}
	if err := caller.ValidateAt(now); err != nil {
		return auth.CallerContext{}, err
	}
	return caller, nil
}

func trustedChildAudiences(root string) []string {
	switch root {
	case "sandbox-api":
		return []string{"sandbox-api", "sandbox-proxy"}
	case "sandbox-proxy":
		return []string{"sandbox-proxy"}
	default:
		return nil
	}
}

func trustedMachineOperations() []string {
	return []string{
		string(auth.MachineOperationCreate), string(auth.MachineOperationList), string(auth.MachineOperationRead),
		string(auth.MachineOperationPause), string(auth.MachineOperationResume), string(auth.MachineOperationActivate),
		string(auth.MachineOperationDelete), string(auth.MachineOperationPatch), string(auth.MachineOperationReconnect),
		string(auth.MachineOperationCommandRun), string(auth.MachineOperationCommandRead), string(auth.MachineOperationCommandWrite),
		string(auth.MachineOperationCommandSignal), string(auth.MachineOperationFileRead), string(auth.MachineOperationFileWrite),
		string(auth.MachineOperationFileList),
	}
}

func lifecycleLineage(operationID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(uuid.Nil, []byte("machine-lineage:"+operationID.String()))
}

func lifecycleExpiry(now time.Time) time.Time {
	return now.Add(24 * time.Hour)
}

func (a *DBMachineAuthority) EnsurePrincipal(ctx context.Context, teamID, tenantID, templateID uuid.UUID, _ string) (auth.MachinePrincipal, error) {
	if !authorizedControlPlane(ctx) {
		return auth.MachinePrincipal{}, auth.ErrMachineCapabilityDenied
	}
	if err := a.requireIssuanceReady(); err != nil {
		return auth.MachinePrincipal{}, err
	}
	row, err := a.Queries.EnsureMachinePrincipal(ctx, teamID, tenantID, uuidToPG(templateID))
	if err != nil {
		return auth.MachinePrincipal{}, err
	}
	return auth.MachinePrincipal{PrincipalID: row.ID, TeamID: row.TeamID, HostedTenantID: row.HostedTenantID, Status: auth.PrincipalStatus(row.Status), Generation: uint64(row.Generation)}, nil
}

func (a *DBMachineAuthority) IssueCredential(_ context.Context, _ uuid.UUID, _ string) (auth.MachineCredential, error) {
	return auth.MachineCredential{}, fmt.Errorf("machine credential issuance requires an explicit generation and operation fence")
}

func (a *DBMachineAuthority) IssueCredentialFenced(ctx context.Context, principalID uuid.UUID, rawSecret string, expectedGeneration int64, operationID uuid.UUID) (auth.MachineCredential, error) {
	if !authorizedControlPlane(ctx) {
		return auth.MachineCredential{}, auth.ErrMachineCapabilityDenied
	}
	if err := a.requireIssuanceReady(); err != nil {
		return auth.MachineCredential{}, err
	}
	digest := sha256.Sum256([]byte(rawSecret))
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	row, err := a.Queries.IssueMachineCredentialFenced(ctx, principalID, lifecycleLineage(operationID), digest[:], lifecycleExpiry(now), trustedMachineOperations(), "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &expectedGeneration, OperationID: operationID, GeneratedExpiry: true})
	if err != nil {
		return auth.MachineCredential{}, err
	}
	return auth.MachineCredential{CredentialID: row.ID, PrincipalID: row.PrincipalID, LineageID: row.LineageID, State: auth.CredentialState(row.State), ExpiresAt: row.ExpiresAt, RevocationGeneration: uint64(row.RevocationGeneration)}, nil
}

func (a *DBMachineAuthority) RotateCredential(context.Context, uuid.UUID, string) (auth.MachineCredential, error) {
	return auth.MachineCredential{}, fmt.Errorf("machine credential rotation requires an explicit replacement credential fence")
}

func (a *DBMachineAuthority) RotateCredentialFenced(ctx context.Context, principalID, replacementID uuid.UUID, rawSecret string, expectedGeneration int64, operationID uuid.UUID) (auth.MachineCredential, error) {
	if !authorizedControlPlane(ctx) {
		return auth.MachineCredential{}, auth.ErrMachineCapabilityDenied
	}
	if err := a.requireIssuanceReady(); err != nil {
		return auth.MachineCredential{}, err
	}
	digest := sha256.Sum256([]byte(rawSecret))
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	row, err := a.Queries.RotateMachineCredentialTargeted(ctx, principalID, replacementID, lifecycleLineage(operationID), digest[:], lifecycleExpiry(now), trustedMachineOperations(), "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &expectedGeneration, OperationID: operationID, GeneratedExpiry: true})
	if err != nil {
		return auth.MachineCredential{}, err
	}
	return auth.MachineCredential{CredentialID: row.ID, PrincipalID: row.PrincipalID, LineageID: row.LineageID, State: auth.CredentialState(row.State), ExpiresAt: row.ExpiresAt, RevocationGeneration: uint64(row.RevocationGeneration)}, nil
}

func (a *DBMachineAuthority) RevokeCredential(ctx context.Context, credentialID uuid.UUID, _ string) error {
	if !authorizedControlPlane(ctx) {
		return auth.ErrMachineCapabilityDenied
	}
	return a.Queries.RevokeMachineCredential(ctx, credentialID)
}

func (a *DBMachineAuthority) DisablePrincipal(ctx context.Context, principalID uuid.UUID, _ string) error {
	return fmt.Errorf("machine disable requires an explicit generation and operation fence")
}

func (a *DBMachineAuthority) DisablePrincipalFenced(ctx context.Context, principalID uuid.UUID, expectedGeneration int64, operationID uuid.UUID) error {
	if !authorizedControlPlane(ctx) {
		return auth.ErrMachineCapabilityDenied
	}
	if a == nil || a.Queries == nil {
		return ErrMachineAuthorityUnavailable
	}
	return a.Queries.DisableMachinePrincipalFenced(ctx, principalID, db.LifecycleOptions{ExpectedGeneration: &expectedGeneration, OperationID: operationID})
}

func (a *DBMachineAuthority) RestorePrincipal(_ context.Context, _ uuid.UUID, _ string) (auth.MachineCredential, error) {
	return auth.MachineCredential{}, fmt.Errorf("machine restore requires an explicit generation and operation fence")
}

func (a *DBMachineAuthority) RestorePrincipalFenced(ctx context.Context, principalID uuid.UUID, rawSecret string, expectedGeneration int64, operationID uuid.UUID) (auth.MachineCredential, error) {
	if !authorizedControlPlane(ctx) {
		return auth.MachineCredential{}, auth.ErrMachineCapabilityDenied
	}
	if err := a.requireIssuanceReady(); err != nil {
		return auth.MachineCredential{}, err
	}
	digest := sha256.Sum256([]byte(rawSecret))
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	row, err := a.Queries.RestoreMachineCredentialFenced(ctx, principalID, lifecycleLineage(operationID), digest[:], lifecycleExpiry(now), trustedMachineOperations(), "sandbox-api", db.LifecycleOptions{ExpectedGeneration: &expectedGeneration, OperationID: operationID, GeneratedExpiry: true})
	if err != nil {
		return auth.MachineCredential{}, err
	}
	return auth.MachineCredential{CredentialID: row.ID, PrincipalID: row.PrincipalID, LineageID: row.LineageID, State: auth.CredentialState(row.State), ExpiresAt: row.ExpiresAt, RevocationGeneration: uint64(row.RevocationGeneration)}, nil
}

func uuidToPG(id uuid.UUID) (out pgtype.UUID) {
	out.Bytes = id
	out.Valid = id != uuid.Nil
	return out
}

var _ MachineCredentialResolver = (*DBMachineAuthority)(nil)
var _ auth.PrincipalLifecycle = (*DBMachineAuthority)(nil)
var _ auth.FencedPrincipalLifecycle = (*DBMachineAuthority)(nil)
