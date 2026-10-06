package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// MachinePrincipalRow and MachineCredentialRow contain only durable identity
// references. Secret material is intentionally absent from these types.
type MachinePrincipalRow struct {
	ID                 uuid.UUID
	TeamID             uuid.UUID
	HostedTenantID     uuid.UUID
	Status             string
	Generation         int64
	ApprovedTemplateID pgtype.UUID
	RestoreUntil       pgtype.Timestamptz
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type MachineCredentialRow struct {
	ID                   uuid.UUID
	PrincipalID          uuid.UUID
	LineageID            uuid.UUID
	State                string
	ExpiresAt            time.Time
	RevocationGeneration int64
	Permissions          []string
	Audience             string
	IssuedAt             time.Time
	RevokedAt            pgtype.Timestamptz
	SecretHash           []byte
}

// LifecycleOptions are caller-supplied fences for mutating authority. An
// expected generation prevents a delayed retry from applying to a newer
// lifecycle transition; operation IDs make response-loss retries idempotent.
type LifecycleOptions struct {
	ExpectedGeneration      *int64
	OperationID             uuid.UUID
	ReplacementCredentialID *uuid.UUID
}

func requireLifecycleFence(options []LifecycleOptions) (LifecycleOptions, error) {
	if len(options) != 1 || options[0].ExpectedGeneration == nil || *options[0].ExpectedGeneration <= 0 || options[0].OperationID == uuid.Nil {
		return LifecycleOptions{}, fmt.Errorf("machine lifecycle requires expected generation and operation id")
	}
	return options[0], nil
}

type MachineSandboxOwnerRow struct {
	SandboxID        uuid.UUID
	OwnerPrincipalID uuid.UUID
	TeamID           uuid.UUID
}

func (q *Queries) MachineIdentityReady(ctx context.Context) error {
	var present bool
	if err := q.db.QueryRow(ctx, `SELECT to_regclass('public.machine_principal') IS NOT NULL`).Scan(&present); err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("machine identity schema is not installed")
	}
	return nil
}

func (q *Queries) ListMachineSandboxOwners(ctx context.Context, principalID, teamID uuid.UUID) ([]MachineSandboxOwnerRow, error) {
	rows, err := q.db.Query(ctx, `SELECT sandbox_id,owner_principal_id,team_id FROM sandbox_machine_owner WHERE owner_principal_id=$1 AND team_id=$2 ORDER BY sandbox_id`, principalID, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	owners := make([]MachineSandboxOwnerRow, 0)
	for rows.Next() {
		var row MachineSandboxOwnerRow
		if err := rows.Scan(&row.SandboxID, &row.OwnerPrincipalID, &row.TeamID); err != nil {
			return nil, err
		}
		owners = append(owners, row)
	}
	return owners, rows.Err()
}

func (q *Queries) EnsureMachinePrincipal(ctx context.Context, teamID, hostedTenantID uuid.UUID, templateID pgtype.UUID) (MachinePrincipalRow, error) {
	var row MachinePrincipalRow
	err := q.db.QueryRow(ctx, `SELECT id, team_id, hosted_tenant_id, status, generation, approved_template_id, restore_until, created_at, updated_at FROM ensure_machine_principal($1,$2,$3)`, teamID, hostedTenantID, templateID).Scan(
		&row.ID, &row.TeamID, &row.HostedTenantID, &row.Status, &row.Generation, &row.ApprovedTemplateID, &row.RestoreUntil, &row.CreatedAt, &row.UpdatedAt)
	return row, err
}

func (q *Queries) GetMachinePrincipal(ctx context.Context, id uuid.UUID) (MachinePrincipalRow, error) {
	var row MachinePrincipalRow
	err := q.db.QueryRow(ctx, `SELECT id, team_id, hosted_tenant_id, status, generation, approved_template_id, restore_until, created_at, updated_at FROM machine_principal WHERE id=$1`, id).Scan(
		&row.ID, &row.TeamID, &row.HostedTenantID, &row.Status, &row.Generation, &row.ApprovedTemplateID, &row.RestoreUntil, &row.CreatedAt, &row.UpdatedAt)
	return row, err
}

func (q *Queries) IssueMachineCredential(ctx context.Context, principalID, lineageID uuid.UUID, expiresAt time.Time, permissions []string, audience string) (MachineCredentialRow, error) {
	var row MachineCredentialRow
	err := q.db.QueryRow(ctx, `INSERT INTO machine_credential(principal_id,lineage_id,expires_at,revocation_generation,permissions,audience) SELECT id,$2,$3,generation,$4,$5 FROM machine_principal WHERE id=$1 AND status='active' RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at`, principalID, lineageID, expiresAt, permissions, audience).Scan(
		&row.ID, &row.PrincipalID, &row.LineageID, &row.State, &row.ExpiresAt, &row.RevocationGeneration, &row.Permissions, &row.Audience, &row.IssuedAt, &row.RevokedAt)
	return row, err
}

// IssueMachineCredentialFenced serializes issuance with principal lifecycle
// transitions and records the operation key before returning the credential.
func (q *Queries) IssueMachineCredentialFenced(ctx context.Context, principalID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, options LifecycleOptions) (MachineCredentialRow, error) {
	var row MachineCredentialRow
	err := q.db.QueryRow(ctx, `WITH principal AS (SELECT id,generation FROM machine_principal WHERE id=$1 AND status='active' AND generation=$2 FOR UPDATE), op AS (INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation) SELECT id,$3,'issue',generation FROM principal ON CONFLICT (principal_id,operation_id) DO UPDATE SET operation_id=EXCLUDED.operation_id RETURNING principal_id), issued AS (INSERT INTO machine_credential(principal_id,lineage_id,secret_hash,expires_at,revocation_generation,permissions,audience) SELECT id,$4,$5,$6,generation,$7,$8 FROM principal RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at,secret_hash) SELECT * FROM issued`, principalID, *options.ExpectedGeneration, options.OperationID, lineageID, secretHash, expiresAt, permissions, audience).Scan(
		&row.ID, &row.PrincipalID, &row.LineageID, &row.State, &row.ExpiresAt, &row.RevocationGeneration, &row.Permissions, &row.Audience, &row.IssuedAt, &row.RevokedAt, &row.SecretHash)
	return row, err
}

// RotateMachineCredential fences replacement and issuance in one statement;
// the principal generation is preserved while the old credential is revoked.
func (q *Queries) RotateMachineCredential(ctx context.Context, principalID, lineageID uuid.UUID, expiresAt time.Time, permissions []string, audience string) (MachineCredentialRow, error) {
	return q.RotateMachineCredentialTargeted(ctx, principalID, uuid.Nil, lineageID, nil, expiresAt, permissions, audience, LifecycleOptions{})
}

// RotateMachineCredentialTargeted revokes only the explicitly replaced
// credential. Principal-wide invalidation remains the disable operation.
func (q *Queries) RotateMachineCredentialTargeted(ctx context.Context, principalID, replacementID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, options LifecycleOptions) (MachineCredentialRow, error) {
	var row MachineCredentialRow
	if options.ExpectedGeneration == nil || options.OperationID == uuid.Nil || replacementID == uuid.Nil {
		return row, fmt.Errorf("machine credential rotation requires replacement credential and lifecycle fence")
	}
	err := q.db.QueryRow(ctx, `WITH principal AS (SELECT id,generation FROM machine_principal WHERE id=$1 AND status='active' AND generation=$2 FOR UPDATE), op AS (INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation) SELECT id,$3,'rotate',generation FROM principal ON CONFLICT (principal_id,operation_id) DO UPDATE SET operation_id=EXCLUDED.operation_id), revoked AS (UPDATE machine_credential SET state='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE id=$4 AND principal_id=$1 AND state='active'), issued AS (INSERT INTO machine_credential(principal_id,lineage_id,secret_hash,expires_at,revocation_generation,permissions,audience) SELECT id,$5,$6,$7,generation,$8,$9 FROM principal RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at,secret_hash) SELECT * FROM issued`, principalID, *options.ExpectedGeneration, options.OperationID, replacementID, lineageID, secretHash, expiresAt, permissions, audience).Scan(
		&row.ID, &row.PrincipalID, &row.LineageID, &row.State, &row.ExpiresAt, &row.RevocationGeneration, &row.Permissions, &row.Audience, &row.IssuedAt, &row.RevokedAt, &row.SecretHash)
	return row, err
}

func (q *Queries) RevokeMachineCredential(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `UPDATE machine_credential SET state='revoked', revoked_at=COALESCE(revoked_at,now()) WHERE id=$1 AND state='active'`, id)
	return err
}

func (q *Queries) DisableMachinePrincipal(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `WITH disabled AS (UPDATE machine_principal SET status='disabled',generation=generation+1,restore_until=now()+interval '7 days',updated_at=now() WHERE id=$1 AND status='active' RETURNING id) UPDATE machine_credential SET state='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE principal_id IN (SELECT id FROM disabled) AND state='active'`, id)
	return err
}

func (q *Queries) RestoreMachinePrincipal(ctx context.Context, id uuid.UUID, options ...LifecycleOptions) error {
	fence, err := requireLifecycleFence(options)
	if err != nil {
		return err
	}
	_, err = q.db.Exec(ctx, `WITH op AS (INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation) VALUES($1,$3,'restore',$2) ON CONFLICT (principal_id,operation_id) DO NOTHING) UPDATE machine_principal SET status='active',generation=generation+1,restore_until=NULL,updated_at=now() WHERE id=$1 AND status='disabled' AND generation=$2 AND restore_until > now()`, id, *fence.ExpectedGeneration, fence.OperationID)
	return err
}

func (q *Queries) RestoreMachineCredential(ctx context.Context, principalID, lineageID uuid.UUID, expiresAt time.Time, permissions []string, audience string, options ...LifecycleOptions) (MachineCredentialRow, error) {
	return q.RestoreMachineCredentialFenced(ctx, principalID, lineageID, nil, expiresAt, permissions, audience, options...)
}

func (q *Queries) RestoreMachineCredentialFenced(ctx context.Context, principalID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, options ...LifecycleOptions) (MachineCredentialRow, error) {
	var row MachineCredentialRow
	fence, err := requireLifecycleFence(options)
	if err != nil {
		return row, err
	}
	err = q.db.QueryRow(ctx, `WITH restored AS (UPDATE machine_principal SET status='active',generation=generation+1,restore_until=NULL,updated_at=now() WHERE id=$1 AND status='disabled' AND generation=$2 AND restore_until IS NOT NULL AND restore_until > now() RETURNING id,generation), op AS (INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation) SELECT id,$3,'restore',$2 FROM restored ON CONFLICT (principal_id,operation_id) DO UPDATE SET operation_id=EXCLUDED.operation_id), issued AS (INSERT INTO machine_credential(principal_id,lineage_id,secret_hash,expires_at,revocation_generation,permissions,audience) SELECT id,$4,$5,$6,generation,$7,$8 FROM restored RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at,secret_hash) SELECT * FROM issued`, principalID, *fence.ExpectedGeneration, fence.OperationID, lineageID, secretHash, expiresAt, permissions, audience).Scan(
		&row.ID, &row.PrincipalID, &row.LineageID, &row.State, &row.ExpiresAt, &row.RevocationGeneration, &row.Permissions, &row.Audience, &row.IssuedAt, &row.RevokedAt, &row.SecretHash)
	return row, err
}

type MachineCredentialLookupRow struct {
	Credential MachineCredentialRow
	Principal  MachinePrincipalRow
}

// LookupMachineCredentialByHash is the only serving lookup. It returns active,
// unexpired credentials whose generation still matches the active principal;
// revoked, disabled, expired, or stale rows are indistinguishable from a miss.
func (q *Queries) LookupMachineCredentialByHash(ctx context.Context, secretHash []byte) (MachineCredentialLookupRow, error) {
	var out MachineCredentialLookupRow
	err := q.db.QueryRow(ctx, `SELECT c.id,c.principal_id,c.lineage_id,c.state,c.expires_at,c.revocation_generation,c.permissions,c.audience,c.issued_at,c.revoked_at,c.secret_hash,p.id,p.team_id,p.hosted_tenant_id,p.status,p.generation,p.approved_template_id,p.restore_until,p.created_at,p.updated_at FROM machine_credential c JOIN machine_principal p ON p.id=c.principal_id WHERE c.secret_hash=$1 AND c.state='active' AND c.expires_at>now() AND p.status='active' AND c.revocation_generation=p.generation`, secretHash).Scan(
		&out.Credential.ID, &out.Credential.PrincipalID, &out.Credential.LineageID, &out.Credential.State, &out.Credential.ExpiresAt, &out.Credential.RevocationGeneration, &out.Credential.Permissions, &out.Credential.Audience, &out.Credential.IssuedAt, &out.Credential.RevokedAt, &out.Credential.SecretHash,
		&out.Principal.ID, &out.Principal.TeamID, &out.Principal.HostedTenantID, &out.Principal.Status, &out.Principal.Generation, &out.Principal.ApprovedTemplateID, &out.Principal.RestoreUntil, &out.Principal.CreatedAt, &out.Principal.UpdatedAt)
	return out, err
}

func (q *Queries) CreateMachineSandboxOwner(ctx context.Context, sandboxID, principalID, teamID uuid.UUID) error {
	result, err := q.db.Exec(ctx, `INSERT INTO sandbox_machine_owner(sandbox_id,owner_principal_id,team_id) VALUES($1,$2,$3) ON CONFLICT(sandbox_id) DO UPDATE SET owner_principal_id=sandbox_machine_owner.owner_principal_id, team_id=sandbox_machine_owner.team_id WHERE sandbox_machine_owner.owner_principal_id=EXCLUDED.owner_principal_id AND sandbox_machine_owner.team_id=EXCLUDED.team_id`, sandboxID, principalID, teamID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("machine sandbox ownership conflict for %s", sandboxID)
	}
	return nil
}

func (q *Queries) GetMachineSandboxOwner(ctx context.Context, sandboxID, teamID uuid.UUID) (MachineSandboxOwnerRow, error) {
	var row MachineSandboxOwnerRow
	err := q.db.QueryRow(ctx, `SELECT sandbox_id,owner_principal_id,team_id FROM sandbox_machine_owner WHERE sandbox_id=$1 AND team_id=$2`, sandboxID, teamID).Scan(&row.SandboxID, &row.OwnerPrincipalID, &row.TeamID)
	return row, err
}
