package db

import (
	"context"
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
}

type MachineSandboxOwnerRow struct {
	SandboxID        uuid.UUID
	OwnerPrincipalID uuid.UUID
	TeamID           uuid.UUID
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

// RotateMachineCredential fences replacement and issuance in one statement;
// the principal generation is preserved while the old credential is revoked.
func (q *Queries) RotateMachineCredential(ctx context.Context, principalID, lineageID uuid.UUID, expiresAt time.Time, permissions []string, audience string) (MachineCredentialRow, error) {
	var row MachineCredentialRow
	err := q.db.QueryRow(ctx, `WITH principal AS (SELECT id,generation FROM machine_principal WHERE id=$1 AND status='active' FOR UPDATE), revoked AS (UPDATE machine_credential SET state='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE principal_id=$1 AND state='active' RETURNING id), issued AS (INSERT INTO machine_credential(principal_id,lineage_id,expires_at,revocation_generation,permissions,audience) SELECT id,$2,$3,generation,$4,$5 FROM principal RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at) SELECT * FROM issued`, principalID, lineageID, expiresAt, permissions, audience).Scan(
		&row.ID, &row.PrincipalID, &row.LineageID, &row.State, &row.ExpiresAt, &row.RevocationGeneration, &row.Permissions, &row.Audience, &row.IssuedAt, &row.RevokedAt)
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

func (q *Queries) RestoreMachinePrincipal(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `UPDATE machine_principal SET status='active',generation=generation+1,restore_until=NULL,updated_at=now() WHERE id=$1 AND status='disabled' AND restore_until > now()`, id)
	return err
}

func (q *Queries) RestoreMachineCredential(ctx context.Context, principalID, lineageID uuid.UUID, expiresAt time.Time, permissions []string, audience string) (MachineCredentialRow, error) {
	var row MachineCredentialRow
	err := q.db.QueryRow(ctx, `WITH restored AS (UPDATE machine_principal SET status='active',generation=generation+1,updated_at=now() WHERE id=$1 AND status='disabled' RETURNING id,generation), issued AS (INSERT INTO machine_credential(principal_id,lineage_id,expires_at,revocation_generation,permissions,audience) SELECT id,$2,$3,generation,$4,$5 FROM restored RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at) SELECT * FROM issued`, principalID, lineageID, expiresAt, permissions, audience).Scan(
		&row.ID, &row.PrincipalID, &row.LineageID, &row.State, &row.ExpiresAt, &row.RevocationGeneration, &row.Permissions, &row.Audience, &row.IssuedAt, &row.RevokedAt)
	return row, err
}

func (q *Queries) CreateMachineSandboxOwner(ctx context.Context, sandboxID, principalID, teamID uuid.UUID) error {
	_, err := q.db.Exec(ctx, `INSERT INTO sandbox_machine_owner(sandbox_id,owner_principal_id,team_id) VALUES($1,$2,$3) ON CONFLICT(sandbox_id) DO UPDATE SET team_id=sandbox_machine_owner.team_id WHERE sandbox_machine_owner.owner_principal_id=EXCLUDED.owner_principal_id AND sandbox_machine_owner.team_id=EXCLUDED.team_id`, sandboxID, principalID, teamID)
	return err
}

func (q *Queries) GetMachineSandboxOwner(ctx context.Context, sandboxID, teamID uuid.UUID) (MachineSandboxOwnerRow, error) {
	var row MachineSandboxOwnerRow
	err := q.db.QueryRow(ctx, `SELECT sandbox_id,owner_principal_id,team_id FROM sandbox_machine_owner WHERE sandbox_id=$1 AND team_id=$2`, sandboxID, teamID).Scan(&row.SandboxID, &row.OwnerPrincipalID, &row.TeamID)
	return row, err
}
