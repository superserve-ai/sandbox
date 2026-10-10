package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

var ErrMachineLifecycleConflict = errors.New("machine lifecycle operation conflict")

func lifecycleInputDigest(kind string, principalID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, expectedGeneration int64, replacementID uuid.UUID, generatedExpiry bool) []byte {
	h := sha256.New()
	h.Write([]byte(kind))
	if generatedExpiry {
		h.Write([]byte{1})
		expiresAt = time.Time{}
	} else {
		h.Write([]byte{0})
	}
	h.Write(principalID[:])
	h.Write(lineageID[:])
	h.Write(secretHash)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(expectedGeneration))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(expiresAt.UnixNano()))
	h.Write(buf[:])
	h.Write([]byte(strings.Join(permissions, "\x00")))
	h.Write([]byte{0})
	h.Write([]byte(audience))
	h.Write(replacementID[:])
	return h.Sum(nil)
}

func scanMachineCredentialRow(row pgx.Row) (MachineCredentialRow, error) {
	var out MachineCredentialRow
	err := row.Scan(&out.ID, &out.PrincipalID, &out.LineageID, &out.State, &out.ExpiresAt, &out.RevocationGeneration, &out.Permissions, &out.Audience, &out.IssuedAt, &out.RevokedAt, &out.SecretHash)
	return out, err
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
	// GeneratedExpiry excludes the server-generated expiry from caller input identity.
	// Its first committed value is retained in the operation result on every retry.
	GeneratedExpiry bool
}

type lifecycleBeginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

func (q *Queries) beginLifecycle(ctx context.Context) (pgx.Tx, error) {
	b, ok := q.db.(lifecycleBeginner)
	if !ok {
		return nil, fmt.Errorf("machine lifecycle requires transaction support")
	}
	return b.Begin(ctx)
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
	return MachineCredentialRow{}, fmt.Errorf("machine credential issuance requires explicit lifecycle fence")
}

// IssueMachineCredentialFenced serializes issuance with principal lifecycle
// transitions and records the operation key before returning the credential.
func (q *Queries) IssueMachineCredentialFenced(ctx context.Context, principalID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, options LifecycleOptions) (MachineCredentialRow, error) {
	if options.ExpectedGeneration == nil || *options.ExpectedGeneration <= 0 || options.OperationID == uuid.Nil {
		return MachineCredentialRow{}, fmt.Errorf("machine credential issuance requires lifecycle fence")
	}
	digest := lifecycleInputDigest("issue", principalID, lineageID, secretHash, expiresAt, permissions, audience, *options.ExpectedGeneration, uuid.Nil, options.GeneratedExpiry)
	tx, err := q.beginLifecycle(ctx)
	if err != nil {
		return MachineCredentialRow{}, err
	}
	defer tx.Rollback(ctx)
	row, runErr := q.WithTx(tx).issueMachineCredentialTx(ctx, principalID, lineageID, secretHash, expiresAt, permissions, audience, options, digest)
	if runErr != nil {
		return MachineCredentialRow{}, runErr
	}
	if err := tx.Commit(ctx); err != nil {
		return MachineCredentialRow{}, err
	}
	return row, nil
}

func (q *Queries) issueMachineCredentialTx(ctx context.Context, principalID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, options LifecycleOptions, digest []byte) (MachineCredentialRow, error) {
	var generation int64
	var status string
	if err := q.db.QueryRow(ctx, `SELECT generation,status FROM machine_principal WHERE id=$1 FOR UPDATE`, principalID).Scan(&generation, &status); err != nil {
		return MachineCredentialRow{}, err
	}
	var existingID pgtype.UUID
	var existingDigest []byte
	err := q.db.QueryRow(ctx, `SELECT result_credential_id,input_digest FROM machine_lifecycle_operation WHERE principal_id=$1 AND operation_id=$2`, principalID, options.OperationID).Scan(&existingID, &existingDigest)
	if err == nil {
		if !bytes.Equal(existingDigest, digest) || !existingID.Valid {
			return MachineCredentialRow{}, ErrMachineLifecycleConflict
		}
		return q.machineCredentialByID(ctx, uuid.UUID(existingID.Bytes))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return MachineCredentialRow{}, err
	}
	if len(secretHash) == 0 {
		return MachineCredentialRow{}, fmt.Errorf("machine credential requires a secret digest")
	}
	if status != "active" || generation != *options.ExpectedGeneration {
		return MachineCredentialRow{}, pgx.ErrNoRows
	}
	if _, err := q.db.Exec(ctx, `INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation,input_digest,lineage_id,credential_digest,expires_at,permissions,audience) VALUES($1,$2,'issue',$3,$4,$5,$6,$7,$8,$9)`, principalID, options.OperationID, *options.ExpectedGeneration, digest, lineageID, secretHash, expiresAt, permissions, audience); err != nil {
		return MachineCredentialRow{}, err
	}
	row, err := scanMachineCredentialRow(q.db.QueryRow(ctx, `INSERT INTO machine_credential(principal_id,lineage_id,secret_hash,expires_at,revocation_generation,permissions,audience) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at,secret_hash`, principalID, lineageID, secretHash, expiresAt, generation, permissions, audience))
	if err != nil {
		return MachineCredentialRow{}, err
	}
	if _, err := q.db.Exec(ctx, `UPDATE machine_lifecycle_operation SET result_credential_id=$1 WHERE principal_id=$2 AND operation_id=$3`, row.ID, principalID, options.OperationID); err != nil {
		return MachineCredentialRow{}, err
	}
	return row, nil
}

func (q *Queries) machineCredentialByID(ctx context.Context, id uuid.UUID) (MachineCredentialRow, error) {
	return scanMachineCredentialRow(q.db.QueryRow(ctx, `SELECT id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at,secret_hash FROM machine_credential WHERE id=$1`, id))
}

// RotateMachineCredential requires explicit replacement and operation fences;
// the principal generation is preserved while the old credential is revoked.
func (q *Queries) RotateMachineCredential(ctx context.Context, principalID, lineageID uuid.UUID, expiresAt time.Time, permissions []string, audience string) (MachineCredentialRow, error) {
	return q.RotateMachineCredentialTargeted(ctx, principalID, uuid.Nil, lineageID, nil, expiresAt, permissions, audience, LifecycleOptions{})
}

// RotateMachineCredentialTargeted revokes only the explicitly replaced
// credential. Principal-wide invalidation remains the disable operation.
func (q *Queries) RotateMachineCredentialTargeted(ctx context.Context, principalID, replacementID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, options LifecycleOptions) (MachineCredentialRow, error) {
	var row MachineCredentialRow
	if options.ExpectedGeneration == nil || *options.ExpectedGeneration <= 0 || options.OperationID == uuid.Nil || replacementID == uuid.Nil {
		return row, fmt.Errorf("machine credential rotation requires replacement credential and lifecycle fence")
	}
	digest := lifecycleInputDigest("rotate", principalID, lineageID, secretHash, expiresAt, permissions, audience, *options.ExpectedGeneration, replacementID, options.GeneratedExpiry)
	tx, err := q.beginLifecycle(ctx)
	if err != nil {
		return MachineCredentialRow{}, err
	}
	defer tx.Rollback(ctx)
	row, runErr := q.WithTx(tx).rotateMachineCredentialTx(ctx, principalID, replacementID, lineageID, secretHash, expiresAt, permissions, audience, options, digest)
	if runErr != nil {
		return MachineCredentialRow{}, runErr
	}
	if err := tx.Commit(ctx); err != nil {
		return MachineCredentialRow{}, err
	}
	return row, nil
}

func (q *Queries) rotateMachineCredentialTx(ctx context.Context, principalID, replacementID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, options LifecycleOptions, digest []byte) (MachineCredentialRow, error) {
	var generation int64
	var status string
	if err := q.db.QueryRow(ctx, `SELECT generation,status FROM machine_principal WHERE id=$1 FOR UPDATE`, principalID).Scan(&generation, &status); err != nil {
		return MachineCredentialRow{}, err
	}
	var existingID pgtype.UUID
	var existingDigest []byte
	err := q.db.QueryRow(ctx, `SELECT result_credential_id,input_digest FROM machine_lifecycle_operation WHERE principal_id=$1 AND operation_id=$2`, principalID, options.OperationID).Scan(&existingID, &existingDigest)
	if err == nil {
		if !bytes.Equal(existingDigest, digest) || !existingID.Valid {
			return MachineCredentialRow{}, ErrMachineLifecycleConflict
		}
		return q.machineCredentialByID(ctx, uuid.UUID(existingID.Bytes))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return MachineCredentialRow{}, err
	}
	if len(secretHash) == 0 {
		return MachineCredentialRow{}, fmt.Errorf("machine credential requires a secret digest")
	}
	if status != "active" || generation != *options.ExpectedGeneration {
		return MachineCredentialRow{}, pgx.ErrNoRows
	}
	var replacementGeneration int64
	if err := q.db.QueryRow(ctx, `SELECT revocation_generation FROM machine_credential WHERE id=$1 AND principal_id=$2 AND state='active' AND revocation_generation=$3 FOR UPDATE`, replacementID, principalID, generation).Scan(&replacementGeneration); err != nil {
		return MachineCredentialRow{}, err
	}
	if _, err := q.db.Exec(ctx, `INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation,input_digest,lineage_id,credential_digest,replacement_credential_id,expires_at,permissions,audience) VALUES($1,$2,'rotate',$3,$4,$5,$6,$7,$8,$9,$10)`, principalID, options.OperationID, *options.ExpectedGeneration, digest, lineageID, secretHash, replacementID, expiresAt, permissions, audience); err != nil {
		return MachineCredentialRow{}, err
	}
	if _, err := q.db.Exec(ctx, `UPDATE machine_credential SET state='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE id=$1 AND state='active'`, replacementID); err != nil {
		return MachineCredentialRow{}, err
	}
	row, err := scanMachineCredentialRow(q.db.QueryRow(ctx, `INSERT INTO machine_credential(principal_id,lineage_id,secret_hash,expires_at,revocation_generation,permissions,audience) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at,secret_hash`, principalID, lineageID, secretHash, expiresAt, replacementGeneration, permissions, audience))
	if err != nil {
		return MachineCredentialRow{}, err
	}
	if _, err := q.db.Exec(ctx, `UPDATE machine_lifecycle_operation SET result_credential_id=$1 WHERE principal_id=$2 AND operation_id=$3`, row.ID, principalID, options.OperationID); err != nil {
		return MachineCredentialRow{}, err
	}
	return row, nil
}

func (q *Queries) RevokeMachineCredential(ctx context.Context, id uuid.UUID) error {
	tx, err := q.beginLifecycle(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var principalID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT p.id FROM machine_principal p JOIN machine_credential c ON c.principal_id=p.id WHERE c.id=$1 FOR UPDATE OF p`, id).Scan(&principalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE machine_credential SET state='revoked', revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1 AND state='active'`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (q *Queries) DisableMachinePrincipal(ctx context.Context, id uuid.UUID) error {
	return fmt.Errorf("machine disable requires an explicit generation and operation fence")
}

func (q *Queries) DisableMachinePrincipalFenced(ctx context.Context, id uuid.UUID, options LifecycleOptions) error {
	fence, err := requireLifecycleFence([]LifecycleOptions{options})
	if err != nil {
		return err
	}
	digest := lifecycleInputDigest("disable", id, uuid.Nil, nil, time.Time{}, nil, "", *fence.ExpectedGeneration, uuid.Nil, false)
	tx, err := q.beginLifecycle(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var generation int64
	var status string
	if err := tx.QueryRow(ctx, `SELECT generation,status FROM machine_principal WHERE id=$1 FOR UPDATE`, id).Scan(&generation, &status); err != nil {
		return err
	}
	var existingKind string
	var existingDigest []byte
	err = tx.QueryRow(ctx, `SELECT operation_kind,input_digest FROM machine_lifecycle_operation WHERE principal_id=$1 AND operation_id=$2`, id, fence.OperationID).Scan(&existingKind, &existingDigest)
	if err == nil {
		if existingKind != "disable" || !bytes.Equal(existingDigest, digest) {
			return ErrMachineLifecycleConflict
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if status != "active" || generation != *fence.ExpectedGeneration {
		return pgx.ErrNoRows
	}
	if _, err := tx.Exec(ctx, `INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation,input_digest) VALUES($1,$2,'disable',$3,$4)`, id, fence.OperationID, *fence.ExpectedGeneration, digest); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE machine_principal SET status='disabled',generation=generation+1,restore_until=clock_timestamp()+interval '7 days',updated_at=clock_timestamp() WHERE id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE machine_credential SET state='revoked',revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE principal_id=$1 AND state='active'`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (q *Queries) RestoreMachinePrincipal(ctx context.Context, id uuid.UUID, options ...LifecycleOptions) error {
	return fmt.Errorf("machine restore requires atomic fresh credential issuance")
}

func (q *Queries) RestoreMachineCredential(ctx context.Context, principalID, lineageID uuid.UUID, expiresAt time.Time, permissions []string, audience string, options ...LifecycleOptions) (MachineCredentialRow, error) {
	return q.RestoreMachineCredentialFenced(ctx, principalID, lineageID, nil, expiresAt, permissions, audience, options...)
}

func (q *Queries) RestoreMachineCredentialFenced(ctx context.Context, principalID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, options ...LifecycleOptions) (MachineCredentialRow, error) {
	fence, err := requireLifecycleFence(options)
	if err != nil {
		return MachineCredentialRow{}, err
	}
	digest := lifecycleInputDigest("restore", principalID, lineageID, secretHash, expiresAt, permissions, audience, *fence.ExpectedGeneration, uuid.Nil, fence.GeneratedExpiry)
	tx, err := q.beginLifecycle(ctx)
	if err != nil {
		return MachineCredentialRow{}, err
	}
	defer tx.Rollback(ctx)
	row, runErr := q.WithTx(tx).restoreMachineCredentialTx(ctx, principalID, lineageID, secretHash, expiresAt, permissions, audience, fence, digest)
	if runErr != nil {
		return MachineCredentialRow{}, runErr
	}
	if err := tx.Commit(ctx); err != nil {
		return MachineCredentialRow{}, err
	}
	return row, nil
}

func (q *Queries) restoreMachineCredentialTx(ctx context.Context, principalID, lineageID uuid.UUID, secretHash []byte, expiresAt time.Time, permissions []string, audience string, fence LifecycleOptions, digest []byte) (MachineCredentialRow, error) {
	var generation int64
	var status string
	if err := q.db.QueryRow(ctx, `SELECT generation,status FROM machine_principal WHERE id=$1 FOR UPDATE`, principalID).Scan(&generation, &status); err != nil {
		return MachineCredentialRow{}, err
	}
	var existingID pgtype.UUID
	var existingDigest []byte
	err := q.db.QueryRow(ctx, `SELECT result_credential_id,input_digest FROM machine_lifecycle_operation WHERE principal_id=$1 AND operation_id=$2`, principalID, fence.OperationID).Scan(&existingID, &existingDigest)
	if err == nil {
		if !bytes.Equal(existingDigest, digest) || !existingID.Valid {
			return MachineCredentialRow{}, ErrMachineLifecycleConflict
		}
		return q.machineCredentialByID(ctx, uuid.UUID(existingID.Bytes))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return MachineCredentialRow{}, err
	}
	if len(secretHash) == 0 {
		return MachineCredentialRow{}, fmt.Errorf("machine credential requires a secret digest")
	}
	if status != "disabled" || generation != *fence.ExpectedGeneration {
		return MachineCredentialRow{}, pgx.ErrNoRows
	}
	var eligible bool
	if err := q.db.QueryRow(ctx, `SELECT restore_until IS NOT NULL AND restore_until > clock_timestamp() FROM machine_principal WHERE id=$1`, principalID).Scan(&eligible); err != nil {
		return MachineCredentialRow{}, err
	}
	if !eligible {
		return MachineCredentialRow{}, pgx.ErrNoRows
	}
	if _, err := q.db.Exec(ctx, `INSERT INTO machine_lifecycle_operation(principal_id,operation_id,operation_kind,expected_generation,input_digest,lineage_id,credential_digest,expires_at,permissions,audience) VALUES($1,$2,'restore',$3,$4,$5,$6,$7,$8,$9)`, principalID, fence.OperationID, *fence.ExpectedGeneration, digest, lineageID, secretHash, expiresAt, permissions, audience); err != nil {
		return MachineCredentialRow{}, err
	}
	var nextGeneration int64
	if err := q.db.QueryRow(ctx, `UPDATE machine_principal SET status='active',generation=generation+1,restore_until=NULL,updated_at=now() WHERE id=$1 AND status='disabled' AND generation=$2 RETURNING generation`, principalID, generation).Scan(&nextGeneration); err != nil {
		return MachineCredentialRow{}, err
	}
	row, err := scanMachineCredentialRow(q.db.QueryRow(ctx, `INSERT INTO machine_credential(principal_id,lineage_id,secret_hash,expires_at,revocation_generation,permissions,audience) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,principal_id,lineage_id,state,expires_at,revocation_generation,permissions,audience,issued_at,revoked_at,secret_hash`, principalID, lineageID, secretHash, expiresAt, nextGeneration, permissions, audience))
	if err != nil {
		return MachineCredentialRow{}, err
	}
	if _, err := q.db.Exec(ctx, `UPDATE machine_lifecycle_operation SET result_credential_id=$1 WHERE principal_id=$2 AND operation_id=$3`, row.ID, principalID, fence.OperationID); err != nil {
		return MachineCredentialRow{}, err
	}
	return row, nil
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
