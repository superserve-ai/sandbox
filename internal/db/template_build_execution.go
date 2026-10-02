package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type BuildExecution struct {
	BuildID        uuid.UUID  `json:"build_id"`
	CurrentAttempt *uuid.UUID `json:"attempt_id,omitempty"`
	Cell           *string    `json:"cell,omitempty"`
	FirstStartedAt *time.Time `json:"first_started_at,omitempty"`
	Reason         string     `json:"reason"`
	Attempts       int        `json:"attempt_count"`
	Publication    bool       `json:"publication_verified"`
	RetryReason    string     `json:"retry_reason,omitempty"`
}

type BuildAttempt struct {
	ID            uuid.UUID
	BuildID       uuid.UUID
	TemplateID    uuid.UUID
	HostID        string
	IncarnationID uuid.UUID
	VMID          string
	State         string
	ClaimedAt     time.Time
}

func (q *Queries) GetBuildExecution(ctx context.Context, id uuid.UUID) (BuildExecution, error) {
	var b BuildExecution
	err := q.db.QueryRow(ctx, `SELECT e.build_id,e.current_attempt,e.cell,e.first_started_at,e.reason,
 (SELECT count(*) FROM template_build_attempt WHERE build_id=e.build_id AND state<>'rejected'),
 EXISTS(SELECT 1 FROM template_build_publication WHERE build_id=e.build_id AND attempt_id=e.current_attempt),
 COALESCE((SELECT reason FROM template_build_attempt WHERE build_id=e.build_id AND state IN ('failed','fenced') ORDER BY claimed_at DESC LIMIT 1),'')
 FROM template_build_execution e WHERE e.build_id=$1`, id).Scan(&b.BuildID, &b.CurrentAttempt, &b.Cell, &b.FirstStartedAt, &b.Reason, &b.Attempts, &b.Publication, &b.RetryReason)
	return b, err
}
func (q *Queries) ClaimBuildAttempt(ctx context.Context, id uuid.UUID, cell string, limit int32) (*uuid.UUID, error) {
	var a *uuid.UUID
	err := q.db.QueryRow(ctx, `SELECT claim_template_build($1,$2,$3)`, id, cell, limit).Scan(&a)
	return a, err
}
func (q *Queries) GetBuildAttempt(ctx context.Context, id uuid.UUID) (BuildAttempt, error) {
	var a BuildAttempt
	err := q.db.QueryRow(ctx, `SELECT a.id,a.build_id,b.template_id,a.host_id,a.incarnation_id,a.vm_id,a.state,a.claimed_at
 FROM template_build_attempt a JOIN template_build b ON b.id=a.build_id WHERE a.id=$1`, id).
		Scan(&a.ID, &a.BuildID, &a.TemplateID, &a.HostID, &a.IncarnationID, &a.VMID, &a.State, &a.ClaimedAt)
	return a, err
}
func (q *Queries) AdmitBuildAttempt(ctx context.Context, id uuid.UUID, host string, incarnation uuid.UUID) (bool, error) {
	var ok bool
	err := q.db.QueryRow(ctx, `SELECT admit_template_build($1,$2,$3)`, id, host, incarnation).Scan(&ok)
	return ok, err
}
func (q *Queries) TransitionBuildAttempt(ctx context.Context, id uuid.UUID, attempt *uuid.UUID, action, reason string) (bool, error) {
	var ok bool
	err := q.db.QueryRow(ctx, `SELECT transition_template_attempt($1,$2,$3,$4)`, id, attempt, action, reason).Scan(&ok)
	return ok, err
}
func (q *Queries) AcceptBuildPublication(ctx context.Context, id, attempt uuid.UUID) (bool, error) {
	var ok bool
	err := q.db.QueryRow(ctx, `SELECT accept_template_publication($1,$2)`, id, attempt).Scan(&ok)
	return ok, err
}
func (q *Queries) RecordBuildPublication(ctx context.Context, attempt uuid.UUID, host, bucket, generation, manifest string, files, runtime json.RawMessage, verified time.Time) (bool, error) {
	var ok bool
	err := q.db.QueryRow(ctx, `SELECT record_template_publication($1,$2,$3,$4,$5,$6,$7,$8)`, attempt, host, bucket, generation, manifest, files, runtime, verified).Scan(&ok)
	return ok, err
}
func (q *Queries) ListBuildAttemptCleanup(ctx context.Context, limit int32, excluded []uuid.UUID) ([]BuildAttempt, error) {
	rows, err := q.db.Query(ctx, `WITH due AS (
 SELECT id FROM template_build_attempt WHERE cleanup_pending AND id <> ALL($2::uuid[])
 ORDER BY cleanup_checked_at NULLS FIRST,claimed_at LIMIT $1 FOR UPDATE SKIP LOCKED
), checked AS (
 UPDATE template_build_attempt SET cleanup_checked_at=now() WHERE id IN (SELECT id FROM due) RETURNING *
)
SELECT a.id,a.build_id,b.template_id,a.host_id,a.incarnation_id,a.vm_id,a.state,a.claimed_at
 FROM checked a JOIN template_build b ON b.id=a.build_id`, limit, excluded)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BuildAttempt
	for rows.Next() {
		var a BuildAttempt
		if err := rows.Scan(&a.ID, &a.BuildID, &a.TemplateID, &a.HostID, &a.IncarnationID, &a.VMID, &a.State, &a.ClaimedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (q *Queries) MarkBuildAttemptCleaned(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.Exec(ctx, `UPDATE template_build_attempt SET cleanup_pending=false WHERE id=$1 AND state IN ('failed','fenced','rejected')`, id)
	return err
}

// Preserve accepted versions as well as active/unreachable execution owners.
func (q *Queries) ProtectedBuildAttemptKeys(ctx context.Context) ([]string, error) {
	rows, err := q.db.Query(ctx, `SELECT b.template_id::text||'/'||a.vm_id FROM template_build_attempt a
 JOIN template_build b ON b.id=a.build_id WHERE a.state IN ('claimed','admitted','uploading','ready')
 OR a.cleanup_pending OR EXISTS(SELECT 1 FROM template_build_publication p WHERE p.attempt_id=a.id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
func (q *Queries) BuildAttemptReferenced(ctx context.Context, id uuid.UUID) (bool, error) {
	var protected bool
	err := q.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM template_build_publication WHERE attempt_id=$1)
 OR EXISTS(SELECT 1 FROM template_build_attempt a JOIN sandbox s ON s.base_path LIKE '%/'||a.vm_id||'/%'
 WHERE a.id=$1 AND s.destroyed_at IS NULL)`, id).Scan(&protected)
	return protected, err
}

// Host identity loss is positive failure evidence. A drain is not host loss.
func (q *Queries) BuildAttemptHostLost(ctx context.Context, a BuildAttempt) (bool, error) {
	var lost bool
	err := q.db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM host WHERE id=$1 AND incarnation_id=$2
 AND last_heartbeat_at>now()-interval '2 minutes' AND status<>'retired')`, a.HostID, a.IncarnationID).Scan(&lost)
	return lost, err
}

func (q *Queries) ListResilientBuildIDs(ctx context.Context, limit int32) ([]uuid.UUID, error) {
	// Rotate checked builds even if reconciliation fails or they remain pending.
	rows, err := q.db.Query(ctx, `WITH due AS (
 SELECT e.build_id FROM template_build_execution e JOIN template_build b ON b.id=e.build_id
 WHERE b.status IN ('pending','building','snapshotting')
 ORDER BY e.reconcile_checked_at NULLS FIRST,b.created_at,b.id LIMIT $1 FOR UPDATE OF e SKIP LOCKED
), checked AS (
 UPDATE template_build_execution e SET reconcile_checked_at=clock_timestamp()
 FROM due WHERE e.build_id=due.build_id RETURNING e.build_id
)
SELECT build_id FROM checked`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
func (q *Queries) GetBuildSubmission(ctx context.Context, id uuid.UUID) (uuid.UUID, time.Time, time.Time, error) {
	var template uuid.UUID
	var created, now time.Time
	err := q.db.QueryRow(ctx, `SELECT template_id,created_at,now() FROM template_build WHERE id=$1`, id).Scan(&template, &created, &now)
	return template, created, now, err
}

func (q *Queries) GetBuildAuditOwner(ctx context.Context, id uuid.UUID) (uuid.UUID, uuid.UUID, error) {
	var templateID, teamID uuid.UUID
	err := q.db.QueryRow(ctx, `SELECT template_id,team_id FROM template_build WHERE id=$1`, id).Scan(&templateID, &teamID)
	return templateID, teamID, err
}

func (q *Queries) HasTemplateExecutions(ctx context.Context, template uuid.UUID) (bool, error) {
	var exists bool
	err := q.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM template_build b JOIN template_build_execution e ON e.build_id=b.id WHERE b.template_id=$1)`, template).Scan(&exists)
	return exists, err
}
func (q *Queries) BuildArtifactProtected(ctx context.Context, vmID string) (bool, error) {
	var exists bool
	err := q.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM template_build_attempt a WHERE a.vm_id=$1 AND
 (a.state IN ('claimed','admitted','uploading','ready') OR a.cleanup_pending OR EXISTS(SELECT 1 FROM template_build_publication p WHERE p.attempt_id=a.id)))`, vmID).Scan(&exists)
	return exists, err
}
