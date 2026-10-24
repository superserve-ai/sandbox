package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type migrationDestination interface {
	querier
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func lockSourceAssignments(ctx context.Context, tx pgx.Tx, team uuid.UUID) error {
	if _, err := tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR UPDATE`, team); err != nil {
		return fmt.Errorf("lock source assignment owner: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM team_plan_assignment WHERE team_id=$1 FOR UPDATE`, team); err != nil {
		return err
	}
	return checkFreePauseTransfer(ctx, tx, team)
}

func checkFreePauseTransfer(ctx context.Context, q querier, team uuid.UUID) error {
	for _, table := range []string{"billing_free_allowance", "billing_team_pause_request", "billing_team_pause_target", "billing_free_allowance_retry", "billing_pricing_adoption_credit_hold", "billing_pricing_adoption_credit_resolution"} {
		var exists bool
		if err := q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+pgx.Identifier{table}.Sanitize()+` WHERE team_id=$1)`, team).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%s state requires coordinated Free allowance and pause authority transfer before team migration", table)
		}
	}
	return nil
}

func copyTable(ctx context.Context, src querier, dst *pgxpool.Pool, spec tableSpec, team uuid.UUID, transform rowTransform) (int64, int64, error) {
	if spec.name != "team" && spec.name != "team_plan_assignment" {
		return copyTableRows(ctx, src, dst, spec, team, transform)
	}
	tx, err := dst.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	var pricing string
	if err := tx.QueryRow(ctx, `SELECT pricing_version FROM billing_pricing_switch WHERE singleton FOR SHARE`).Scan(&pricing); err != nil {
		return 0, 0, err
	}
	if pricing == "v2" {
		return 0, 0, fmt.Errorf("regional team import is unavailable while pricing v2 is active")
	}
	payload, count, err := assignmentSnapshot(ctx, src, team)
	if err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR UPDATE`, team); err != nil {
		return 0, 0, err
	}
	if err := checkAssignmentReferences(ctx, src, tx, team); err != nil {
		return 0, 0, err
	}
	if count > 0 {
		if _, err := tx.Exec(ctx, `LOCK TABLE team_plan_assignment IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return 0, 0, err
		}
	}
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
	 SELECT 1 FROM team_plan_assignment d LEFT JOIN jsonb_populate_recordset(NULL::team_plan_assignment,$1::jsonb) s ON s.id=d.id
	 WHERE d.team_id=$2 AND (s.id IS NULL OR (to_jsonb(d)-'effective_to') IS DISTINCT FROM (to_jsonb(s)-'effective_to')
	 OR (d.effective_to IS NOT NULL AND d.effective_to IS DISTINCT FROM s.effective_to)))`, payload, team).Scan(&conflict); err != nil {
		return 0, 0, err
	}
	if conflict {
		return 0, 0, fmt.Errorf("destination assignment history differs; refusing to overwrite financial authority")
	}
	var copied, skipped int64
	if spec.name == "team" {
		if _, err := tx.Exec(ctx, `SELECT set_config('superserve.migrating_team_id',$1,true),set_config('superserve.applying_plan_limits','on',true),set_config('superserve.applying_assignment_limits','on',true)`, team.String()); err != nil {
			return 0, 0, err
		}
		copied, skipped, err = copyTableRows(ctx, src, tx, spec, team, transform)
		if err != nil {
			return 0, 0, err
		}
	}
	if count > 0 {
		for _, trigger := range []string{"team_plan_assignment_guard", "team_plan_assignment_limits"} {
			if _, err := tx.Exec(ctx, `ALTER TABLE team_plan_assignment DISABLE TRIGGER `+pgx.Identifier{trigger}.Sanitize()); err != nil {
				return 0, 0, err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE team_plan_assignment d SET effective_to=s.effective_to
	 FROM jsonb_populate_recordset(NULL::team_plan_assignment,$1::jsonb) s
	 WHERE d.id=s.id AND d.effective_to IS NULL AND s.effective_to IS NOT NULL`, payload); err != nil {
			return 0, 0, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO team_plan_assignment SELECT * FROM jsonb_populate_recordset(NULL::team_plan_assignment,$1::jsonb)
	 ORDER BY effective_from,id ON CONFLICT (id) DO NOTHING`, payload); err != nil {
			return 0, 0, err
		}
		for _, trigger := range []string{"team_plan_assignment_guard", "team_plan_assignment_limits"} {
			if _, err := tx.Exec(ctx, `ALTER TABLE team_plan_assignment ENABLE TRIGGER `+pgx.Identifier{trigger}.Sanitize()); err != nil {
				return 0, 0, err
			}
		}
	}
	if err := requireAssignmentParity(ctx, src, tx, team); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	if spec.name == "team_plan_assignment" {
		return 0, count, nil
	}
	return copied, skipped, nil
}

func assignmentSnapshot(ctx context.Context, src querier, team uuid.UUID) ([]byte, int64, error) {
	rows, err := src.Query(ctx, `SELECT to_jsonb(a) FROM team_plan_assignment a WHERE team_id=$1 ORDER BY effective_from,id FOR UPDATE`, team)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	assignments := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		assignments = append(assignments, raw)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	payload, err := json.Marshal(assignments)
	return payload, int64(len(assignments)), err
}

func checkAssignmentReferences(ctx context.Context, src querier, dst pgx.Tx, team uuid.UUID) error {
	for _, q := range []querier{src, dst} {
		if err := checkFreePauseTransfer(ctx, q, team); err != nil {
			return err
		}
	}
	var contractBacked bool
	if err := src.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND contract_id IS NOT NULL)`, team).Scan(&contractBacked); err != nil {
		return err
	}
	if contractBacked {
		return fmt.Errorf("contract-backed assignment history requires coordinated financial authority transfer before team migration")
	}
	for _, ref := range []struct{ table, column, projection string }{
		{"billing_plan_version", "plan_version_id", `to_jsonb(r)-ARRAY['state','created_by','created_at','updated_at','published_by','published_at','retired_by','retired_at']`},
	} {
		rows, err := src.Query(ctx, fmt.Sprintf(`SELECT r.id,%s FROM %s r WHERE id IN (SELECT %s FROM team_plan_assignment WHERE team_id=$1) FOR SHARE`, ref.projection, ref.table, ref.column), team)
		if err != nil {
			return err
		}
		type reference struct {
			id   uuid.UUID
			body []byte
		}
		refs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (reference, error) {
			var r reference
			err := row.Scan(&r.id, &r.body)
			return r, err
		})
		if err != nil {
			return err
		}
		for _, r := range refs {
			var matches bool
			err := dst.QueryRow(ctx, fmt.Sprintf(`SELECT %s=$2::jsonb FROM %s r WHERE id=$1 FOR SHARE`, ref.projection, ref.table), r.id, r.body).Scan(&matches)
			if err != nil || !matches {
				return fmt.Errorf("destination must already have matching %s %s before assignment migration: %v", ref.table, r.id, err)
			}
		}
	}
	return nil
}

func requireAssignmentParity(ctx context.Context, src, dst querier, team uuid.UUID) error {
	for _, q := range []querier{src, dst} {
		if err := checkFreePauseTransfer(ctx, q, team); err != nil {
			return err
		}
	}
	spec := tableSpec{"team_plan_assignment", "team_id=$1"}
	source, err := rowChecksums(ctx, src, spec, team, nil)
	if err != nil {
		return err
	}
	destination, err := rowChecksums(ctx, dst, spec, team, nil)
	if err != nil {
		return err
	}
	if a, b := diffChecksums(source, destination); a+b != 0 {
		return fmt.Errorf("assignment history changed; rerun copy and validate before cutover")
	}
	return nil
}

func validateRetainedAssignments(ctx context.Context, src, dst querier, team uuid.UUID) error {
	rows, err := src.Query(ctx, `SELECT id,to_jsonb(a),effective_to IS NULL FROM team_plan_assignment a WHERE team_id=$1`, team)
	if err != nil {
		return err
	}
	type assignment struct {
		id   uuid.UUID
		body []byte
		open bool
	}
	assignments, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (assignment, error) {
		var a assignment
		err := row.Scan(&a.id, &a.body, &a.open)
		return a, err
	})
	if err != nil {
		return err
	}
	for _, a := range assignments {
		var matches bool
		err := dst.QueryRow(ctx, `SELECT CASE WHEN $3 THEN to_jsonb(a)-'effective_to'=$2::jsonb-'effective_to' ELSE to_jsonb(a)=$2::jsonb END FROM team_plan_assignment a WHERE id=$1 AND team_id=$4`, a.id, a.body, a.open, team).Scan(&matches)
		if err != nil || !matches {
			return fmt.Errorf("source assignment %s is not preserved in destination; refusing cutover/purge", a.id)
		}
	}
	return nil
}
