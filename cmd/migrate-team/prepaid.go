package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func checkPrepaidMigration(ctx context.Context, q querier, team uuid.UUID) error {
	for _, table := range []struct{ name, predicate string }{
		{"team_plan_assignment", "kind='prepaid' OR (effective_to IS NULL AND kind='free')"},
		{"billing_prepaid_purchase", "true"},
		{"billing_prepaid_auto_recharge", "true"},
		{"billing_funding_account", "to_jsonb(t)->>'prepaid'='true' OR to_jsonb(t)->>'prepaid_enrolment_due_at' IS NOT NULL"},
	} {
		var present bool
		if err := q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table.name).Scan(&present); err != nil {
			return err
		}
		if !present {
			continue
		}
		var blocked bool
		if err := q.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s t WHERE team_id=$1 AND (%s))`, table.name, table.predicate), team).Scan(&blocked); err != nil {
			return err
		}
		if blocked {
			return fmt.Errorf("refusing team migration: %s contains prepaid authority or entry eligibility; coordinated prepaid financial-authority transfer is required", table.name)
		}
	}
	return nil
}

func checkPrepaidCells(ctx context.Context, src, dst *pgxpool.Pool, team uuid.UUID) error {
	if err := checkPrepaidMigration(ctx, src, team); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if dst != nil {
		if err := checkPrepaidMigration(ctx, dst, team); err != nil {
			return fmt.Errorf("destination: %w", err)
		}
	}
	return nil
}

func lockPrepaidDestination(ctx context.Context, dst *pgxpool.Pool, team uuid.UUID) (pgx.Tx, error) {
	tx, err := dst.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err == nil {
		err = checkPrepaidMigration(ctx, tx, team)
	}
	if err != nil {
		tx.Rollback(ctx)
		return nil, fmt.Errorf("destination: %w", err)
	}
	return tx, nil
}
