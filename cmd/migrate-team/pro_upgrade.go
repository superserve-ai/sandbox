package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

func checkProUpgradeMigration(ctx context.Context, q querier, team uuid.UUID) error {
	var present, owned bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('public.billing_pro_upgrade') IS NOT NULL`).Scan(&present); err != nil {
		return err
	}
	if !present {
		return nil
	}
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE team_id=$1)`, team).Scan(&owned); err != nil {
		return err
	}
	if owned {
		return fmt.Errorf("Pro upgrade history requires coordinated financial authority transfer before team migration")
	}
	return nil
}
