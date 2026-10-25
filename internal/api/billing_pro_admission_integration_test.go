//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestProAdmissionRetainsLocksAndRejectsRotatedEpoch(t *testing.T) {
	h, _ := newPlanAssignmentFixture(t)
	ctx := t.Context()
	if _, err := h.Pool.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='v2' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.Pool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`)
	})
	var epoch uuid.UUID
	if err := h.Pool.QueryRow(ctx, `SELECT epoch FROM billing_pricing_adoption WHERE singleton`).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	system := uuid.New()
	evidence, _ := json.Marshal(map[string]any{"epoch": epoch.String(), "region": "usw", "system_team_id": system.String(), "assembled_sha": "1111111111111111111111111111111111111111", "schema_sha": "1111111111111111111111111111111111111111", "worker_sha": "1111111111111111111111111111111111111111", "verified_worker": true, "deployment_reference": "disposable-fixture", "worker_reference": "disposable-fixture"})
	if _, err := h.Pool.Exec(ctx, `UPDATE billing_pricing_adoption SET region='usw',system_team_id=$1,state='released',released_at=clock_timestamp(),evidence=$2 WHERE singleton`, system, evidence); err != nil {
		t.Fatal(err)
	}
	expected, err := h.publicPricingState(ctx)
	if err != nil || !expected.EntryOpen {
		t.Fatalf("fixture entry: %+v %v", expected, err)
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = lockProAdmission(ctx, tx, expected); err != nil {
		t.Fatal(err)
	}
	rollback, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback.Rollback(ctx)
	if _, err = rollback.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = rollback.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" {
		t.Fatalf("rollback escaped acceptance lock: %v", err)
	}
	rollback.Rollback(ctx)
	tx.Rollback(ctx)
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='legacy' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	stale, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Rollback(ctx)
	err = lockProAdmission(ctx, stale, expected)
	if !errors.As(err, &pe) || pe.Code != "55000" {
		t.Fatalf("stale epoch accepted: %v", err)
	}
}

func TestProAssignmentChecksPredecessorAfterTeamLock(t *testing.T) {
	h, team := newPlanAssignmentFixture(t)
	ctx := t.Context()
	initial, err := assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", "free", 2, nil), Source: "signup", Reason: "initial Free"})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	if _, err = writer.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
		t.Fatal(err)
	}
	stale, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Rollback(ctx)
	if _, err = stale.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	cap := int32(100)
	offer := proOffer{Key: "pro_monthly", PredecessorKnown: true, InitialAssignment: &initial.ID, Limits: &planLimits{MaxConcurrent: &cap}}
	err = assignCheckoutPlan(ctx, stale, proChoice{Team: team, Offer: offer.Key, Actor: uuid.New()}, offer, uuid.New())
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" {
		t.Fatalf("activation did not serialize: %v", err)
	}
	stale.Rollback(ctx)
	newer, err := assignTeamPlan(ctx, writer, planAssignment{Team: team, Terms: testPlanTerms("custom", "custom", 7, nil), Source: "staff", Reason: "newer agreement"})
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	retry, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Rollback(ctx)
	err = assignCheckoutPlan(ctx, retry, proChoice{Team: team, Offer: offer.Key, Actor: uuid.New()}, offer, uuid.New())
	if err == nil || err.Error() != "team plan changed after paid acceptance" {
		t.Fatalf("newer plan replaced: %v", err)
	}
	retry.Rollback(ctx)
	var retained bool
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE id=$1 AND effective_to IS NULL) AND (SELECT max_sandboxes=7 FROM team WHERE id=$2)`, newer.ID, team).Scan(&retained); err != nil || !retained {
		t.Fatalf("newer authority changed: %v %v", retained, err)
	}
}
