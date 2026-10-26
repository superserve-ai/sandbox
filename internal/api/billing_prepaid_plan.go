package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func assertPrepaidEntry(ctx context.Context, tx pgx.Tx) error {
	var epoch uuid.UUID
	err := tx.QueryRow(ctx, `SELECT billing_assert_pricing_entry_open()`).Scan(&epoch)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55000" {
		return errPricingV2Off
	}
	return err
}

type prepaidPurchasePlan struct {
	Terms       planTerms  `json:"terms"`
	Predecessor *uuid.UUID `json:"predecessor"`
	Retain      bool       `json:"retain"`
}

func (h *Handlers) preparePrepaidPurchase(ctx context.Context, tx pgx.Tx, id, team uuid.UUID, customer string, actor uuid.UUID, amount int64) error {
	raw, entryOpen, err := lockPricingEntry(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_prepaid_purchase WHERE id=$1 AND team_id=$2 AND customer_id=$3 AND amount_cents=$4 AND actor_id=$5 AND source='checkout')`, id, team, customer, amount, actor).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	live, err := prepaidUnspentPurchases(ctx, tx, team)
	if err != nil {
		return err
	}
	if live >= prepaidLiveGrantLimit {
		return errPrepaidTooManyUnspent
	}
	if raw != "v2" || !entryOpen {
		return errPricingV2Off
	}
	if err := assertPrepaidEntry(ctx, tx); err != nil {
		return err
	}
	current, ok, err := currentTeamPlan(ctx, tx, team)
	if err != nil {
		return err
	}
	if !ok || (current.Kind != planKindFree && current.Kind != planKindPrepaid) {
		return errors.New("this team's plan cannot buy prepaid credit")
	}
	terms, err := h.planTermsForPricingVersion(ctx, "starter", raw, tx)
	if err != nil {
		return err
	}
	if terms.Kind != planKindPrepaid || terms.Retired {
		return errUnknownPlan
	}
	snapshot, err := json.Marshal(prepaidPurchasePlan{Terms: terms, Predecessor: &current.ID, Retain: current.Kind == planKindPrepaid})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_prepaid_purchase(id,team_id,customer_id,source,amount_cents,actor_id,payment_idempotency_key,credit_idempotency_key,plan_snapshot)
 VALUES($1,$2,$3,'checkout',$4,$5,'','',$6)`, id, team, customer, amount, actor, snapshot)
	return err
}

var assignStarterAfterPurchase = settlePrepaidPlan

func settlePrepaidPlan(ctx context.Context, h *Handlers, team, purchase uuid.UUID) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
		return err
	}
	key := "prepaid-plan:v1:" + purchase.String()
	var replay bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND idempotency_key=$2)`, team, key).Scan(&replay); err != nil {
		return err
	}
	if replay {
		return tx.Commit(ctx)
	}
	var raw []byte
	var actor *uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT plan_snapshot,actor_id FROM billing_prepaid_purchase WHERE id=$1 AND team_id=$2 AND source='checkout' AND payment_state='succeeded'`, purchase, team).Scan(&raw, &actor); err != nil {
		return err
	}
	var snapshot prepaidPurchasePlan
	if len(raw) == 0 {
		return errors.New("paid purchase lacks frozen plan authority; operator recovery required")
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	if snapshot.Terms.Kind != planKindPrepaid || snapshot.Terms.Retired {
		return errors.New("paid purchase has invalid frozen Starter terms")
	}
	current, ok, err := currentTeamPlan(ctx, tx, team)
	if err != nil {
		return err
	}
	if snapshot.Retain || (ok && (snapshot.Predecessor == nil || current.ID != *snapshot.Predecessor)) || (!ok && snapshot.Predecessor != nil) {
		return tx.Commit(ctx)
	}
	if _, err = assignTeamPlan(ctx, tx, planAssignment{Team: team, Terms: snapshot.Terms, Source: planSourceCreditPurchase, Actor: actor, Reason: "paid prepaid credit purchase", Key: key}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
