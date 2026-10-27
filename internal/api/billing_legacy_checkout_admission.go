package api

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

var errLegacyCheckoutPlan = errors.New("this team's plan requires plan-aware checkout; choose Starter credit or Pro")

// This early check avoids customer/identity writes for an incompatible plan.
// The transaction below repeats admission after locking the assignment writer.
func (h *Handlers) checkLegacyCheckoutPlan(ctx context.Context, team uuid.UUID) error {
	if h.Pool == nil {
		return errors.New("billing transactions are not configured")
	}
	var denied bool
	err := h.Pool.QueryRow(ctx, `SELECT EXISTS (
  SELECT 1 FROM team_plan_assignment p WHERE p.team_id=$1 AND p.effective_to IS NULL AND p.kind<>'legacy_payg'
 ) AND NOT EXISTS (
  SELECT 1 FROM team_billing_account a WHERE a.team_id=$1 AND a.checkout_initializing_at IS NOT NULL
 )`, team).Scan(&denied)
	if err != nil {
		return err
	}
	if denied {
		return errLegacyCheckoutPlan
	}
	return nil
}

func (h *Handlers) beginLegacyCheckout(ctx context.Context, team, actor uuid.UUID, req billingCheckoutSessionRequest, key string, attempt uuid.UUID, trusted bool) (db.TeamBillingAccount, error) {
	var account db.TeamBillingAccount
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return account, err
	}
	defer tx.Rollback(ctx)
	if trusted {
		if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
			return account, err
		}
	}
	// Keep the identity -> account lock order of both existing checkout writers.
	if trusted && req.Decision == "publication_failed" {
		_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('stripe-promo-user:' || $1::text)::bigint)`, actor)
	} else {
		_, err = tx.Exec(ctx, `SELECT lock_stripe_checkout_identity($1)`, actor)
	}
	if err != nil {
		return account, err
	}
	q := h.DB.WithTx(tx)
	if _, err = tx.Exec(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, team); err != nil {
		return account, err
	}
	// Assignment INSERT takes KEY SHARE; plan changes take NO KEY UPDATE. UPDATE
	// conflicts with both, including a first assignment absent at our first read.
	// Billing writers use both team/account lock orders. Do not wait on the team
	// while holding the account: contention is retried without a new lease.
	var lockedTeam uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM team WHERE id=$1 FOR UPDATE NOWAIT`, team).Scan(&lockedTeam); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			return account, pgx.ErrNoRows
		}
		return account, err
	}
	var denied bool
	if err = tx.QueryRow(ctx, `SELECT a.checkout_initializing_at IS NULL AND EXISTS (
  SELECT 1 FROM team_plan_assignment p WHERE p.team_id=a.team_id AND p.effective_to IS NULL AND p.kind<>'legacy_payg'
 ) FROM team_billing_account a WHERE a.team_id=$1`, team).Scan(&denied); err != nil {
		return account, err
	}
	// An accepted generation retains its original actor/key/deadline validation.
	// A later assignment must not strand its uncertain provider outcome.
	if denied {
		return account, errLegacyCheckoutPlan
	}
	if trusted {
		err = q.BeginStripeCheckoutWithPublicationDecision(ctx, db.BeginStripeCheckoutWithPublicationDecisionParams{
			TeamID: team, UserID: actor, OperationID: req.OperationID, HomeRegion: req.HomeRegion,
			RequestKey: key, Decision: req.Decision, AttemptID: attempt,
		})
		if err == nil {
			account, err = q.GetTeamBillingCheckoutForRecovery(ctx, team)
		}
	} else {
		account, err = q.BeginTeamBillingCheckout(ctx, db.BeginTeamBillingCheckoutParams{TeamID: team, ActorID: pgtype.UUID{Bytes: actor, Valid: true}, RequestKey: &key, AttemptID: attempt})
		if errors.Is(err, pgx.ErrNoRows) {
			account, err = q.ResumeTeamBillingCheckout(ctx, db.ResumeTeamBillingCheckoutParams{TeamID: team, ActorID: pgtype.UUID{Bytes: actor, Valid: true}, RequestKey: &key, AttemptID: attempt})
		}
	}
	if err != nil {
		return account, err
	}
	return account, tx.Commit(ctx)
}
