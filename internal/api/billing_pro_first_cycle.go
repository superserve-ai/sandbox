package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

var errProFirstCycleReconciliation = errors.New("An earlier billing setup requires reconciliation before starting a new Pro billing month.")

// Team entry states. A new team is on its trial, with compute while the
// trial credit lasts, until its first checkout assigns a plan. A team whose
// first payment is confirmed but whose plan is still being assigned is
// activating, so it is neither sent back to the plan picker nor shown as paid.
const (
	entryTrial         = "trial"
	entryTrialEnded    = "trial_ended"
	entryPaymentFailed = "payment_failed"
	entryActivating    = "activating"
	entryPlanRequired  = "plan_required"
	entryActive        = "active"
)

func teamAwaitingPlan(ctx context.Context, q db.DBTX, team uuid.UUID) (bool, error) {
	var awaiting bool
	err := q.QueryRow(ctx, `SELECT billing_team_awaiting_plan($1)`, team).Scan(&awaiting)
	return awaiting, err
}

func teamEntryState(ctx context.Context, q db.DBTX, team uuid.UUID) (string, error) {
	var state string
	err := q.QueryRow(ctx, `SELECT CASE WHEN s<>'active' AND EXISTS(SELECT 1 FROM billing_pro_upgrade u WHERE u.team_id=$1 AND u.state IN ('paid','credited') AND NOT EXISTS(SELECT 1 FROM billing_pro_upgrade_setup x WHERE x.upgrade_id=u.id AND x.state='open')) THEN 'activating' ELSE s END FROM billing_team_entry_state($1) s`, team).Scan(&state)
	return state, err
}

func firstProCycleEligible(ctx context.Context, q db.DBTX, team uuid.UUID, free, anchored, subscribed bool) (bool, error) {
	if !free {
		return false, nil
	}
	var previousPaidTerms, abandonedFirstCycle bool
	err := q.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1)
 OR EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND kind<>'free')
 OR EXISTS(SELECT 1 FROM billing_prepaid_purchase WHERE team_id=$1 AND payment_state='succeeded'),
 EXISTS(SELECT 1 FROM billing_pro_upgrade u JOIN team_billing_account a ON a.team_id=u.team_id AND a.stripe_subscription_id=u.subscription_id
  WHERE u.team_id=$1 AND u.state='expired' AND u.request_payload->>'FirstPaidProCycle'='true')`, team).Scan(&previousPaidTerms, &abandonedFirstCycle)
	if err != nil {
		return false, err
	}
	if abandonedFirstCycle || (!previousPaidTerms && !anchored && subscribed) {
		return false, errProFirstCycleReconciliation
	}
	return !previousPaidTerms && !anchored && !subscribed, nil
}

type customerProCheckout struct {
	FirstPaidProCycle bool       `json:"first_paid_pro_cycle"`
	Accepted          bool       `json:"accepted"`
	OfferKey          string     `json:"offer_key,omitempty"`
	PeriodStart       *time.Time `json:"period_start,omitempty"`
	PeriodEnd         *time.Time `json:"period_end,omitempty"`
	CreditExpiresAt   *time.Time `json:"credit_expires_at,omitempty"`
	FirstPaymentCents *int64     `json:"first_payment_cents,omitempty"`
	FirstCreditCents  *int64     `json:"first_credit_cents,omitempty"`
}

func customerProCheckoutTerms(ctx context.Context, q db.DBTX, team uuid.UUID, free, anchored bool) (customerProCheckout, error) {
	var out customerProCheckout
	u, err := scanProUpgrade(q.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE team_id=$1 AND state NOT IN ('expired','ended')`, team))
	if err == nil {
		var p StripeCreateCheckoutSessionParams
		if err = json.Unmarshal(u.Payload, &p); err != nil {
			return out, err
		}
		expires, err := u.creditExpiry()
		if err != nil {
			return out, err
		}
		credit := u.bridgeCreditAmount()
		out = customerProCheckout{FirstPaidProCycle: p.FirstPaidProCycle, Accepted: true, OfferKey: u.Offer, PeriodStart: &u.Quoted, PeriodEnd: &u.End, FirstPaymentCents: &u.Amount, FirstCreditCents: &credit}
		if expires != 0 {
			out.CreditExpiresAt = &u.End
		}
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if !free {
		return out, nil
	}
	var subscribed bool
	if err = q.QueryRow(ctx, `SELECT COALESCE((SELECT stripe_subscription_id IS NOT NULL FROM team_billing_account WHERE team_id=$1),false)`, team).Scan(&subscribed); err != nil {
		return out, err
	}
	out.FirstPaidProCycle, err = firstProCycleEligible(ctx, q, team, free, anchored, subscribed)
	if errors.Is(err, errProFirstCycleReconciliation) {
		return out, nil
	}
	return out, err
}

// Provider metadata selects the calendar interpretation, but the frozen local
// operation independently requires it before financial work can proceed.
func validateFirstProCycleProviderCalendar(id uuid.UUID, anchor time.Time, sub invoiceSubscription) error {
	if sub.Metadata["first_paid_pro_cycle"] != "true" || sub.Metadata["pro_upgrade_id"] != id.String() || sub.StartDate != anchor.Unix() || sub.BillingCycleAnchorConfig == nil {
		return errors.New("first Pro month provider calendar authority differs")
	}
	start, _, ok := providerInvoicePeriod(sub, anchor)
	if !ok || !start.Equal(anchor) {
		return errors.New("first Pro month provider calendar differs from accepted anniversary")
	}
	return nil
}

func (h *Handlers) verifyFirstProCycleProviderCalendar(ctx context.Context, reader db.DBTX, sub invoiceSubscription) error {
	var id uuid.UUID
	var anchor time.Time
	var customer string
	err := reader.QueryRow(ctx, `SELECT id,anchor,customer_id FROM billing_pro_upgrade WHERE subscription_id=$1 AND request_payload->>'FirstPaidProCycle'='true'`, sub.ID).Scan(&id, &anchor, &customer)
	if errors.Is(err, pgx.ErrNoRows) {
		if sub.Metadata["first_paid_pro_cycle"] == "true" {
			return errors.New("first Pro month provider marker lacks frozen local authority")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if sub.Customer != customer {
		return errors.New("first Pro month provider customer differs")
	}
	return validateFirstProCycleProviderCalendar(id, anchor, sub)
}
