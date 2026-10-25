package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func (h *Handlers) releasePlanChangeSubscription(ctx context.Context, tx pgx.Tx, c teamPlanChange, current teamPlan, sub invoiceSubscription) error {
	if current.ContractID == nil || c.Subscription == nil || !subscriptionEnded(sub) || sub.ID != *c.Subscription {
		return errors.New("the source subscription has not ended")
	}
	q := h.DB.WithTx(tx)
	a, err := q.LockTeamBillingAccount(ctx, c.Team)
	if err != nil {
		return err
	}
	if sub.Customer == "" || sub.Customer != derefString(a.StripeCustomerID) || sub.ID != derefString(a.StripeSubscriptionID) {
		return errors.New("the billing account no longer owns the source subscription")
	}
	var source, conflict bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE id=$1 AND team_id=$2 AND customer_id=$3 AND subscription_id=$4),
        EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$2 AND id<>$1 AND status<>'ended')
        OR EXISTS(SELECT 1 FROM billing_yc_operation WHERE team_id=$2 AND NOT billing_yc_released($2))
        OR EXISTS(SELECT 1 FROM billing_sponsored_annual_authority WHERE team_id=$2 AND state<>'ended')`, current.ContractID, c.Team, sub.Customer, sub.ID).Scan(&source, &conflict); err != nil {
		return err
	}
	if !source || conflict {
		return errors.New("the source contract no longer owns the billing authority")
	}
	var choiceJSON, accountJSON []byte
	var state string
	var subscription *string
	if err = tx.QueryRow(ctx, `SELECT to_jsonb(c),state,subscription_id FROM billing_signup_choice c WHERE team_id=$1 FOR UPDATE`, c.Team).Scan(&choiceJSON, &state, &subscription); err != nil {
		return err
	}
	var pending, mayExist bool
	var requestKey *string
	if err = tx.QueryRow(ctx, `SELECT cardinality(checkout_pending_attempt_ids)<>0,checkout_may_exist,checkout_request_key FROM team_billing_account WHERE team_id=$1`, c.Team).Scan(&pending, &mayExist, &requestKey); err != nil {
		return err
	}
	if pending || state == "pending" || a.StripeActivationCreditReservedAt.Valid || (subscription != nil && *subscription != sub.ID) || (a.CheckoutSubscriptionID != nil && *a.CheckoutSubscriptionID != sub.ID) {
		return errors.New("the previous checkout still has unresolved authority")
	}
	upgrade, err := h.proUpgradeRelease(ctx, tx, c, current, sub)
	if err != nil {
		return err
	}
	var checkout *StripeRetrievedCheckoutSession
	if upgrade != nil {
		if a.CheckoutInitializingAt.Valid || a.CheckoutSessionID != nil || mayExist || requestKey != nil || state == "pending" {
			return errors.New("a different checkout owns the released upgrade account")
		}
	} else if state == "committed" {
		choice, e := scanProChoice(tx.QueryRow(ctx, `SELECT `+proChoiceColumns+` FROM billing_signup_choice WHERE team_id=$1`, c.Team))
		if e != nil {
			return e
		}
		var params StripeCreateCheckoutSessionParams
		if e = json.Unmarshal(choice.Payload, &params); e != nil {
			return e
		}
		generation := params.Metadata["checkout_generation"]
		at, e := time.Parse(time.RFC3339Nano, generation)
		if e != nil || !at.Equal(choice.Generation) || params.CustomerID != sub.Customer || choice.Session == nil || *choice.Session == "" || derefString(choice.Subscription) != sub.ID || params.IdempotencyKey == "" {
			return errors.New("the source checkout provenance changed")
		}
		if (a.CheckoutInitializingAt.Valid || mayExist) && (!a.CheckoutInitializingAt.Valid || !a.CheckoutInitializingAt.Time.Equal(choice.Generation) || derefString(a.CheckoutSessionID) != *choice.Session || derefString(requestKey) != params.IdempotencyKey) {
			return errors.New("a different checkout generation owns the account")
		}
		session, e := h.Stripe.(*stripeHTTPClient).RetrieveCheckoutSession(ctx, *choice.Session)
		if e != nil {
			return e
		}
		if session.ID != *choice.Session || session.CustomerID != sub.Customer || session.SubscriptionID != sub.ID || session.ClientReferenceID != c.Team.String() || session.Status != "complete" || session.Mode != "subscription" || session.Metadata["checkout_generation"] != generation || session.Metadata["commercial_offer"] != choice.Offer || session.Metadata["activation_user_id"] != choice.Actor.String() || sub.Metadata["checkout_generation"] != generation || sub.Metadata["commercial_offer"] != choice.Offer {
			return errors.New("the provider checkout does not match the source purchase")
		}
		checkout = &session
	} else if state != "selecting" || subscription != nil || a.CheckoutInitializingAt.Valid || a.CheckoutSessionID != nil || a.CheckoutCompletedAt.Valid || mayExist {
		return errors.New("the source checkout is not reconciled")
	}
	var invoiceSnapshot *invoiceAccount
	var invoiceOwner invoiceAccount
	invoiceErr := tx.QueryRow(ctx, `SELECT customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at FROM billing_invoice_account WHERE team_id=$1 FOR SHARE`, c.Team).Scan(&invoiceOwner.Customer, &invoiceOwner.Subscription, &invoiceOwner.Price, &invoiceOwner.Event, &invoiceOwner.Meter, &invoiceOwner.EnrolledAt)
	if invoiceErr == nil {
		if invoiceOwner.Customer != sub.Customer || invoiceOwner.Subscription != sub.ID {
			return errors.New("invoice reconciliation still belongs to a different purchase")
		}
		if err = h.loadInvoiceBase(ctx, c.Team, &invoiceOwner, tx); err != nil {
			return err
		}
		invoiceOwner.Base.TerminatedAt = sub.EndedAt
		if invoiceOwner.Base.TerminatedAt <= 0 {
			invoiceOwner.Base.TerminatedAt = h.nowUTC().Unix()
		}
		invoiceSnapshot = &invoiceOwner
	} else if !errors.Is(invoiceErr, pgx.ErrNoRows) {
		return invoiceErr
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1 AND status<>'ended'`, current.ContractID); err != nil {
		return err
	}
	if err = tx.QueryRow(ctx, `SELECT to_jsonb(a) FROM team_billing_account a WHERE team_id=$1`, c.Team).Scan(&accountJSON); err != nil {
		return err
	}
	evidence, err := json.Marshal(struct {
		invoiceSubscription
		Checkout *StripeRetrievedCheckoutSession `json:"checkout,omitempty"`
		Upgrade  *proUpgradeReleaseEvidence      `json:"pro_upgrade,omitempty"`
		Invoice  *invoiceAccount                 `json:"invoice_account,omitempty"`
	}{sub, checkout, upgrade, invoiceSnapshot})
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_plan_release(team_id,actor_id,previous_offer,customer_id,subscription_id,previous_choice,previous_account,provider_status,provider_evidence,plan_change_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, c.Team, c.RequestedBy, current.PlanKey, sub.Customer, sub.ID, choiceJSON, accountJSON, sub.Status, evidence, c.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, resetProChoiceSQL, c.Team); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL,stripe_subscription_event_at=NULL,cancel_at_period_end=false,updated_at=clock_timestamp()
        WHERE team_id=$1 AND stripe_customer_id=$2 AND stripe_subscription_id=$3`, c.Team, sub.Customer, sub.ID); err != nil {
		return err
	}
	return q.FinishTeamBillingCheckout(ctx, c.Team)
}

func (h *Handlers) planChangeProcessingLease(ctx context.Context, c teamPlanChange) (*stripeWebhookProcessingLease, error) {
	if c.Subscription == nil {
		return nil, nil
	}
	var customer string
	err := h.Pool.QueryRow(ctx, `SELECT b.customer_id FROM billing_commercial_contract b JOIN team_plan_assignment a ON a.contract_id=b.id WHERE a.id=$1 AND b.team_id=$2 AND b.subscription_id=$3`, c.FromAssignment, c.Team, *c.Subscription).Scan(&customer)
	if err != nil {
		return nil, err
	}
	return claimStripeWebhookProcessingLease(ctx, h.DB, customer)
}
