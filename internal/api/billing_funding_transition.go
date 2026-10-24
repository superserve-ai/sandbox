package api

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

var errFundingPlanTransition = errors.New("the previous purchase must be reconciled and its subscription terminated before choosing Free")

// Choosing Free is an explicit release, never permission to cancel a subscription.
// Keep the old account association until Checkout verifies its replacement.
func (h *Handlers) commitFreeFundingPlan(ctx context.Context, team, actor uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := h.Pool.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1) ON CONFLICT DO NOTHING`, team); err != nil {
		return err
	}
	account, err := h.DB.GetTeamBillingAccount(ctx, team)
	if err != nil {
		return err
	}
	var lease *stripeWebhookProcessingLease
	if customer := derefString(account.StripeCustomerID); customer != "" {
		lease, err = claimStripeWebhookProcessingLease(ctx, h.DB, customer)
		if err != nil {
			return err
		}
		defer func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			_ = h.DB.ReleaseStripeWebhookProcessingLease(cleanup, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: lease.CustomerID, Token: lease.Token})
		}()
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rawPricing, entryOpen, err := lockPricingEntry(ctx, tx)
	if err != nil {
		return err
	}
	if lease != nil {
		if err = lease.lock(ctx, h.DB.WithTx(tx)); err != nil {
			return err
		}
	}
	locked, err := h.DB.WithTx(tx).LockTeamBillingAccount(ctx, team)
	if err != nil {
		return err
	}
	// The lock helper returns only the activation projection; checkout release
	// also needs its request key and in-flight attempt fences.
	if err = tx.QueryRow(ctx, `SELECT checkout_request_key,checkout_pending_attempt_ids,checkout_may_exist FROM team_billing_account WHERE team_id=$1`, team).Scan(&locked.CheckoutRequestKey, &locked.CheckoutPendingAttemptIds, &locked.CheckoutMayExist); err != nil {
		return err
	}
	if derefString(locked.StripeCustomerID) != derefString(account.StripeCustomerID) {
		return errFundingPlanTransition
	}
	var annual bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_sponsored_annual_authority WHERE team_id=$1 AND state<>'ended')`, team).Scan(&annual); err != nil {
		return err
	}
	if annual {
		return errFundingPlanTransition
	}
	var choiceJSON, accountJSON, ycJSON []byte
	var offer, choiceSubscription *string
	var choiceState string
	err = tx.QueryRow(ctx, `SELECT to_jsonb(c),offer_key,state,subscription_id FROM billing_signup_choice c WHERE team_id=$1 FOR UPDATE`, team).Scan(&choiceJSON, &offer, &choiceState, &choiceSubscription)
	if errors.Is(err, pgx.ErrNoRows) {
		choiceJSON = []byte(`{}`)
		err = nil
	}
	if err != nil {
		return err
	}
	var operation pgtype.UUID
	var ycCustomer, ycSubscription *string
	var ycState string
	var ycAttempt, ycRevoked pgtype.Timestamptz
	err = tx.QueryRow(ctx, `SELECT to_jsonb(o),id,customer_id,subscription_id,state,provider_attempt_at,revoked_at FROM billing_yc_operation o WHERE team_id=$1 FOR UPDATE`, team).Scan(&ycJSON, &operation, &ycCustomer, &ycSubscription, &ycState, &ycAttempt, &ycRevoked)
	if !errors.Is(err, pgx.ErrNoRows) && err != nil {
		return err
	}
	var ycReleased bool
	if operation.Valid {
		if err = tx.QueryRow(ctx, `SELECT billing_yc_released($1)`, team).Scan(&ycReleased); err != nil {
			return err
		}
	}
	needsRelease := (operation.Valid && !ycReleased) || (offer != nil && *offer != "free")
	if !needsRelease {
		if offer != nil && *offer == "free" && choiceState == "committed" {
			return tx.Commit(ctx)
		}
		if rawPricing == "v2" && !entryOpen {
			return errFundingPlanTransition
		}
		if rawPricing == "v2" {
			var assigned, available bool
			if err = tx.QueryRow(ctx, `SELECT to_regclass('team_plan_assignment') IS NOT NULL`).Scan(&available); err != nil {
				return err
			}
			if available {
				err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL AND kind='free')`, team).Scan(&assigned)
				if err != nil {
					return err
				}
			}
			if !assigned {
				return errFundingPlanTransition
			}
		}
		// "free" here is the legacy pay-as-you-go choice, not the v2 Free
		// plan family; v2 code reads a team's plan from its plan assignment.
		_, err = tx.Exec(ctx, `INSERT INTO billing_signup_choice(team_id,offer_key,state) VALUES($1,'free','committed') ON CONFLICT(team_id) DO UPDATE SET offer_key='free',state='committed',revision=billing_signup_choice.revision+1`, team)
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if choiceState == "pending" || len(locked.CheckoutPendingAttemptIds) != 0 || locked.StripeActivationCreditReservedAt.Valid {
		return errFundingPlanTransition
	}
	customer, subscription := derefString(locked.StripeCustomerID), derefString(locked.StripeSubscriptionID)
	if operation.Valid && !ycReleased {
		if ycState != "ended" || derefString(ycCustomer) != customer || derefString(ycSubscription) != subscription {
			return errFundingPlanTransition
		}
		subscription = derefString(ycSubscription)
	} else {
		operation = pgtype.UUID{}
		ycJSON = nil
	}
	if choiceSubscription != nil && *choiceSubscription != "" && *choiceSubscription != subscription {
		return errFundingPlanTransition
	}
	retainedCheckout := locked.CheckoutInitializingAt.Valid || locked.CheckoutMayExist
	providerStatus := "no_attempt"
	evidence := []byte(`{}`)
	if subscription == "" {
		if retainedCheckout || !operation.Valid || !ycRevoked.Valid || ycAttempt.Valid {
			return errFundingPlanTransition
		}
	} else {
		client, ok := h.Stripe.(*stripeHTTPClient)
		if !ok {
			return errors.New("provider verification unavailable")
		}
		sub, e := client.invoiceSubscription(ctx, subscription)
		if e != nil {
			return e
		}
		if sub.ID != subscription || sub.Customer != customer || (sub.Status != "canceled" && sub.Status != "incomplete_expired") {
			return errFundingPlanTransition
		}
		var checkout *StripeRetrievedCheckoutSession
		if retainedCheckout {
			if operation.Valid || offer == nil || *offer == "free" || !locked.CheckoutInitializingAt.Valid {
				return errFundingPlanTransition
			}
			choice, e := scanProChoice(tx.QueryRow(ctx, `SELECT `+proChoiceColumns+` FROM billing_signup_choice WHERE team_id=$1`, team))
			if e != nil {
				return e
			}
			var params StripeCreateCheckoutSessionParams
			if e = json.Unmarshal(choice.Payload, &params); e != nil {
				return e
			}
			if choice.State != "committed" || choice.Session == nil || *choice.Session == "" || derefString(locked.CheckoutSessionID) != *choice.Session || !choice.Generation.Equal(locked.CheckoutInitializingAt.Time) || params.CustomerID != customer || params.IdempotencyKey == "" || params.IdempotencyKey != derefString(locked.CheckoutRequestKey) || derefString(choice.Subscription) != subscription || (locked.CheckoutSubscriptionID != nil && *locked.CheckoutSubscriptionID != subscription) {
				return errFundingPlanTransition
			}
			session, e := client.RetrieveCheckoutSession(ctx, *choice.Session)
			if e != nil {
				return e
			}
			generation := params.Metadata["checkout_generation"]
			generationTime, e := time.Parse(time.RFC3339Nano, generation)
			if e != nil || !generationTime.Equal(choice.Generation) {
				return errFundingPlanTransition
			}
			if session.ID != *choice.Session || session.CustomerID != customer || session.ClientReferenceID != team.String() || session.Status != "complete" || session.Mode != "subscription" || session.SubscriptionID != subscription || session.Metadata["checkout_generation"] != generation || session.Metadata["commercial_offer"] != choice.Offer || session.Metadata["activation_user_id"] != choice.Actor.String() || sub.Metadata["checkout_generation"] != generation || sub.Metadata["commercial_offer"] != choice.Offer {
				return errFundingPlanTransition
			}
			checkout = &session
		}
		providerStatus = sub.Status
		evidence, err = json.Marshal(struct {
			invoiceSubscription
			Checkout *StripeRetrievedCheckoutSession `json:"checkout,omitempty"`
		}{sub, checkout})
		if err != nil {
			return err
		}
	}
	var conflictingContract bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND status<>'ended' AND (customer_id<>$2 OR subscription_id<>$3))`, team, customer, subscription).Scan(&conflictingContract); err != nil {
		return err
	}
	if conflictingContract {
		return errFundingPlanTransition
	}
	if subscription != "" {
		if _, err = tx.Exec(ctx, `UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3 AND status<>'ended'`, team, customer, subscription); err != nil {
			return err
		}
	}
	if err = tx.QueryRow(ctx, `SELECT to_jsonb(a) FROM team_billing_account a WHERE team_id=$1`, team).Scan(&accountJSON); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_plan_release(team_id,actor_id,previous_offer,customer_id,subscription_id,yc_operation_id,previous_choice,previous_account,previous_yc,provider_status,provider_evidence) VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8,$9,$10,$11)`, team, actor, offer, customer, subscription, operation, choiceJSON, accountJSON, ycJSON, providerStatus, evidence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET offer_key='free',state='committed',generation=NULL,actor_id=NULL,base_price_id=NULL,request_payload=NULL,session_id=NULL,subscription_id=NULL,invoice_cursor=NULL,last_error=NULL,paid_observed_at=NULL,paid_observed_until=NULL,revision=revision+1,next_check_at='infinity' WHERE team_id=$1`, team)
	if err != nil {
		return err
	}
	if subscription != "" && derefString(locked.StripeSubscriptionID) == subscription {
		if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_status=$2 WHERE team_id=$1 AND stripe_subscription_id=$3`, team, providerStatus, subscription); err != nil {
			return err
		}
	}
	if retainedCheckout {
		if err = h.DB.WithTx(tx).FinishTeamBillingCheckout(ctx, team); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `SELECT apply_plan_limits($1,'free')`, team); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
