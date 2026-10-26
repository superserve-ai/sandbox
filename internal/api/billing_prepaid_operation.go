package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

var errPrepaidOperationConflict = errors.New("checkout operation is bound to another purchase request")

type prepaidOperationResponse struct {
	ID         string    `json:"id,omitempty"`
	URL        string    `json:"url,omitempty"`
	PurchaseID uuid.UUID `json:"purchase_id"`
	State      string    `json:"state"`
}

// Existing accepted terms remain recoverable after redirect policy changes.
func (h *Handlers) acceptedPrepaidCheckoutOperation(ctx context.Context, team, actor uuid.UUID, req prepaidCheckoutBody) (bool, error) {
	var matches, accepted bool
	err := h.Pool.QueryRow(ctx, `SELECT o.team_id=$2 AND o.actor_id=$3 AND o.amount_cents=$4 AND o.success_url=$5 AND o.cancel_url=$6,
		EXISTS(SELECT 1 FROM billing_prepaid_purchase p WHERE p.id=o.id AND p.team_id=o.team_id AND p.actor_id=o.actor_id AND p.amount_cents=o.amount_cents AND p.source='checkout')
		FROM billing_prepaid_checkout_operation o WHERE o.id=$1`, req.OperationID, team, actor, req.AmountCents, req.SuccessURL, req.CancelURL).Scan(&matches, &accepted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !matches {
		return false, errPrepaidOperationConflict
	}
	return accepted, nil
}

func (h *Handlers) bindPrepaidCheckoutOperation(ctx context.Context, team, actor uuid.UUID, req prepaidCheckoutBody) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO billing_prepaid_checkout_operation(id,team_id,actor_id,amount_cents,success_url,cancel_url) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING`, req.OperationID, team, actor, req.AmountCents, req.SuccessURL, req.CancelURL)
	if err != nil {
		return err
	}
	var matches bool
	if err = tx.QueryRow(ctx, `SELECT team_id=$2 AND actor_id=$3 AND amount_cents=$4 AND success_url=$5 AND cancel_url=$6 FROM billing_prepaid_checkout_operation WHERE id=$1`, req.OperationID, team, actor, req.AmountCents, req.SuccessURL, req.CancelURL).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return errPrepaidOperationConflict
	}
	return tx.Commit(ctx)
}

// Replays precede new-entry checks: a changed plan or rollout switch must not
// turn a lost response for an accepted purchase into another payment.
func (h *Handlers) resumePrepaidCheckoutOperation(c *gin.Context, client *stripeHTTPClient, team, actor uuid.UUID, req prepaidCheckoutBody) (bool, error) {
	ctx := c.Request.Context()
	var customer, payment, credit string
	var session *string
	var raw, proof []byte
	err := h.Pool.QueryRow(ctx, `SELECT customer_id,payment_state,credit_state,checkout_session_id,payment_request,payment_evidence->'checkout_session' FROM billing_prepaid_purchase WHERE id=$1 AND team_id=$2 AND actor_id=$3 AND amount_cents=$4 AND source='checkout'`, req.OperationID, team, actor, req.AmountCents).Scan(&customer, &payment, &credit, &session, &raw, &proof)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	response := prepaidOperationResponse{PurchaseID: req.OperationID, State: "pending"}
	terminal := func() bool {
		if payment == "failed" {
			response.State = "failed"
		} else if credit == "issued" {
			response.State = "credited"
		} else if payment == "succeeded" {
			response.State = "paid"
		} else {
			return false
		}
		if len(raw) == 0 && payment == "succeeded" {
			var saved prepaidCheckoutSession
			if json.Unmarshal(proof, &saved) == nil && saved.Mode == "subscription" {
				// Settlement remains authoritative during provider outages or later plan
				// changes. Repair only a still-unpublished original lease from its proof.
				if err := h.restorePrepaidSubscriptionCheckout(ctx, team, actor, req.OperationID, customer, saved, true); err != nil {
					log.Warn().Err(err).Str("team_id", team.String()).Str("purchase_id", req.OperationID.String()).Msg("settled prepaid checkout association awaits recovery")
				}
			}
		}
		c.JSON(http.StatusOK, response)
		return true
	}
	if terminal() {
		return true, nil
	}
	if client == nil {
		return true, errPrepaidPaymentPending
	}
	if session == nil {
		if len(raw) > 0 {
			err = h.settleCheckoutPurchase(ctx, client, req.OperationID)
			if err != nil && !errors.Is(err, errPrepaidPaymentPending) {
				return true, err
			}
		} else {
			found, findErr := client.findPrepaidCheckout(ctx, customer, req.OperationID)
			if findErr != nil {
				return true, findErr
			}
			if found != "" {
				session = &found
			} else {
				account, accountErr := h.DB.GetTeamBillingAccount(ctx, team)
				if accountErr != nil {
					return true, accountErr
				}
				// The original subscription request is protected by its existing lease.
				if !billingAccountHasEstablishedSubscription(account) {
					return false, nil
				}
			}
		}
		var recorded *string
		if err = h.Pool.QueryRow(ctx, `SELECT payment_state,credit_state,checkout_session_id,payment_evidence->'checkout_session' FROM billing_prepaid_purchase WHERE id=$1`, req.OperationID).Scan(&payment, &credit, &recorded, &proof); err != nil {
			return true, err
		}
		if recorded != nil {
			session = recorded
		}
		if terminal() {
			return true, nil
		}
	}
	if session == nil {
		c.JSON(http.StatusAccepted, response)
		return true, nil
	}
	saved, err := client.retrievePrepaidCheckout(ctx, *session)
	if err != nil {
		return true, err
	}
	if saved.Customer != customer || saved.Metadata["prepaid_purchase_id"] != req.OperationID.String() {
		return true, errors.New("checkout session differs from the operation")
	}
	if len(raw) == 0 && saved.Status != "expired" {
		var managed bool
		if err = h.Pool.QueryRow(ctx, `SELECT qm_team_managed_billing($1)`, team).Scan(&managed); err != nil {
			return true, err
		}
		if managed {
			c.JSON(http.StatusAccepted, response)
			return true, nil
		}
		if err = h.restorePrepaidSubscriptionCheckout(ctx, team, actor, req.OperationID, customer, saved, false); err != nil {
			return true, err
		}
	}
	if terminal() {
		return true, nil
	}
	if saved.Status == "expired" {
		if err = h.failPrepaidPayment(ctx, req.OperationID, "", "the checkout was not completed", false); err != nil {
			return true, err
		}
		if err = h.Pool.QueryRow(ctx, `SELECT payment_state,credit_state FROM billing_prepaid_purchase WHERE id=$1`, req.OperationID).Scan(&payment, &credit); err != nil {
			return true, err
		}
		if terminal() {
			return true, nil
		}
		c.JSON(http.StatusAccepted, response)
		return true, nil
	}
	if saved.Status == "open" {
		response.ID, response.URL = saved.ID, saved.URL
		c.JSON(http.StatusOK, response)
	} else {
		c.JSON(http.StatusAccepted, response)
	}
	return true, nil
}

// A provider response can be lost before either local association is written.
// Restore both under the original lease fence before exposing its Checkout URL.
func (h *Handlers) restorePrepaidSubscriptionCheckout(ctx context.Context, team, actor, purchase uuid.UUID, customer string, saved prepaidCheckoutSession, unresolvedOnly bool) error {
	generation, err := time.Parse(time.RFC3339Nano, saved.Metadata["checkout_generation"])
	if err != nil || saved.Mode != "subscription" || saved.ClientReferenceID != team.String() || saved.Metadata["activation_user_id"] != actor.String() || saved.Metadata["prepaid_purchase_id"] != purchase.String() || saved.Customer != customer || saved.ID == "" {
		return errors.New("recovered subscription checkout identity differs")
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if _, err = q.LockTeamBillingAccount(ctx, team); err != nil {
		return err
	}
	// The lock helper returns the billing projection; read the full lease tuple
	// while retaining that row lock for the actor and request-key checks.
	account, err := q.GetTeamBillingCheckoutForRecovery(ctx, team)
	if err != nil {
		return err
	}
	sameOwner := derefString(account.StripeCustomerID) == customer && account.StripeCheckoutActorID.Valid && uuid.UUID(account.StripeCheckoutActorID.Bytes) == actor
	sameLease := account.CheckoutInitializingAt.Valid && account.CheckoutInitializingAt.Time.Equal(generation) && strings.HasSuffix(derefString(account.CheckoutRequestKey), ":prepaid-operation:"+purchase.String())
	if unresolvedOnly && (!sameOwner || !sameLease || account.CheckoutSessionID != nil) {
		return nil
	}
	if !sameOwner || (account.CheckoutSessionID != nil && *account.CheckoutSessionID != saved.ID) {
		return errors.New("subscription checkout association changed during recovery")
	}
	if account.CheckoutInitializingAt.Valid {
		if !sameLease {
			return errors.New("subscription checkout lease changed during recovery")
		}
		expired, err := q.HasStripeCheckoutExpiration(ctx, team, customer, generation)
		if err != nil {
			return err
		}
		if expired {
			return errors.New("subscription checkout generation already expired")
		}
		if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET checkout_session_id=$2,checkout_may_exist=true,updated_at=clock_timestamp() WHERE team_id=$1`, team, saved.ID); err != nil {
			return err
		}
	} else if saved.Subscription == "" || derefString(account.StripeSubscriptionID) != saved.Subscription || derefString(account.CheckoutSubscriptionID) != saved.Subscription {
		return errors.New("subscription checkout lease is no longer current")
	}
	tag, err := tx.Exec(ctx, `UPDATE billing_prepaid_purchase SET checkout_session_id=$2,payment_state=CASE WHEN payment_state IN ('pending','uncertain') THEN 'processing' ELSE payment_state END WHERE id=$1 AND team_id=$3 AND actor_id=$4 AND customer_id=$5 AND source='checkout' AND (checkout_session_id IS NULL OR checkout_session_id=$2) AND payment_state<>'failed'`, purchase, saved.ID, team, actor, customer)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("purchase checkout association changed during recovery")
	}
	return tx.Commit(ctx)
}
