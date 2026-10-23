package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

type proOffer struct {
	Key, Price string
	Amount     int64
	Months     int32
	Credit     int64
}

// Purchases started before the plan catalog carry no frozen terms.
var legacyProOffers = map[string]proOffer{
	"pro_monthly": {Key: "pro_monthly", Amount: 120000, Months: 1, Credit: 100000},
	"pro_annual":  {Key: "pro_annual", Amount: 1200000, Months: 12, Credit: 100000},
}

// paidPlanOffers matches every offer_key in the self-serve plan catalog.
const paidPlanOffers = "(SELECT offer_key FROM billing_plan)"

var errOfferUnavailable = errors.New("plan is not available")

// proOffer returns a purchasable catalog plan's current terms and configured Stripe price.
func (h *Handlers) proOffer(ctx context.Context, key string) (proOffer, error) {
	if h.Config == nil || h.Pool == nil {
		return proOffer{}, errors.New("billing is not configured")
	}
	o := proOffer{Key: key}
	var available bool
	err := h.Pool.QueryRow(ctx, `SELECT charge_amount_cents,charge_interval_months,monthly_credit_cents,available FROM billing_plan WHERE offer_key=$1`, key).Scan(&o.Amount, &o.Months, &o.Credit, &available)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !available) {
		return o, errOfferUnavailable
	}
	if err != nil {
		return o, err
	}
	o.Price = h.Config.PlanPriceID(key)
	if o.Price == "" {
		return o, errOfferUnavailable
	}
	return o, nil
}

// checkoutOffer returns the frozen terms of the team's pending purchase of key,
// or the catalog's current terms when no such purchase is pending.
func (h *Handlers) checkoutOffer(ctx context.Context, team uuid.UUID, key string) (proOffer, bool, error) {
	var choice proChoice
	err := h.Pool.QueryRow(ctx, `SELECT COALESCE(offer_key,''),state,COALESCE(base_price_id,''),request_payload FROM billing_signup_choice WHERE team_id=$1`, team).Scan(&choice.Offer, &choice.State, &choice.Price, &choice.Payload)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return proOffer{}, false, err
	}
	if err == nil && choice.State == "pending" && choice.Offer == key {
		o, err := choice.frozenOffer()
		return o, true, err
	}
	o, err := h.proOffer(ctx, key)
	return o, false, err
}

// frozenProOffer returns the terms a purchase was started with.
func frozenProOffer(key string, payload StripeCreateCheckoutSessionParams) (proOffer, error) {
	t := payload.PlanTerms
	if t == nil {
		if o, ok := legacyProOffers[key]; ok {
			return o, nil
		}
		return proOffer{}, errors.New("unsupported offer")
	}
	if t.Amount <= 0 || t.Credit <= 0 || (t.Months != 1 && t.Months != 12) {
		return proOffer{}, errors.New("invalid frozen plan terms")
	}
	return proOffer{Key: key, Amount: t.Amount, Months: t.Months, Credit: t.Credit}, nil
}

func (c proChoice) frozenOffer() (proOffer, error) {
	var params StripeCreateCheckoutSessionParams
	if err := json.Unmarshal(c.Payload, &params); err != nil {
		return proOffer{}, err
	}
	o, err := frozenProOffer(c.Offer, params)
	o.Price = c.Price
	return o, err
}

type proChoice struct {
	Team                  uuid.UUID
	Offer, State, Price   string
	Generation            time.Time
	Actor                 uuid.UUID
	Payload               []byte
	Session, Subscription *string
	Revision              int64
	LeaseToken            uuid.UUID
	InvoiceCursor         *string
}

func scanProChoice(row pgx.Row) (proChoice, error) {
	var c proChoice
	err := row.Scan(&c.Team, &c.Offer, &c.State, &c.Price, &c.Generation, &c.Actor, &c.Payload, &c.Session, &c.Subscription, &c.Revision, &c.InvoiceCursor)
	return c, err
}

const proChoiceColumns = "team_id,offer_key,state,base_price_id,generation,actor_id,request_payload,session_id,subscription_id,revision,invoice_cursor"

func (h *Handlers) getProChoice(ctx context.Context, team uuid.UUID) (proChoice, error) {
	return scanProChoice(h.Pool.QueryRow(ctx, `SELECT `+proChoiceColumns+` FROM billing_signup_choice WHERE team_id=$1 AND offer_key IN `+paidPlanOffers, team))
}
func proConflict(c *gin.Context) {
	respondErrorMsg(c, "plan_conflict", "plan selection or payment is already committed or awaiting confirmation", http.StatusConflict)
}

func (h *Handlers) createProCheckout(c *gin.Context, team, actor uuid.UUID, req billingCheckoutSessionRequest) {
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	offer, resuming, err := h.checkoutOffer(c.Request.Context(), team, req.Offer)
	if errors.Is(err, errOfferUnavailable) {
		respondErrorMsg(c, "invalid_offer", "plan is not available", http.StatusBadRequest)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if _, ok := h.Stripe.(*stripeHTTPClient); !ok {
		respondErrorMsg(c, "service_unavailable", "Pro payment verification is unavailable", http.StatusServiceUnavailable)
		return
	}
	enabled, err := h.billingExportEnabled(c.Request.Context(), team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if !enabled {
		proConflict(c)
		return
	}
	success, err := h.validateBillingRedirectURL(req.SuccessURL)
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid success URL", 400)
		return
	}
	cancelURL, err := h.validateBillingRedirectURL(req.CancelURL)
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid cancel URL", 400)
		return
	}
	storage, err := h.billingStorageBillingEnabled(c.Request.Context(), team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	prices, err := billingCheckoutPriceIDs(h.billingResourceStates(storage))
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	client := h.Stripe.(*stripeHTTPClient)
	if err = client.validateProPrice(c.Request.Context(), offer); err != nil {
		respondErrorMsg(c, "service_unavailable", "Pro price configuration requires verification", 503)
		return
	}
	terms, err := h.freezeProResourceTerms(c.Request.Context(), team, prices, client)
	if err != nil {
		respondErrorMsg(c, "service_unavailable", "Pro resource configuration requires verification", 503)
		return
	}
	customer, err := h.ensureStripeCustomer(c.Request.Context(), team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	params := StripeCreateCheckoutSessionParams{CustomerID: customer, SuccessURL: success, CancelURL: cancelURL, ClientReferenceID: team.String(), PriceIDs: prices, BasePriceID: offer.Price, Flexible: true, ResourceTerms: terms,
		PlanTerms: &StripeCheckoutPlanTerms{Amount: offer.Amount, Months: offer.Months, Credit: offer.Credit}}
	if offer.Months == 12 {
		// Checkout cannot mix annual fees with monthly usage. Keep the actual
		// request frozen so older replicas also replay the base-only session.
		params.PriceIDs = nil
		params.DeferredResourcePriceIDs = prices
	}
	ctx := c.Request.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	account, err := q.LockTeamBillingAccount(ctx, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	var state string
	var selected *string
	err = tx.QueryRow(ctx, `SELECT state,offer_key FROM billing_signup_choice WHERE team_id=$1 FOR UPDATE`, team).Scan(&state, &selected)
	if errors.Is(err, pgx.ErrNoRows) {
		proConflict(c)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if state == "committed" || (selected != nil && *selected != offer.Key) || account.StripeSubscriptionID != nil || account.TrialEndedAt.Valid || account.StripeActivationCreditReservedAt.Valid || account.StripeActivationCreditGrantID != nil {
		proConflict(c)
		return
	}
	attempt := uuid.New()
	var choice proChoice
	if state == "selecting" {
		if resuming || account.CheckoutInitializingAt.Valid || account.CheckoutCompletedAt.Valid {
			proConflict(c)
			return
		}
		var generation time.Time
		if err = tx.QueryRow(ctx, `SELECT now()`).Scan(&generation); err != nil {
			respondError(c, ErrInternal)
			return
		}
		expires := generation.Add(checkoutSessionLifetime - time.Minute)
		params.ExpiresAt = &expires
		params.Metadata = map[string]string{"activation_user_id": actor.String(), "checkout_generation": generation.Format(time.RFC3339Nano), "commercial_offer": offer.Key}
		params.IdempotencyKey = "pro:" + checkoutSessionIdempotencyKeyForLease(team, customer, success, cancelURL, append(append([]string{}, prices...), offer.Price), generation)
		payload, _ := json.Marshal(params)
		_, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET state='pending',offer_key=$2,base_price_id=$3,generation=$4,actor_id=$5,request_payload=$6,revision=revision+1,next_check_at=now() WHERE team_id=$1`, team, offer.Key, offer.Price, generation, actor, payload)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE team_billing_account SET checkout_initializing_at=$2,checkout_request_key=$3,checkout_pending_attempt_ids=ARRAY[$4::uuid],checkout_may_exist=false,stripe_checkout_actor_id=$5,stripe_checkout_actor_claimed_at=$2,checkout_anchor_snapshot=commercial_billing_anchor WHERE team_id=$1`, team, generation, params.IdempotencyKey, attempt, actor)
		}
		choice = proChoice{Team: team, Offer: offer.Key, Price: offer.Price, Actor: actor, Generation: generation, Payload: payload}
	} else {
		choice, err = scanProChoice(tx.QueryRow(ctx, `SELECT `+proChoiceColumns+` FROM billing_signup_choice WHERE team_id=$1`, team))
		if err == nil {
			err = json.Unmarshal(choice.Payload, &params)
		}
		if err == nil && (choice.Actor != actor || params.SuccessURL != success || params.CancelURL != cancelURL || choice.Price != offer.Price) {
			proConflict(c)
			return
		}
		if err == nil {
			_, err = q.ResumeTeamBillingCheckout(ctx, db.ResumeTeamBillingCheckoutParams{TeamID: team, ActorID: pgtype.UUID{Bytes: actor, Valid: true}, RequestKey: &params.IdempotencyKey, AttemptID: attempt})
		}
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			proConflict(c)
		} else {
			respondError(c, ErrInternal)
		}
		return
	}
	if err = tx.Commit(ctx); err != nil {
		respondError(c, ErrInternal)
		return
	}
	session, err := h.Stripe.CreateCheckoutSession(ctx, params)
	if err != nil {
		released, finishErr := h.finishProCheckoutAttempt(ctx, choice, attempt, !definitiveStripeRejection(err))
		if finishErr == nil && released {
			respondErrorMsg(c, "checkout_rejected", "checkout could not be created; choose a plan again", http.StatusBadRequest)
			return
		}
		respondErrorMsg(c, "payment_confirmation_pending", "checkout outcome requires recovery", http.StatusAccepted)
		return
	}
	// The existing attempt fence survives a crash or lost provider response.
	tx, err = h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	q = h.DB.WithTx(tx)
	_, err = q.SetTeamBillingCheckoutSession(ctx, db.SetTeamBillingCheckoutSessionParams{TeamID: team, SessionID: &session.ID, LeaseStartedAt: pgtype.Timestamptz{Time: choice.Generation, Valid: true}, AttemptID: attempt})
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET session_id=$2,revision=revision+1 WHERE team_id=$1 AND generation=$3`, team, session.ID, choice.Generation)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, billingSessionResponse{ID: session.ID, URL: session.URL})
}

// Free/Enterprise onboarding commits the same PAYG decision, without creating Stripe objects.
func (h *Handlers) CommitFreeSignupPlan(c *gin.Context) {
	team, err := customerContextTeamID(c)
	if err != nil {
		return
	}
	if !h.requireCustomerTeamPermission(c, team, "billing:write") {
		return
	}
	var input struct {
		Offer string `json:"offer"`
	}
	if c.ShouldBindJSON(&input) != nil || input.Offer != "free" {
		respondErrorMsg(c, "bad_request", "offer must be free", 400)
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	actor, err := customerActorID(c)
	if err != nil {
		return
	}
	if err = h.commitFreeFundingPlan(c.Request.Context(), team, actor); err != nil {
		if errors.Is(err, errFundingPlanTransition) {
			respondErrorMsg(c, "plan_conflict", err.Error(), http.StatusConflict)
		} else {
			respondError(c, ErrInternal)
		}
		return
	}
	c.JSON(200, gin.H{"offer": "free", "state": "committed"})
}

func (c *stripeHTTPClient) validateProPrice(ctx context.Context, o proOffer) error {
	var p storagePrice
	if err := c.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(o.Price), nil, &p, ""); err != nil {
		return err
	}
	interval := "month"
	if o.Months == 12 {
		interval = "year"
	}
	if p.ID != o.Price || !p.Active || p.Currency != "usd" || p.BillingScheme != "per_unit" || p.TransformQuantity != nil || p.Recurring.UsageType != "licensed" || p.Recurring.Interval != interval || p.Recurring.IntervalCount != 1 || p.UnitAmountDecimal != fmt.Sprint(o.Amount) {
		return errors.New("unexpected Pro licensed price")
	}
	return nil
}

func (h *Handlers) processProWebhook(ctx context.Context, event stripeEventEnvelope) (bool, error) {
	if h.Pool == nil {
		return false, nil
	}
	if !strings.HasPrefix(event.Type, "invoice.") && !strings.HasPrefix(event.Type, "customer.subscription.") && !strings.HasPrefix(event.Type, "checkout.session.") {
		return false, nil
	}
	var obj struct {
		Customer     string `json:"customer"`
		ID           string `json:"id"`
		Subscription string `json:"subscription"`
		Parent       struct {
			SubscriptionDetails *struct {
				Subscription string `json:"subscription"`
			} `json:"subscription_details"`
		} `json:"parent"`
	}
	if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
		return false, err
	}
	subscription := obj.Subscription
	if strings.HasPrefix(event.Type, "customer.subscription.") {
		subscription = obj.ID
	}
	if obj.Parent.SubscriptionDetails != nil {
		subscription = obj.Parent.SubscriptionDetails.Subscription
	}
	var adopted bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_sponsored_annual_authority WHERE customer_id=$1 AND subscription_id=$2 AND state<>'ended')`, obj.Customer, subscription).Scan(&adopted); err != nil {
		return false, err
	}
	if adopted {
		if _, err := h.Pool.Exec(ctx, `UPDATE billing_sponsored_annual_authority SET next_check_at=clock_timestamp() WHERE customer_id=$1 AND subscription_id=$2 AND state<>'ended'`, obj.Customer, subscription); err != nil {
			return true, err
		}
		if strings.HasPrefix(event.Type, "invoice.") {
			// Invoice projection and collection wakeups still belong to the
			// generic handler; only verified reconciliation can activate renewal.
			return false, nil
		}
		_, err := h.DB.MarkStripeWebhookEventProcessed(ctx, event.ID)
		return true, err
	}
	var yc bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_yc_operation o WHERE customer_id=$1 AND NOT billing_yc_released(o.team_id))`, obj.Customer).Scan(&yc); err != nil {
		return false, err
	}
	if yc {
		if _, err := h.Pool.Exec(ctx, `UPDATE billing_yc_operation SET next_check_at=clock_timestamp() WHERE customer_id=$1`, obj.Customer); err != nil {
			return true, err
		}
		_, err := h.DB.MarkStripeWebhookEventProcessed(ctx, event.ID)
		return true, err
	}
	var released bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_plan_release WHERE customer_id=$1 AND (subscription_id=$2 OR previous_choice->>'session_id'=$3))`, obj.Customer, subscription, obj.ID).Scan(&released); err != nil {
		return false, err
	}
	if released {
		if strings.HasPrefix(event.Type, "invoice.") {
			if _, err := h.Pool.Exec(ctx, `UPDATE billing_invoice_collection SET next_attempt_at=LEAST(next_attempt_at,clock_timestamp()) WHERE invoice_id=$1 AND customer_id=$2 AND state NOT IN ('paid','void')`, obj.ID, obj.Customer); err != nil {
				return true, err
			}
		}
		_, err := h.DB.MarkStripeWebhookEventProcessed(ctx, event.ID)
		return true, err
	}
	var closed bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_pro_closed_purchase p JOIN team_billing_account a USING(team_id) WHERE a.stripe_customer_id=$1 AND (p.subscription_id=$2 OR p.session_id=$3))`, obj.Customer, subscription, obj.ID).Scan(&closed); err != nil {
		return false, err
	}
	if closed {
		_, err := h.DB.MarkStripeWebhookEventProcessed(ctx, event.ID)
		return true, err
	}
	var team uuid.UUID
	err := h.Pool.QueryRow(ctx, `SELECT b.team_id FROM team_billing_account b JOIN billing_signup_choice c USING(team_id) WHERE b.stripe_customer_id=$1 AND c.offer_key IN `+paidPlanOffers, obj.Customer).Scan(&team)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = h.reconcileProCheckout(ctx, team, false)
	if err != nil {
		return true, err
	}
	_, err = h.DB.MarkStripeWebhookEventProcessed(ctx, event.ID)
	return true, err
}

const resetProChoiceSQL = `UPDATE billing_signup_choice SET offer_key=NULL,state='selecting',generation=NULL,actor_id=NULL,base_price_id=NULL,request_payload=NULL,session_id=NULL,subscription_id=NULL,invoice_cursor=NULL,last_error=NULL,paid_observed_at=NULL,paid_observed_until=NULL,revision=revision+1 WHERE team_id=$1`

func (h *Handlers) finishProCheckoutAttempt(ctx context.Context, choice proChoice, attempt uuid.UUID, mayExist bool) (bool, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if _, err = q.LockTeamBillingAccount(ctx, choice.Team); err != nil {
		return false, err
	}
	if err = q.FinishFailedTeamBillingCheckoutAttempt(ctx, db.FinishFailedTeamBillingCheckoutAttemptParams{TeamID: choice.Team, LeaseStartedAt: pgtype.Timestamptz{Time: choice.Generation, Valid: true}, AttemptID: attempt, MayExist: mayExist}); err != nil {
		return false, err
	}
	var released bool
	err = tx.QueryRow(ctx, `SELECT a.checkout_initializing_at IS NULL AND a.stripe_subscription_id IS NULL AND c.generation=$2 AND c.state='pending' FROM team_billing_account a JOIN billing_signup_choice c USING(team_id) WHERE team_id=$1 FOR UPDATE`, choice.Team, choice.Generation).Scan(&released)
	if err != nil {
		return false, err
	}
	if released {
		if _, err = tx.Exec(ctx, resetProChoiceSQL, choice.Team); err != nil {
			return false, err
		}
	}
	return released, tx.Commit(ctx)
}
