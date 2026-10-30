package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type proUpgrade struct {
	ID, Team, Actor                             uuid.UUID
	Customer, Offer, State                      string
	Subscription, Session, Grant, PaymentMethod *string
	Contract                                    *uuid.UUID
	Payload                                     []byte
	Anchor, Start, End, Quoted                  time.Time
	Amount                                      int64
	BridgeCredit                                *int64
	GrantAttempt                                *time.Time
	RecurringAttempt, BaseCreated               *time.Time
	InitialAssignment                           *uuid.UUID
	Evidence                                    []byte
}

const proUpgradeColumns = `id,team_id,actor_id,customer_id,subscription_id,offer_key,state,session_id,grant_id,payment_method_id,contract_id,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,grant_attempted_at,payment_evidence,recurring_attempted_at,base_created_at,initial_assignment_id,bridge_credit_cents`

func scanProUpgrade(row pgx.Row) (u proUpgrade, err error) {
	err = row.Scan(&u.ID, &u.Team, &u.Actor, &u.Customer, &u.Subscription, &u.Offer, &u.State, &u.Session, &u.Grant, &u.PaymentMethod, &u.Contract, &u.Payload, &u.Anchor, &u.Start, &u.End, &u.Quoted, &u.Amount, &u.GrantAttempt, &u.Evidence, &u.RecurringAttempt, &u.BaseCreated, &u.InitialAssignment, &u.BridgeCredit)
	return
}

// NULL identifies accepted operations predating independent credit quotes.
func (u proUpgrade) bridgeCreditAmount() int64 {
	if u.BridgeCredit != nil {
		return *u.BridgeCredit
	}
	return u.Amount
}

func (h *Handlers) proUpgrade(ctx context.Context, team uuid.UUID) (proUpgrade, error) {
	return scanProUpgrade(h.Pool.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE team_id=$1 AND state NOT IN ('expired','ended')`, team))
}

func proratedProAmount(amount int64, start, end, at time.Time) (int64, error) {
	duration, remaining := end.Unix()-start.Unix(), end.Unix()-at.Unix()
	if amount < 0 || duration <= 0 || remaining <= 0 || at.Before(start) || remaining > duration {
		return 0, errors.New("invalid Pro proration window")
	}
	n := new(big.Int).Mul(big.NewInt(amount), big.NewInt(remaining))
	n.Add(n, big.NewInt(duration/2)).Quo(n, big.NewInt(duration))
	if !n.IsInt64() {
		return 0, errors.New("Pro proration exceeds supported amount")
	}
	return n.Int64(), nil
}

func proUpgradeCheckoutDescription(offer proOffer, amount, credit int64, quoted, end time.Time, promotionCodes bool) string {
	money := func(cents int64) string { return fmt.Sprintf("$%d.%02d", cents/100, cents%100) }
	date := func(at time.Time) string { return at.UTC().Format("Jan 2, 2006 15:04 MST") }
	text := fmt.Sprintf("Prorated first payment (before any promotion): %s for %s to %s. Includes %s non-expiring usage credit. From %s, renews at %s/month with %s usage credit per billing month; monthly credit expires at the end of that billing month.", money(amount), date(quoted), date(end), money(credit), date(end), money(offer.Amount), money(offer.Credit))
	if promotionCodes {
		text += " Promotion codes apply only to this first payment."
	}
	return text
}

func proFirstCycleCheckoutDescription(offer proOffer, start, end time.Time, promotionCodes bool) string {
	money := func(cents int64) string { return fmt.Sprintf("$%d.%02d", cents/100, cents%100) }
	date := func(at time.Time) string { return at.UTC().Format("Jan 2, 2006 15:04 MST") }
	text := fmt.Sprintf("First monthly payment (before any promotion): %s for %s to %s. Includes %s usage credit that expires at the end of this billing month. From %s, renews at %s/month with %s usage credit per billing month; monthly credit expires at the end of that billing month.", money(offer.Amount), date(start), date(end), money(offer.Credit), date(end), money(offer.Amount), money(offer.Credit))
	if promotionCodes {
		text += " Promotion codes apply only to this first payment."
	}
	return text
}

// Unmarked requests retain their accepted non-expiring bridge credit terms.
func (u proUpgrade) creditExpiry() (int64, error) {
	if len(u.Payload) == 0 {
		return 0, nil
	}
	var params StripeCreateCheckoutSessionParams
	if err := json.Unmarshal(u.Payload, &params); err != nil {
		return 0, err
	}
	if !params.FirstPaidProCycle {
		return 0, nil
	}
	_, end, ok := billing.AnniversaryPeriod(u.Anchor, u.Anchor)
	if !ok || !u.Anchor.Equal(u.Start) || !u.Start.Equal(u.Quoted) || !u.End.Equal(end) || params.PlanTerms == nil || params.PlanTerms.Months != 1 || params.PlanTerms.Amount != u.Amount || params.PlanTerms.Credit != u.bridgeCreditAmount() {
		return 0, errors.New("first Pro billing month differs from accepted terms")
	}
	// The closing usage invoice includes the boundary second; customer credit
	// still expires at the logical month end, as with recurring allowances.
	return u.End.Unix() + 1, nil
}

func (h *Handlers) createProUpgrade(c *gin.Context, team, actor uuid.UUID, offer proOffer, params StripeCreateCheckoutSessionParams, admission pricingPublicState) {
	ctx := c.Request.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	priorReplay, replayErr := scanProUpgrade(tx.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE team_id=$1 AND state NOT IN ('expired','ended')`, team))
	if replayErr == nil {
		if priorReplay.Actor != actor || priorReplay.Offer != offer.Key || (params.OperationID != uuid.Nil && params.OperationID != priorReplay.ID) {
			proConflict(c)
			return
		}
		tx.Rollback(ctx)
		h.resumeProUpgradeCheckout(c, priorReplay)
		return
	}
	if !errors.Is(replayErr, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	if err = lockProAdmission(ctx, tx, admission); err != nil {
		respondProAdmission(c, err)
		return
	}
	a, err := h.DB.WithTx(tx).LockTeamBillingAccount(ctx, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	prior, priorErr := scanProUpgrade(tx.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE team_id=$1 AND state NOT IN ('expired','ended')`, team))
	if priorErr == nil {
		if prior.Actor != actor || prior.Offer != offer.Key || (params.OperationID != uuid.Nil && params.OperationID != prior.ID) {
			proConflict(c)
			return
		}
		if err = tx.Commit(ctx); err != nil {
			respondError(c, ErrInternal)
			return
		}
		h.resumeProUpgradeCheckout(c, prior)
		return
	}
	if !errors.Is(priorErr, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	if _, err = tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if err = lockProOffer(ctx, tx, offer); err != nil {
		proConflict(c)
		return
	}
	var conflict bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=$1 AND state='pending') OR EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND status<>'ended') OR EXISTS(SELECT 1 FROM yc_claim_team_intent WHERE team_id=$1 AND released_at IS NULL) OR EXISTS(SELECT 1 FROM billing_yc_operation WHERE team_id=$1 AND state<>'ended')`, team).Scan(&conflict)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	plan, assigned, err := currentTeamPlan(ctx, tx, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if conflict || a.CheckoutInitializingAt.Valid || a.CheckoutSessionID != nil || (assigned && plan.Kind != planKindFree && plan.Kind != planKindPrepaid && plan.Kind != planKindLegacyPAYG) {
		proConflict(c)
		return
	}
	awaiting, err := teamAwaitingPlan(ctx, tx, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	now := h.nowUTC().Truncate(time.Second)
	firstPaidCycle, err := firstProCycleEligible(ctx, tx, team, awaiting || (assigned && plan.Kind == planKindFree), a.CommercialBillingAnchor.Valid, a.StripeSubscriptionID != nil)
	if errors.Is(err, errProFirstCycleReconciliation) {
		respondErrorMsg(c, "billing_reconciliation_required", err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	anchor := now
	start, end := billing.CurrentBillingPeriod(now)
	if firstPaidCycle {
		start, end, _ = billing.AnniversaryPeriod(now, now)
	} else if a.CommercialBillingAnchor.Valid {
		anchor = a.CommercialBillingAnchor.Time
		var ok bool
		start, end, ok = billing.AnniversaryPeriod(anchor, now)
		if !ok {
			respondError(c, ErrInternal)
			return
		}
	} else {
		period, e := h.DB.WithTx(tx).GetActiveTeamBillingPeriod(ctx, team)
		if e == nil {
			start, end = period.PeriodStart, period.PeriodEnd
		} else if !errors.Is(e, pgx.ErrNoRows) {
			respondError(c, ErrInternal)
			return
		}
		anchor = start
	}
	var initial *uuid.UUID
	if assigned {
		initial = &plan.ID
	}
	amount, err := proratedProAmount(offer.Amount, start, end, now)
	if err != nil || amount < 50 || end.Sub(now) < 31*time.Minute {
		respondErrorMsg(c, "billing_boundary", "The remaining prorated payment is below the card minimum or the billing date is too close. Retry after the next billing date.", 409)
		return
	}
	credit, err := proratedProAmount(offer.Credit, start, end, now)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	id := params.OperationID
	if id == uuid.Nil {
		id = uuid.New()
	}
	params.OperationID = id
	var previous bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1)`, team).Scan(&previous); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if previous {
		release, e := proReleaseForReentry(ctx, tx, team, params.CustomerID)
		if e != nil {
			respondError(c, ErrInternal)
			return
		}
		if release == nil || params.OperationID == uuid.Nil {
			proConflict(c)
			return
		}
		params.ReleaseID = release
	}
	params.PlanTerms.PredecessorKnown = true
	params.PlanTerms.InitialAssignment = initial
	params.PriceIDs = nil
	params.OneOffAmount = amount
	params.FirstPaidProCycle = firstPaidCycle
	params.OneOffName = proUpgradeCheckoutDescription(offer, amount, credit, now, end, params.AllowPromotionCodes)
	if firstPaidCycle {
		params.OneOffName = proFirstCycleCheckoutDescription(offer, now, end, params.AllowPromotionCodes)
	}
	params.Metadata = map[string]string{"pro_upgrade_id": id.String(), "team_id": team.String(), "actor_id": actor.String()}
	params.IdempotencyKey = "pro-upgrade-checkout:" + id.String()
	expires := now.Add(23 * time.Hour)
	if cutoff := end.Add(-time.Minute); cutoff.Before(expires) {
		expires = cutoff
	}
	params.ExpiresAt = &expires
	payload, err := json.Marshal(params)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,subscription_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,initial_assignment_id,bridge_credit_cents,admission_source,admission_epoch) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, id, team, actor, params.CustomerID, a.StripeSubscriptionID, offer.Key, payload, anchor, start, end, now, amount, initial, credit, pricingSource(admission), pricingEpoch(admission))
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	u, err := h.proUpgrade(ctx, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	h.resumeProUpgradeCheckout(c, u)
}

const providerBackdateMargin = 1500 * time.Millisecond

// A session missing from the provider's listing is treated as expired only
// once the provider's clock has certainly passed the quote deadline too.
const upgradeExpiryClockMargin = 5 * time.Minute

// respondUpgradeUnsettled reports a payment still settling only when the
// customer has paid; an upgrade whose checkout could not be opened is an
// error the customer can retry, never a pending payment without a session.
func (h *Handlers) respondUpgradeUnsettled(c *gin.Context, team uuid.UUID, cause error) {
	ctx := c.Request.Context()
	latest, err := h.proUpgrade(ctx, team)
	paid := err == nil && (latest.State == "paid" || latest.State == "credited" || latest.State == "active")
	if !paid && err == nil && latest.Session != nil {
		if s, e := h.Stripe.(*stripeHTTPClient).RetrieveCheckoutSession(ctx, *latest.Session); e == nil && s.Status == "complete" {
			paid = true
		}
	}
	if paid {
		c.JSON(http.StatusAccepted, gin.H{"outcome": "payment_confirmation_pending"})
		return
	}
	log.Warn().Err(cause).Str("team_id", team.String()).Msg("upgrade checkout unavailable")
	respondErrorMsg(c, "checkout_unavailable", "Checkout could not be opened. Please try again.", http.StatusServiceUnavailable)
}

func (h *Handlers) resumeProUpgradeCheckout(c *gin.Context, u proUpgrade) {
	outcome, err := h.reconcileProUpgrade(c.Request.Context(), u, false)
	if err != nil {
		h.respondUpgradeUnsettled(c, u.Team, err)
		return
	}
	if outcome == "active" {
		c.JSON(http.StatusOK, gin.H{"outcome": outcome})
		return
	}
	if outcome == "payment_method_required" {
		if target, e := h.proUpgradeSetupURL(c.Request.Context(), u.Team); e == nil {
			c.JSON(http.StatusOK, billingSessionResponse{URL: target})
			return
		}
	}
	latest, err := h.proUpgrade(c.Request.Context(), u.Team)
	if err != nil || latest.Session == nil {
		h.respondUpgradeUnsettled(c, u.Team, fmt.Errorf("upgrade %s has no checkout session: %w", outcome, err))
		return
	}
	s, err := h.Stripe.(*stripeHTTPClient).RetrieveCheckoutSession(c.Request.Context(), *latest.Session)
	if err != nil || s.Status != "open" {
		h.respondUpgradeUnsettled(c, u.Team, fmt.Errorf("upgrade checkout session is %q: %w", s.Status, err))
		return
	}
	c.JSON(http.StatusOK, billingSessionResponse{URL: s.URL})
}

func (h *Handlers) proUpgradeInvoiceLock(ctx context.Context, team uuid.UUID) (*pgxpool.Conn, func(), error) {
	conn, err := h.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	var locked bool
	err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, "invoice:"+team.String()).Scan(&locked)
	if err != nil || !locked {
		conn.Release()
		return nil, nil, errors.New("invoice reconciliation is busy")
	}
	release := func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		var unlocked bool
		if e := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, "invoice:"+team.String()).Scan(&unlocked); e != nil || !unlocked {
			_ = conn.Conn().Close(cleanup)
		}
		conn.Release()
	}
	return conn, release, nil
}

func (h *Handlers) reconcileProUpgrade(ctx context.Context, u proUpgrade, restart bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return "", errors.New("Pro payment verification unavailable")
	}
	token := uuid.New()
	if _, err := h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: u.Customer, Token: token}); err != nil {
		return "", err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer stop()
		_ = h.DB.ReleaseStripeWebhookProcessingLease(cleanup, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: u.Customer, Token: token})
	}()
	conn, release, err := h.proUpgradeInvoiceLock(ctx, u.Team)
	if err != nil {
		return "", err
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	u, err = scanProUpgrade(conn.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE id=$1 AND team_id=$2`, u.ID, u.Team))
	if err != nil {
		return "", err
	}
	var params StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(u.Payload, &params); err != nil {
		return "", err
	}
	offer, err := frozenProOffer(u.Offer, params)
	if err != nil {
		return "", err
	}
	offer.Price = params.BasePriceID
	if u.State == "expired" {
		return "retryable", nil
	}
	if u.State == "active" {
		if u.Session == nil {
			return "", errors.New("active upgrade payment session is missing")
		}
		session, e := client.RetrieveCheckoutSession(ctx, *u.Session)
		if e != nil {
			return "", e
		}
		if _, _, e = h.verifyProUpgradePayment(ctx, conn, client, u, session, false); e != nil {
			return "", e
		}
		if err = h.catchUpProUpgrade(ctx, conn, u, offer, client); err != nil {
			return "", err
		}
		release()
		release = nil
		return h.reconcileProUpgradeRenewals(ctx, u, offer, client)
	}
	if u.Session == nil {
		var inventory struct {
			Data    []StripeRetrievedCheckoutSession `json:"data"`
			HasMore bool                             `json:"has_more"`
		}
		if err = client.doForm(ctx, http.MethodGet, "/v1/checkout/sessions?"+url.Values{"customer": {u.Customer}, "limit": {"100"}}.Encode(), nil, &inventory, ""); err != nil {
			return "", err
		}
		if inventory.HasMore {
			return "", errors.New("upgrade Checkout inventory exceeds supported bound")
		}
		for _, found := range inventory.Data {
			if found.Metadata["pro_upgrade_id"] == u.ID.String() && found.Mode == "payment" {
				if u.Session != nil {
					return "", errors.New("ambiguous upgrade Checkout sessions")
				}
				u.Session = stringPtr(found.ID)
			}
		}
		if u.Session == nil && !h.nowUTC().Before(params.ExpiresAt.Add(upgradeExpiryClockMargin)) {
			return "retryable", h.expireProUpgrade(ctx, conn, u, params, client)
		}
	}
	if u.Session != nil {
		session, e := client.RetrieveCheckoutSession(ctx, *u.Session)
		if e != nil {
			return "", e
		}
		if e = checkUpgradeSession(u, session); e != nil {
			return "", e
		}
		if session.Status == "expired" {
			return "retryable", h.expireProUpgrade(ctx, conn, u, params, client)
		}
	}
	sub, err := h.prepareProUpgradeSubscription(ctx, conn, &u, params, client)
	if err != nil {
		return "", err
	}
	{
		if u.Session == nil {
			session, err := client.CreateCheckoutSession(ctx, params)
			if err != nil {
				return "", err
			}
			if session.ID == "" {
				return "", errors.New("missing upgrade checkout identity")
			}
			if _, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade SET session_id=$2,state='checkout' WHERE id=$1`, u.ID, session.ID); err != nil {
				return "", err
			}
			u.Session = &session.ID
		} else if _, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade SET session_id=$2,state=CASE WHEN state='prepared' THEN 'checkout' ELSE state END WHERE id=$1`, u.ID, *u.Session); err != nil {
			return "", err
		}
	}
	session, err := client.RetrieveCheckoutSession(ctx, *u.Session)
	if err != nil {
		return "", err
	}
	if err = checkUpgradeSession(u, session); err != nil {
		return "", err
	}
	if restart && session.Status == "open" {
		if err = client.doForm(ctx, http.MethodPost, "/v1/checkout/sessions/"+url.PathEscape(session.ID)+"/expire", nil, nil, "pro-upgrade-expire:"+u.ID.String()); err != nil {
			return "", err
		}
		session, err = client.RetrieveCheckoutSession(ctx, session.ID)
		if err != nil {
			return "", err
		}
	}
	if session.Status == "expired" {
		return "retryable", h.expireProUpgrade(ctx, conn, u, params, client)
	}
	if session.Status != "complete" {
		return "payment_confirmation_pending", nil
	}
	method, evidence, err := h.verifyProUpgradePayment(ctx, conn, client, u, session, true)
	if err != nil {
		return "", err
	}
	if _, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade SET state=CASE WHEN state='checkout' THEN 'paid' ELSE state END,payment_evidence=$2,payment_method_id=NULLIF($3,'') WHERE id=$1`, u.ID, evidence, method); err != nil {
		return "", err
	}
	u.PaymentMethod = stringPtr(method)
	if err = h.issueProUpgradeCredit(ctx, conn, &u, client); err != nil {
		return "", err
	}
	if method == "" {
		method, err = h.ensureProUpgradePaymentMethod(ctx, conn, u, params, client)
		if err != nil {
			return "", err
		}
		if method == "" {
			return "payment_method_required", nil
		}
		if _, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade SET payment_method_id=$2 WHERE id=$1`, u.ID, method); err != nil {
			return "", err
		}
	}
	u.PaymentMethod = stringPtr(method)
	if err = h.commitProUpgrade(ctx, conn, &u, sub, offer, method, client, token); err != nil {
		return "", err
	}
	if err = h.catchUpProUpgrade(ctx, conn, u, offer, client); err != nil {
		return "", err
	}
	release()
	release = nil
	if err = h.enrollInvoiceAccount(ctx, u.Team, nil); err != nil {
		return "", err
	}
	return h.activateProUpgrade(ctx, u, params, session)
}

func (h *Handlers) activateProUpgrade(ctx context.Context, u proUpgrade, params StripeCreateCheckoutSessionParams, session StripeRetrievedCheckoutSession) (string, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	a, err := q.LockTeamBillingAccount(ctx, u.Team)
	if err != nil {
		return "", err
	}
	if derefString(a.StripeCustomerID) != u.Customer || derefString(a.StripeSubscriptionID) != derefString(u.Subscription) {
		return "", errors.New("upgrade billing association changed during enrollment")
	}
	var completed uuid.UUID
	if err = tx.QueryRow(ctx, `UPDATE billing_pro_upgrade SET state='active',last_error=NULL WHERE id=$1 AND state='credited' AND EXISTS(SELECT 1 FROM billing_commercial_contract c WHERE c.id=billing_pro_upgrade.contract_id AND c.status<>'ended') RETURNING id`, u.ID).Scan(&completed); err != nil {
		return "", err
	}
	if err = h.DB.WithTx(tx).ActivateTeamBilling(ctx, db.ActivateTeamBillingParams{TeamID: u.Team, StripeGrantID: ""}); err != nil {
		return "", err
	}
	var newTeamTrial bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_new_team_enrollment WHERE team_id=$1 AND initial_assignment_id IS NULL)`, u.Team).Scan(&newTeamTrial); err != nil {
		return "", err
	}
	if err = applyUpgradeTopoff(ctx, tx, u, params, session); err != nil {
		return "", err
	}
	// A new team's first paid plan ends its trial, dropping any credit left.
	if _, err = tx.Exec(ctx, `UPDATE team_credit_grant SET remaining_usd=0,updated_at=clock_timestamp() WHERE team_id=$1 AND reason='signup trial credit' AND remaining_usd<>0 AND $2`, u.Team, u.InitialAssignment == nil && newTeamTrial); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET trial_ended_at=COALESCE(trial_ended_at,clock_timestamp()),updated_at=clock_timestamp() WHERE team_id=$1 AND trial_ended_at IS NULL AND $2`, u.Team, u.InitialAssignment == nil && newTeamTrial); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET state='committed',offer_key=$2,generation=$3,actor_id=$4,base_price_id=$5,request_payload=$6,session_id=$7,subscription_id=$8,revision=revision+1,admission_source=(SELECT admission_source FROM billing_pro_upgrade WHERE id=$9),admission_epoch=(SELECT admission_epoch FROM billing_pro_upgrade WHERE id=$9) WHERE team_id=$1 AND state='selecting'`, u.Team, u.Offer, u.Quoted, u.Actor, params.BasePriceID, u.Payload, u.Session, u.Subscription, u.ID); err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return "active", nil
}

func checkUpgradeSession(u proUpgrade, session StripeRetrievedCheckoutSession) error {
	if session.ID != *u.Session || session.Mode != "payment" || session.CustomerID != u.Customer || session.ClientReferenceID != u.Team.String() || session.Metadata["pro_upgrade_id"] != u.ID.String() {
		return errors.New("upgrade checkout association differs")
	}
	return nil
}

// An expired upgrade can no longer be paid, so a first paid month also hands
// back the collection-paused subscription, the billing calendar it claimed and
// the untouched reporting period of that calendar, leaving the team free to
// quote again.
func (h *Handlers) expireProUpgrade(ctx context.Context, conn *pgxpool.Conn, u proUpgrade, p StripeCreateCheckoutSessionParams, c *stripeHTTPClient) error {
	if u.Evidence != nil {
		return errors.New("paid upgrade cannot expire")
	}
	subscription := ""
	if p.FirstPaidProCycle {
		var err error
		if subscription, err = cancelUnpaidUpgradeSubscription(ctx, c, u); err != nil {
			return err
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	tag, err := tx.Exec(ctx, `UPDATE billing_pro_upgrade SET state='expired',subscription_id=COALESCE(subscription_id,NULLIF($2,'')) WHERE id=$1 AND payment_evidence IS NULL AND state NOT IN ('expired','ended')`, u.ID, subscription)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("upgrade payment state changed during expiry")
	}
	if subscription != "" {
		if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL,current_period_start=NULL,current_period_end=NULL,
 commercial_billing_anchor=CASE WHEN commercial_billing_anchor=$4 THEN NULL ELSE commercial_billing_anchor END
 WHERE team_id=$1 AND stripe_customer_id=$2 AND stripe_subscription_id=$3`, u.Team, u.Customer, subscription, u.Anchor); err != nil {
			return err
		}
		h.retireAbandonedFirstCyclePeriod(ctx, tx, u)
	}
	return tx.Commit(ctx)
}

// The abandoned month's reporting period is retired only while nothing has
// touched it, and in a savepoint: the provider cancellation has already
// happened, so a refusal here leaves the period open rather than undoing expiry.
func (h *Handlers) retireAbandonedFirstCyclePeriod(ctx context.Context, tx pgx.Tx, u proUpgrade) {
	sp, err := tx.Begin(ctx)
	if err == nil {
		_, err = sp.Exec(ctx, `UPDATE team_billing_period SET status='finalized',blocked_reason='reporting_only_calendar_period',gross_charges_usd=0,credits_applied_usd=0,net_invoice_amount_usd=0,finalized_at=clock_timestamp(),updated_at=clock_timestamp()
 WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND status='open' AND exported_at IS NULL AND approved_at IS NULL AND finalized_at IS NULL AND blocked_at IS NULL
  AND COALESCE(gross_charges_usd,0)=0 AND COALESCE(credits_applied_usd,0)=0 AND COALESCE(net_invoice_amount_usd,0)=0
  AND NOT EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND commercial_billing_anchor IS NOT NULL)
  AND NOT EXISTS(SELECT 1 FROM billing_invoice_account WHERE team_id=$1)
  AND NOT EXISTS(SELECT 1 FROM billing_incremental_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3)
  AND NOT EXISTS(SELECT 1 FROM billing_period_close_work WHERE team_id=$1 AND period_start=$2 AND period_end=$3)
  AND NOT EXISTS(SELECT 1 FROM billing_usage_export WHERE team_id=$1 AND period_start=$2 AND period_end=$3)
  AND NOT EXISTS(SELECT 1 FROM billing_export_allocation WHERE team_id=$1 AND period_start=$2 AND period_end=$3)`, u.Team, u.Start, u.End)
		if err == nil {
			err = sp.Commit(ctx)
		}
	}
	if err != nil {
		if sp != nil {
			_ = sp.Rollback(ctx)
		}
		log.Warn().Err(err).Str("team_id", u.Team.String()).Str("pro_upgrade_id", u.ID.String()).Msg("abandoned first paid month reporting period left open")
	}
}

// cancelUnpaidUpgradeSubscription cancels the subscription created for the
// upgrade, found by its metadata even when its identity was never saved, and
// returns its identity, or "" when none was created.
func cancelUnpaidUpgradeSubscription(ctx context.Context, c *stripeHTTPClient, u proUpgrade) (string, error) {
	type subscription struct {
		ID       string            `json:"id"`
		Customer string            `json:"customer"`
		Status   string            `json:"status"`
		Metadata map[string]string `json:"metadata"`
	}
	var sub subscription
	if u.Subscription != nil {
		if err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(*u.Subscription), nil, &sub, ""); err != nil {
			return "", err
		}
		if sub.ID != *u.Subscription {
			return "", errors.New("upgrade subscription association differs")
		}
	} else {
		var all struct {
			Data    []subscription `json:"data"`
			HasMore bool           `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+url.Values{"customer": {u.Customer}, "status": {"all"}, "limit": {"100"}}.Encode(), nil, &all, ""); err != nil {
			return "", err
		}
		if all.HasMore {
			return "", errors.New("upgrade subscription inventory exceeds supported bound")
		}
		for _, s := range all.Data {
			if s.Metadata["pro_upgrade_id"] == u.ID.String() {
				if sub.ID != "" {
					return "", errors.New("ambiguous upgrade subscriptions")
				}
				sub = s
			}
		}
		if sub.ID == "" {
			return "", nil
		}
	}
	if sub.Customer != u.Customer || sub.Metadata["pro_upgrade_id"] != u.ID.String() {
		return "", errors.New("upgrade subscription association differs")
	}
	var invoices struct {
		Data []struct {
			Status     string `json:"status"`
			AmountPaid int64  `json:"amount_paid"`
			Total      int64  `json:"total"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"subscription": {sub.ID}, "limit": {"100"}}.Encode(), nil, &invoices, ""); err != nil {
		return "", err
	}
	if invoices.HasMore {
		return "", errors.New("upgrade subscription invoice inventory exceeds supported bound")
	}
	for _, inv := range invoices.Data {
		if inv.AmountPaid != 0 || (inv.Status != "draft" && inv.Status != "void" && (inv.Status != "paid" || inv.Total != 0)) {
			return "", errors.New("unpaid upgrade subscription has issued invoices and requires reconciliation")
		}
	}
	if sub.Status == "canceled" || sub.Status == "incomplete_expired" {
		return sub.ID, nil
	}
	return sub.ID, c.doForm(ctx, http.MethodDelete, "/v1/subscriptions/"+url.PathEscape(sub.ID)+"?"+url.Values{"invoice_now": {"false"}, "prorate": {"false"}}.Encode(), nil, nil, "")
}

func (h *Handlers) prepareProUpgradeSubscription(ctx context.Context, conn *pgxpool.Conn, u *proUpgrade, p StripeCreateCheckoutSessionParams, c *stripeHTTPClient) (invoiceSubscription, error) {
	id := derefString(u.Subscription)
	if id == "" {
		var all struct {
			Data    []invoiceSubscription `json:"data"`
			HasMore bool                  `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+url.Values{"customer": {u.Customer}, "status": {"all"}, "limit": {"100"}}.Encode(), nil, &all, ""); err != nil {
			return invoiceSubscription{}, err
		}
		if all.HasMore {
			return invoiceSubscription{}, errors.New("upgrade subscription inventory exceeds supported bound")
		}
		for _, s := range all.Data {
			if s.Metadata["pro_upgrade_id"] == u.ID.String() {
				if id != "" {
					return invoiceSubscription{}, errors.New("ambiguous upgrade subscriptions")
				}
				id = s.ID
			} else if s.Status != "canceled" && s.Status != "incomplete_expired" {
				return invoiceSubscription{}, errors.New("existing provider subscription requires reconciliation")
			}
		}
		if id == "" {
			if h.nowUTC().Sub(u.Quoted) >= 23*time.Hour {
				return invoiceSubscription{}, errors.New("upgrade subscription creation replay expired")
			}
			form := url.Values{"customer": {u.Customer}, "billing_mode[type]": {"flexible"}, "proration_behavior": {"none"}, "backdate_start_date": {strconv.FormatInt(u.Anchor.Unix(), 10)}, "metadata[pro_upgrade_id]": {u.ID.String()}}
			if p.FirstPaidProCycle {
				form.Set("metadata[first_paid_pro_cycle]", "true")
				anchor := u.Anchor.UTC()
				form.Set("billing_cycle_anchor_config[day_of_month]", strconv.Itoa(anchor.Day()))
				form.Set("billing_cycle_anchor_config[hour]", strconv.Itoa(anchor.Hour()))
				form.Set("billing_cycle_anchor_config[minute]", strconv.Itoa(anchor.Minute()))
				form.Set("billing_cycle_anchor_config[second]", strconv.Itoa(anchor.Second()))
			} else if u.End.Day() == u.Anchor.Day() {
				form.Set("billing_cycle_anchor", strconv.FormatInt(u.End.Unix(), 10))
			}
			for i, t := range p.ResourceTerms {
				form.Set(fmt.Sprintf("items[%d][price]", i), t.PriceID)
			}
			// The provider accepts a backdated start only once it is in the
			// past, and a first paid month starts at the quote itself.
			if wait := u.Anchor.Add(providerBackdateMargin).Sub(h.nowUTC()); wait > 0 {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return invoiceSubscription{}, ctx.Err()
				}
			}
			var created invoiceSubscription
			if err := c.doForm(ctx, http.MethodPost, "/v1/subscriptions", form, &created, "pro-upgrade-subscription:"+u.ID.String()); err != nil {
				return created, err
			}
			id = created.ID
		}
		if id == "" {
			return invoiceSubscription{}, errors.New("missing upgrade subscription identity")
		}
		if _, err := conn.Exec(ctx, `UPDATE billing_pro_upgrade SET subscription_id=$2 WHERE id=$1`, u.ID, id); err != nil {
			return invoiceSubscription{}, err
		}
		u.Subscription = &id
	}
	sub, err := c.invoiceSubscription(ctx, id)
	if err != nil {
		return sub, err
	}
	var rounding string
	if err = conn.QueryRow(ctx, `SELECT COALESCE((SELECT adjustment_price_id FROM billing_invoice_account WHERE team_id=$1),'')`, u.Team).Scan(&rounding); err != nil {
		return sub, err
	}
	if rounding, err = pendingInvoiceRounding(sub, rounding); err != nil {
		return sub, err
	}
	expectedStart, expectedEnd, err := validateProUpgradeSubscription(*u, p, sub, rounding, h.nowUTC())
	if err != nil {
		return sub, err
	}
	if sub.PauseCollection == nil {
		if err = c.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(id), url.Values{"pause_collection[behavior]": {"keep_as_draft"}}, nil, "pro-upgrade-prepare-hold:"+u.ID.String()); err != nil {
			return sub, err
		}
		sub, err = c.invoiceSubscription(ctx, id)
		if err != nil {
			return sub, err
		}
		expectedStart, expectedEnd, err = validateProUpgradeSubscription(*u, p, sub, rounding, h.nowUTC())
		if err != nil {
			return sub, err
		}
	}
	if sub.PauseCollection == nil || sub.PauseCollection.Behavior != "keep_as_draft" || sub.PauseCollection.ResumesAt != 0 {
		return sub, errors.New("upgrade collection hold requires verification before payment")
	}

	tag, err := conn.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=$2,stripe_subscription_status=$3,commercial_billing_anchor=COALESCE(commercial_billing_anchor,$4),current_period_start=$6,current_period_end=$7 WHERE team_id=$1 AND stripe_customer_id=$5 AND (stripe_subscription_id IS NULL OR stripe_subscription_id=$2) AND (commercial_billing_anchor IS NULL OR commercial_billing_anchor=$4)`, u.Team, id, sub.Status, u.Anchor, u.Customer, expectedStart, expectedEnd)
	if err == nil && tag.RowsAffected() != 1 {
		err = errors.New("upgrade billing association changed before payment")
	}
	return sub, err
}

func validateProUpgradeSubscription(u proUpgrade, p StripeCreateCheckoutSessionParams, sub invoiceSubscription, rounding string, now time.Time) (time.Time, time.Time, error) {
	if p.FirstPaidProCycle {
		if err := validateFirstProCycleProviderCalendar(u.ID, u.Anchor, sub); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	if sub.ID != derefString(u.Subscription) || sub.Customer != u.Customer || sub.Status != "active" || sub.CancelAtPeriodEnd || sub.CancelAt != 0 || sub.PendingUpdate != nil || sub.Schedule != "" || len(sub.Discounts) != 0 || sub.AutomaticTax.Enabled || sub.BillingMode.Type != "flexible" {
		return time.Time{}, time.Time{}, errors.New("subscription is unavailable for immediate Pro upgrade")
	}
	resources := sub
	for _, item := range sub.Items.Data {
		if item.Price.ID != p.BasePriceID {
			continue
		}
		var err error
		resources, err = (invoiceBase{Price: p.BasePriceID, Amount: p.PlanTerms.Amount, Months: 1}).stripSubscription(sub)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	if err := validateFrozenProResources(resources, p.ResourceTerms, rounding); err != nil {
		return time.Time{}, time.Time{}, err
	}
	expectedStart, expectedEnd, ok := billing.AnniversaryPeriod(u.Anchor, now)
	if !ok {
		return time.Time{}, time.Time{}, errors.New("upgrade billing calendar is unavailable")
	}
	if u.Contract == nil {
		for _, item := range resources.Items.Data {
			if item.Price.ID == rounding {
				continue
			}
			if item.Start != expectedStart.Unix() || item.End != expectedEnd.Unix() {
				return time.Time{}, time.Time{}, errors.New("upgrade provider calendar must preserve the existing billing period before payment")
			}
		}
	}
	if err := invoiceCalendarCompatible(u.Anchor, resources, rounding); err != nil {
		return time.Time{}, time.Time{}, err
	}
	return expectedStart, expectedEnd, nil
}

// applyUpgradeTopoff settles the funding of a prepaid-funded plan with the
// top-off answer the customer gave at checkout, under the admission the
// checkout accepted.
func applyUpgradeTopoff(ctx context.Context, tx pgx.Tx, u proUpgrade, params StripeCreateCheckoutSessionParams, session StripeRetrievedCheckoutSession) error {
	if params.PlanTerms == nil || params.PlanTerms.FundingPolicy != fundingPolicyPrepaid {
		return nil
	}
	enabled := false
	if params.Topoff != nil {
		var err error
		if enabled, err = session.topoffChosen(); err != nil {
			return err
		}
	}
	var admission pricingPublicState
	var epoch *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT COALESCE(admission_source,''),admission_epoch FROM billing_pro_upgrade WHERE id=$1`, u.ID).Scan(&admission.Source, &epoch); err != nil {
		return err
	}
	if epoch != nil {
		admission.Epoch = *epoch
	}
	if !enabled {
		return applyCheckoutTopoff(ctx, tx, u.Team, session.ID, false, admission)
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	err = applyCheckoutTopoff(ctx, sp, u.Team, session.ID, true, admission)
	if err == nil {
		return sp.Commit(ctx)
	}
	if rollbackErr := sp.Rollback(ctx); rollbackErr != nil {
		return rollbackErr
	}
	// A plan already paid for must still activate when entry closed after
	// checkout; the top-off stays off, which the low-credit warnings cover.
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		return err
	}
	log.Warn().Err(err).Str("team_id", u.Team.String()).Msg("checkout top-off admission closed; activating with top-off off")
	return applyCheckoutTopoff(ctx, tx, u.Team, session.ID, false, admission)
}
