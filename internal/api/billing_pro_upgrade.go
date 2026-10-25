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
	"github.com/jackc/pgx/v5/pgxpool"
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
	GrantAttempt                                *time.Time
	RecurringAttempt, BaseCreated               *time.Time
	InitialAssignment                           *uuid.UUID
	Evidence                                    []byte
}

const proUpgradeColumns = `id,team_id,actor_id,customer_id,subscription_id,offer_key,state,session_id,grant_id,payment_method_id,contract_id,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,grant_attempted_at,payment_evidence,recurring_attempted_at,base_created_at,initial_assignment_id`

func scanProUpgrade(row pgx.Row) (u proUpgrade, err error) {
	err = row.Scan(&u.ID, &u.Team, &u.Actor, &u.Customer, &u.Subscription, &u.Offer, &u.State, &u.Session, &u.Grant, &u.PaymentMethod, &u.Contract, &u.Payload, &u.Anchor, &u.Start, &u.End, &u.Quoted, &u.Amount, &u.GrantAttempt, &u.Evidence, &u.RecurringAttempt, &u.BaseCreated, &u.InitialAssignment)
	return
}

func (h *Handlers) proUpgrade(ctx context.Context, team uuid.UUID) (proUpgrade, error) {
	return scanProUpgrade(h.Pool.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE team_id=$1 AND state NOT IN ('expired','ended')`, team))
}

func proratedProAmount(amount int64, start, end, at time.Time) (int64, error) {
	duration, remaining := end.Unix()-start.Unix(), end.Unix()-at.Unix()
	if amount <= 0 || duration <= 0 || remaining <= 0 || at.Before(start) || remaining > duration {
		return 0, errors.New("invalid Pro proration window")
	}
	n := new(big.Int).Mul(big.NewInt(amount), big.NewInt(remaining))
	n.Add(n, big.NewInt(duration/2)).Quo(n, big.NewInt(duration))
	if !n.IsInt64() || n.Int64() <= 0 {
		return 0, errors.New("Pro proration rounds to zero; retry at the next billing date")
	}
	return n.Int64(), nil
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
	now := h.nowUTC().Truncate(time.Second)
	anchor := now
	start, end := billing.CurrentBillingPeriod(now)
	if a.CommercialBillingAnchor.Valid {
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
	params.OneOffName = fmt.Sprintf("%s upgrade through %s; equal non-expiring usage credit", offer.Name, end.UTC().Format("2006-01-02 15:04 MST"))
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
	_, err = tx.Exec(ctx, `INSERT INTO billing_pro_upgrade(id,team_id,actor_id,customer_id,subscription_id,offer_key,request_payload,anchor,period_start,period_end,quoted_at,amount_cents,initial_assignment_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, team, actor, params.CustomerID, a.StripeSubscriptionID, offer.Key, payload, anchor, start, end, now, amount, initial)
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

func (h *Handlers) resumeProUpgradeCheckout(c *gin.Context, u proUpgrade) {
	outcome, err := h.reconcileProUpgrade(c.Request.Context(), u, false)
	if err != nil {
		c.JSON(http.StatusAccepted, gin.H{"outcome": "payment_confirmation_pending"})
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
		c.JSON(http.StatusAccepted, gin.H{"outcome": "payment_confirmation_pending"})
		return
	}
	s, err := h.Stripe.(*stripeHTTPClient).RetrieveCheckoutSession(c.Request.Context(), *latest.Session)
	if err != nil || s.Status != "open" {
		c.JSON(http.StatusAccepted, gin.H{"outcome": "payment_confirmation_pending"})
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
		if u.Session == nil && !h.nowUTC().Before(*params.ExpiresAt) {
			_, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade SET state='expired' WHERE id=$1 AND payment_evidence IS NULL`, u.ID)
			return "retryable", err
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
	if session.ID != *u.Session || session.Mode != "payment" || session.CustomerID != u.Customer || session.ClientReferenceID != u.Team.String() || session.Metadata["pro_upgrade_id"] != u.ID.String() {
		return "", errors.New("upgrade checkout association differs")
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
		_, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade SET state='expired' WHERE id=$1 AND payment_evidence IS NULL`, u.ID)
		return "retryable", err
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
	if _, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET state='committed',offer_key=$2,generation=$3,actor_id=$4,base_price_id=$5,request_payload=$6,session_id=$7,subscription_id=$8,revision=revision+1 WHERE team_id=$1 AND state='selecting'`, u.Team, u.Offer, u.Quoted, u.Actor, params.BasePriceID, u.Payload, u.Session, u.Subscription); err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return "active", nil
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
			if u.End.Day() == u.Anchor.Day() {
				form.Set("billing_cycle_anchor", strconv.FormatInt(u.End.Unix(), 10))
			}
			for i, t := range p.ResourceTerms {
				form.Set(fmt.Sprintf("items[%d][price]", i), t.PriceID)
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
