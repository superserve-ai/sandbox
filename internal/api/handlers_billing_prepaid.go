package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

type prepaidCheckoutBody struct {
	AmountCents int64  `json:"amount_cents"`
	SuccessURL  string `json:"success_url"`
	CancelURL   string `json:"cancel_url"`
}

type prepaidAutoRechargeBody struct {
	Enabled        bool  `json:"enabled"`
	ThresholdCents int64 `json:"threshold_cents"`
	AmountCents    int64 `json:"amount_cents"`
}

const prepaidPurchaseJSON = `jsonb_build_object('id',p.id,'team_id',p.team_id,'source',p.source,'amount_cents',p.amount_cents,
 'state',CASE WHEN p.payment_state='failed' THEN 'failed' WHEN p.credit_state='issued' THEN 'credited' WHEN p.payment_state='succeeded' THEN 'paid' ELSE 'pending' END,
 'failure_reason',p.failure_reason,'paid_at',p.paid_at,'credited_at',p.credited_at,'created_at',p.created_at)`

const prepaidAutoRechargeJSON = `jsonb_build_object('enabled',COALESCE(a.enabled,false),'threshold_cents',a.threshold_cents,'amount_cents',a.amount_cents,
 'disabled_reason',a.disabled_reason,'disabled_at',a.disabled_at,
 'in_flight',EXISTS(SELECT 1 FROM billing_prepaid_purchase q WHERE q.team_id=t.team_id AND q.source='auto_recharge' AND q.payment_state IN ('pending','uncertain','processing')))`

func (h *Handlers) prepaidSummary(ctx context.Context, team uuid.UUID, purchases int) ([]byte, error) {
	var raw []byte
	err := h.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'balance_cents',CASE WHEN f.observe AND f.observed_generation=f.generation AND f.credit_valid_until>clock_timestamp() THEN floor(f.credit_usd*100)::bigint ELSE 0 END,
 'low_balance',(CASE WHEN f.observe AND f.observed_generation=f.generation AND f.credit_valid_until>clock_timestamp() THEN floor(f.credit_usd*100)::bigint ELSE 0 END)<500 AND NOT COALESCE(a.enabled,false),
 'auto_recharge',`+prepaidAutoRechargeJSON+`,
 'has_saved_card',COALESCE(f.payment_method_ready,false),
 'purchases',(SELECT COALESCE(jsonb_agg(`+prepaidPurchaseJSON+` ORDER BY p.created_at DESC),'[]') FROM
   (SELECT * FROM billing_prepaid_purchase WHERE team_id=t.team_id ORDER BY created_at DESC LIMIT $2) p))
 FROM (SELECT $1::uuid team_id) t LEFT JOIN billing_funding_account f USING(team_id) LEFT JOIN billing_prepaid_auto_recharge a USING(team_id)`, team, purchases).Scan(&raw)
	return raw, err
}

func (h *Handlers) GetPrepaidCredit(c *gin.Context) {
	team, err := customerContextTeamID(c)
	if err != nil {
		return
	}
	if !h.requireCustomerTeamPermission(c, team, "billing:read") {
		return
	}
	raw, err := h.prepaidSummary(c.Request.Context(), team, 20)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

func (h *Handlers) CreatePrepaidCheckout(c *gin.Context) {
	team, err := customerContextTeamID(c)
	if err != nil {
		return
	}
	if !h.requireCustomerTeamPermission(c, team, "billing:write") {
		return
	}
	actor, err := customerActorID(c)
	if err != nil {
		return
	}
	var req prepaidCheckoutBody
	if err = c.ShouldBindJSON(&req); err != nil || !validPrepaidAmount(req.AmountCents) {
		respondErrorMsg(c, "bad_request", "amount_cents must be a multiple of 500 between 500 and 100000000", http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	var managed bool
	if err = h.Pool.QueryRow(ctx, `SELECT qm_team_managed_billing($1)`, team).Scan(&managed); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if managed {
		respondErrorMsg(c, "forbidden", "This team's billing is managed by QM", http.StatusForbidden)
		return
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		respondErrorMsg(c, "service_unavailable", "Stripe billing is not configured", http.StatusServiceUnavailable)
		return
	}
	capacity, err := h.prepaidCapacityAvailable(ctx, team)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if !capacity {
		respondErrorMsg(c, "service_unavailable", "prepaid credit is temporarily unavailable; try again later", http.StatusServiceUnavailable)
		return
	}
	var proPending bool
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=$1 AND offer_key IN `+paidPlanOffers+`)`, team).Scan(&proPending); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if proPending {
		proConflict(c)
		return
	}
	account, err := h.DB.GetTeamBillingAccount(ctx, team)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	if !billingAccountHasEstablishedSubscription(account) {
		h.createPAYGCheckout(c, team, actor, billingCheckoutSessionRequest{SuccessURL: req.SuccessURL, CancelURL: req.CancelURL}, false, &prepaidCheckoutLine{AmountCents: req.AmountCents})
		return
	}
	successURL, err := h.validateBillingRedirectURL(req.SuccessURL)
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid success_url", http.StatusBadRequest)
		return
	}
	cancelURL, err := h.validateBillingRedirectURL(req.CancelURL)
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid cancel_url", http.StatusBadRequest)
		return
	}
	session, err := h.startPrepaidPaymentCheckout(ctx, client, team, actor, derefString(account.StripeCustomerID), req.AmountCents, successURL, cancelURL)
	if err != nil {
		if errors.Is(err, errPrepaidTooManyUnspent) {
			respondErrorMsg(c, "conflict", errPrepaidTooManyUnspent.Error(), http.StatusConflict)
			return
		}
		if errors.Is(err, errPricingV2Off) {
			respondErrorMsg(c, "conflict", "pricing v2 entry is not released", http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", team.String()).Msg("create prepaid checkout failed")
		respondErrorMsg(c, "bad_gateway", "checkout could not be created; try again", http.StatusBadGateway)
		return
	}
	c.JSON(http.StatusOK, billingSessionResponse{ID: session.ID, URL: session.URL})
}

func (h *Handlers) PutPrepaidAutoRecharge(c *gin.Context) {
	team, err := customerContextTeamID(c)
	if err != nil {
		return
	}
	if !h.requireCustomerTeamPermission(c, team, "billing:write") {
		return
	}
	actor, err := customerActorID(c)
	if err != nil {
		return
	}
	var req prepaidAutoRechargeBody
	if err = c.ShouldBindJSON(&req); err != nil {
		respondErrorMsg(c, "bad_request", "invalid auto-recharge settings", http.StatusBadRequest)
		return
	}
	if req.Enabled {
		if !validPrepaidAmount(req.ThresholdCents) || !validPrepaidAmount(req.AmountCents) {
			respondErrorMsg(c, "bad_request", "threshold_cents and amount_cents must be multiples of 500 between 500 and 100000000", http.StatusBadRequest)
			return
		}
	}
	ctx := c.Request.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var rawVersion string
	var entryOpen bool
	if req.Enabled {
		rawVersion, entryOpen, err = lockPricingEntry(ctx, tx)
		if err != nil {
			respondError(c, ErrInternal)
			return
		}
	}
	if err = tx.QueryRow(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team).Scan(&team); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if !req.Enabled {
		_, err = tx.Exec(ctx, `INSERT INTO billing_prepaid_auto_recharge(team_id,enabled,updated_by) VALUES($1,false,$2)
 ON CONFLICT(team_id) DO UPDATE SET enabled=false,updated_by=$2,updated_at=clock_timestamp()`, team, actor)
	} else {
		var replay bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_prepaid_auto_recharge WHERE team_id=$1 AND enabled AND threshold_cents=$2 AND amount_cents=$3 AND updated_by=$4)`, team, req.ThresholdCents, req.AmountCents, actor).Scan(&replay); err != nil {
			respondError(c, ErrInternal)
			return
		}
		if !replay && (rawVersion != "v2" || !entryOpen) {
			respondErrorMsg(c, "conflict", "pricing v2 entry is not released", http.StatusConflict)
			return
		}
		if !replay {
			if err = assertPrepaidEntry(ctx, tx); err != nil {
				if errors.Is(err, errPricingV2Off) {
					respondErrorMsg(c, "conflict", "pricing v2 entry is not released", http.StatusConflict)
				} else {
					respondError(c, ErrInternal)
				}
				return
			}
			plan, ok, planErr := currentTeamPlan(ctx, tx, team)
			if planErr != nil {
				respondError(c, ErrInternal)
				return
			}
			if !ok || plan.Kind != planKindPrepaid {
				respondErrorMsg(c, "conflict", "auto-recharge requires a prepaid plan", http.StatusConflict)
				return
			}
			var ready bool
			if err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT observe AND payment_method_ready FROM billing_funding_account WHERE team_id=$1),false)`, team).Scan(&ready); err != nil {
				respondError(c, ErrInternal)
				return
			}
			if !ready {
				respondErrorMsg(c, "conflict", "auto-recharge needs a card saved by an earlier credit purchase", http.StatusConflict)
				return
			}
			_, err = tx.Exec(ctx, `INSERT INTO billing_prepaid_auto_recharge(team_id,enabled,threshold_cents,amount_cents,updated_by) VALUES($1,true,$2,$3,$4)
 ON CONFLICT(team_id) DO UPDATE SET enabled=true,threshold_cents=$2,amount_cents=$3,updated_by=$4,updated_at=clock_timestamp(),
  disabled_reason=NULL,disabled_at=NULL,disabled_by=NULL,notified_at=NULL`, team, req.ThresholdCents, req.AmountCents, actor)
		}
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if err = tx.Commit(ctx); err != nil {
		respondError(c, ErrInternal)
		return
	}
	raw, err := h.prepaidSummary(ctx, team, 0)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

func (h *Handlers) GetPlatformTeamPrepaid(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	raw, err := h.prepaidSummary(c.Request.Context(), team, 200)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

func (h *Handlers) DisablePlatformAutoRecharge(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	reason, ok := bindMatchingReason(c)
	if !ok {
		return
	}
	var disabled time.Time
	err = h.Pool.QueryRow(c.Request.Context(), `UPDATE billing_prepaid_auto_recharge SET enabled=false,disabled_reason=$2,disabled_at=clock_timestamp(),disabled_by=$3,notified_at=clock_timestamp(),updated_at=clock_timestamp()
 WHERE team_id=$1 AND enabled RETURNING disabled_at`, team, "disabled by staff: "+reason, actor).Scan(&disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "not_found", "auto-recharge is not enabled for this team", http.StatusNotFound)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"team_id": team, "disabled_at": disabled, "disabled_by": actor, "disabled_reason": "disabled by staff: " + reason})
}

// Prepaid revenue is cash received when a purchase was paid; it is never MRR.
func (h *Handlers) ListPrepaidPurchases(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	from, errFrom := time.Parse(time.RFC3339, strings.TrimSpace(c.Query("from")))
	to, errTo := time.Parse(time.RFC3339, strings.TrimSpace(c.Query("to")))
	if errFrom != nil || errTo != nil || !to.After(from) {
		respondErrorMsg(c, "bad_request", "from and to must be RFC3339 times with to after from", http.StatusBadRequest)
		return
	}
	var raw []byte
	err := h.Pool.QueryRow(c.Request.Context(), `SELECT jsonb_build_object(
 'total_cents',(SELECT COALESCE(sum(amount_cents),0) FROM billing_prepaid_purchase WHERE payment_state='succeeded' AND paid_at>=$1 AND paid_at<$2),
 'count',(SELECT count(*) FROM billing_prepaid_purchase WHERE payment_state='succeeded' AND paid_at>=$1 AND paid_at<$2),
 'purchases',(SELECT COALESCE(jsonb_agg(`+prepaidPurchaseJSON+` ORDER BY p.paid_at,p.id),'[]') FROM
   (SELECT * FROM billing_prepaid_purchase WHERE payment_state='succeeded' AND paid_at>=$1 AND paid_at<$2 ORDER BY paid_at,id LIMIT 1000) p))`, from, to).Scan(&raw)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}
