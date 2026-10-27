package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"
)

type prepaidCheckoutBody struct {
	OperationID uuid.UUID `json:"operation_id,omitempty"`
	AmountCents int64     `json:"amount_cents"`
	SuccessURL  string    `json:"success_url"`
	CancelURL   string    `json:"cancel_url"`
}

type prepaidAutoRechargeBody struct {
	Enabled        bool  `json:"enabled"`
	ThresholdCents int64 `json:"threshold_cents"`
	AmountCents    int64 `json:"amount_cents"`
}

const prepaidPurchaseJSON = `jsonb_build_object('id',p.id,'team_id',p.team_id,'source',p.source,'amount_cents',p.amount_cents,
 'state',CASE WHEN p.payment_state='failed' THEN 'failed' WHEN p.credit_state='issued' THEN 'credited' WHEN p.payment_state='succeeded' THEN 'paid' ELSE 'pending' END,
 'failure_reason',p.failure_reason,'paid_at',p.paid_at,'credited_at',p.credited_at,'created_at',p.created_at,
 'reversal',(SELECT jsonb_build_object('version',r.version,'refunded_cents',r.refunded_cents,'dispute_status',r.dispute_status,'disputed_cents',r.disputed_cents,
   'detected_at',r.detected_at,'observed_at',r.observed_at,'state',billing_prepaid_reversal_state(r.purchase_id),
   'decisions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('version',d.version,'decision',d.decision,'decided_by',d.decided_by,'reason',d.reason,'decided_at',d.decided_at,
     'revoked_cents',d.revoked_cents,'revoked_at',d.revoked_at,'revoke_attempted_at',d.revoke_attempted_at,
     'revoke_closed_unexecuted',d.revoked_at IS NULL AND d.revoke_retry_after IS NOT DISTINCT FROM 'infinity') ORDER BY d.version),'[]') FROM billing_prepaid_reversal_decision d WHERE d.purchase_id=r.purchase_id))
  FROM billing_prepaid_reversal r WHERE r.purchase_id=p.id))`

const prepaidAutoRechargeCapExceededSQL = `(a.amount_cents>1000000 OR a.threshold_cents>1000000)`
const prepaidAutoRechargeEnabledSQL = `(COALESCE(a.enabled,false) AND NOT ` + prepaidAutoRechargeCapExceededSQL + `)`

const prepaidAutoRechargeJSON = `jsonb_build_object('enabled',` + prepaidAutoRechargeEnabledSQL + `,'threshold_cents',a.threshold_cents,'amount_cents',a.amount_cents,
 'disabled_reason',CASE WHEN a.enabled AND ` + prepaidAutoRechargeCapExceededSQL + ` THEN '` + prepaidAutoRechargeCapReason + `' ELSE a.disabled_reason END,'disabled_at',a.disabled_at,
 'in_flight',EXISTS(SELECT 1 FROM billing_prepaid_purchase q WHERE q.team_id=t.team_id AND q.source='auto_recharge' AND q.payment_state IN ('pending','uncertain','processing')))`

func (h *Handlers) prepaidSummary(ctx context.Context, team uuid.UUID, purchases int) ([]byte, error) {
	var raw []byte
	err := h.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'checkout_idempotency_supported',true,
 'balance_cents',CASE WHEN f.observe AND f.observed_generation=f.generation AND f.credit_valid_until>clock_timestamp() THEN floor(f.credit_usd*100)::bigint ELSE 0 END,
 'low_balance',(CASE WHEN f.observe AND f.observed_generation=f.generation AND f.credit_valid_until>clock_timestamp() THEN floor(f.credit_usd*100)::bigint ELSE 0 END)<500 AND NOT `+prepaidAutoRechargeEnabledSQL+`,
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
		respondErrorMsg(c, "bad_request", "amount_cents must be a multiple of 500 between 500 and 1000000", http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	client, _ := h.Stripe.(*stripeHTTPClient)
	recoverOperation := func() bool {
		handled, resumeErr := h.resumePrepaidCheckoutOperation(c, client, team, actor, req)
		if resumeErr != nil {
			log.Warn().Err(resumeErr).Str("team_id", team.String()).Str("purchase_id", req.OperationID.String()).Msg("prepaid checkout operation awaits recovery")
			c.JSON(http.StatusAccepted, prepaidOperationResponse{PurchaseID: req.OperationID, State: "pending"})
		}
		return handled || resumeErr != nil
	}
	acceptedRedirects := false
	if req.OperationID != uuid.Nil {
		for _, raw := range []*string{&req.SuccessURL, &req.CancelURL} {
			if parsed, parseErr := url.Parse(strings.TrimSpace(*raw)); parseErr == nil {
				*raw = parsed.String()
			}
		}
		acceptedRedirects, err = h.acceptedPrepaidCheckoutOperation(ctx, team, actor, req)
		if err != nil {
			if errors.Is(err, errPrepaidOperationConflict) {
				respondErrorMsg(c, "operation_conflict", err.Error(), 409)
			} else {
				respondError(c, ErrInternal)
			}
			return
		}
		if acceptedRedirects && recoverOperation() {
			return
		}
	}
	if !acceptedRedirects && !validNewPrepaidAmount(req.AmountCents) {
		respondErrorMsg(c, "bad_request", "amount_cents must be a multiple of 500 between 500 and 1000000", http.StatusBadRequest)
		return
	}
	// Managed billing and other entry policies govern new dispatch, while an
	// already accepted payment remains recoverable under its immutable identity.
	var managed bool
	if err = h.Pool.QueryRow(ctx, `SELECT qm_team_managed_billing($1)`, team).Scan(&managed); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if managed {
		if acceptedRedirects {
			c.JSON(http.StatusAccepted, prepaidOperationResponse{PurchaseID: req.OperationID, State: "pending"})
		} else {
			respondErrorMsg(c, "forbidden", "This team's billing is managed by QM", http.StatusForbidden)
		}
		return
	}
	if client == nil {
		respondErrorMsg(c, "service_unavailable", "Stripe billing is not configured", http.StatusServiceUnavailable)
		return
	}
	if req.OperationID != uuid.Nil && !acceptedRedirects {
		req.SuccessURL, err = h.validateBillingRedirectURL(req.SuccessURL)
		if err != nil {
			respondErrorMsg(c, "bad_request", "invalid success_url", 400)
			return
		}
		req.CancelURL, err = h.validateBillingRedirectURL(req.CancelURL)
		if err != nil {
			respondErrorMsg(c, "bad_request", "invalid cancel_url", 400)
			return
		}
		if err = h.bindPrepaidCheckoutOperation(ctx, team, actor, req); err != nil {
			if errors.Is(err, errPrepaidOperationConflict) {
				respondErrorMsg(c, "operation_conflict", err.Error(), 409)
			} else {
				respondError(c, ErrInternal)
			}
			return
		}
		if recoverOperation() {
			return
		}
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
		h.createPAYGCheckout(c, team, actor, billingCheckoutSessionRequest{SuccessURL: req.SuccessURL, CancelURL: req.CancelURL}, false, &prepaidCheckoutLine{AmountCents: req.AmountCents, OperationID: req.OperationID, acceptedRedirects: acceptedRedirects})
		return
	}
	successURL, cancelURL := req.SuccessURL, req.CancelURL
	if !acceptedRedirects {
		successURL, err = h.validateBillingRedirectURL(req.SuccessURL)
		if err != nil {
			respondErrorMsg(c, "bad_request", "invalid success_url", http.StatusBadRequest)
			return
		}
		cancelURL, err = h.validateBillingRedirectURL(req.CancelURL)
		if err != nil {
			respondErrorMsg(c, "bad_request", "invalid cancel_url", http.StatusBadRequest)
			return
		}
	}
	session, err := h.startPrepaidPaymentCheckout(ctx, client, team, actor, derefString(account.StripeCustomerID), req.AmountCents, successURL, cancelURL, req.OperationID)
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
	if req.OperationID != uuid.Nil {
		c.JSON(http.StatusOK, prepaidOperationResponse{ID: session.ID, URL: session.URL, PurchaseID: req.OperationID, State: "pending"})
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
		if !validNewPrepaidAmount(req.ThresholdCents) || !validNewPrepaidAmount(req.AmountCents) {
			respondErrorMsg(c, "bad_request", "threshold_cents and amount_cents must be multiples of 500 between 500 and 1000000", http.StatusBadRequest)
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
	raw, err := h.prepaidRevenue(c.Request.Context(), from, to)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

func (h *Handlers) prepaidRevenue(ctx context.Context, from, to time.Time) ([]byte, error) {
	var raw []byte
	err := h.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'gross_cents',(SELECT COALESCE(sum(amount_cents),0) FROM billing_prepaid_purchase WHERE payment_state='succeeded' AND paid_at>=$1 AND paid_at<$2),
 'refunded_cents',(SELECT COALESCE(sum(r.refunded_cents),0) FROM billing_prepaid_purchase p JOIN billing_prepaid_reversal r ON r.purchase_id=p.id WHERE p.payment_state='succeeded' AND p.paid_at>=$1 AND p.paid_at<$2),
 'dispute_lost_cents',(SELECT COALESCE(sum(r.disputed_cents),0) FROM billing_prepaid_purchase p JOIN billing_prepaid_reversal r ON r.purchase_id=p.id WHERE p.payment_state='succeeded' AND p.paid_at>=$1 AND p.paid_at<$2 AND r.dispute_status='lost'),
 'dispute_open_cents',(SELECT COALESCE(sum(r.disputed_cents),0) FROM billing_prepaid_purchase p JOIN billing_prepaid_reversal r ON r.purchase_id=p.id WHERE p.payment_state='succeeded' AND p.paid_at>=$1 AND p.paid_at<$2 AND r.dispute_status=ANY($3)),
 'inquiry_cents',(SELECT COALESCE(sum(r.disputed_cents),0) FROM billing_prepaid_purchase p JOIN billing_prepaid_reversal r ON r.purchase_id=p.id WHERE p.payment_state='succeeded' AND p.paid_at>=$1 AND p.paid_at<$2 AND r.dispute_status IN ('warning_needs_response','warning_under_review')),
 'dispute_recovered_cents',(SELECT COALESCE(sum(r.disputed_cents),0) FROM billing_prepaid_purchase p JOIN billing_prepaid_reversal r ON r.purchase_id=p.id WHERE p.payment_state='succeeded' AND p.paid_at>=$1 AND p.paid_at<$2 AND r.dispute_status='won'),
 'total_cents',(SELECT COALESCE(sum(p.amount_cents-COALESCE(r.refunded_cents,0)-CASE WHEN r.dispute_status='lost' THEN r.disputed_cents ELSE 0 END),0) FROM billing_prepaid_purchase p LEFT JOIN billing_prepaid_reversal r ON r.purchase_id=p.id WHERE p.payment_state='succeeded' AND p.paid_at>=$1 AND p.paid_at<$2),
 'count',(SELECT count(*) FROM billing_prepaid_purchase WHERE payment_state='succeeded' AND paid_at>=$1 AND paid_at<$2),
 'purchases',(SELECT COALESCE(jsonb_agg(`+prepaidPurchaseJSON+` ORDER BY p.paid_at,p.id),'[]') FROM
   (SELECT * FROM billing_prepaid_purchase WHERE payment_state='succeeded' AND paid_at>=$1 AND paid_at<$2 ORDER BY paid_at,id LIMIT 1000) p))`, from, to, prepaidWithdrawnDisputeStates).Scan(&raw)
	return raw, err
}

// Reversed purchases whose latest observation has no staff decision yet.
func (h *Handlers) ListPrepaidReversals(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	var raw []byte
	err := h.Pool.QueryRow(c.Request.Context(), `SELECT COALESCE(jsonb_agg(`+prepaidPurchaseJSON+` ORDER BY p.reversal_observed_at),'[]') FROM
 (SELECT p.*,r.observed_at reversal_observed_at FROM billing_prepaid_reversal r JOIN billing_prepaid_purchase p ON p.id=r.purchase_id
  WHERE NOT EXISTS(SELECT 1 FROM billing_prepaid_reversal_decision d WHERE d.purchase_id=r.purchase_id AND d.version=r.version)
  ORDER BY r.observed_at LIMIT 200) p`).Scan(&raw)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(`{"reversals":`+string(raw)+`}`))
}

type prepaidReversalBody struct {
	Decision string `json:"decision"`
	Version  int32  `json:"version"`
	Reason   string `json:"reason"`
}

// Staff decide the latest observation of a reversed purchase: keep leaves the
// credit (for example after a won dispute); revoke voids only what is still
// unspent. A newer observation reopens the purchase for a fresh decision.
func (h *Handlers) ResolvePrepaidReversal(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	purchase, err := parseUUIDParam(c, "purchase_id")
	if err != nil {
		return
	}
	var req prepaidReversalBody
	err = c.ShouldBindJSON(&req)
	reason := strings.TrimSpace(req.Reason)
	if err != nil || (req.Decision != "revoke" && req.Decision != "keep") || req.Version < 1 || reason == "" || len([]rune(reason)) > 500 {
		respondErrorMsg(c, "bad_request", "decision must be revoke or keep, version is the reversal version decided, and a reason of at most 500 characters is required", http.StatusBadRequest)
		return
	}
	var decided time.Time
	err = h.Pool.QueryRow(c.Request.Context(), `INSERT INTO billing_prepaid_reversal_decision(purchase_id,version,decision,decided_by,reason)
 SELECT r.purchase_id,$3,$4,$5,$6 FROM billing_prepaid_reversal r WHERE r.purchase_id=$1 AND r.team_id=$2 AND r.version=$3
 ON CONFLICT(purchase_id,version) DO NOTHING RETURNING decided_at`, purchase, team, req.Version, req.Decision, actor, reason).Scan(&decided)
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == "P0001") {
		respondErrorMsg(c, "conflict", "this reversal version is already decided or is not the latest observation", http.StatusConflict)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"purchase_id": purchase, "version": req.Version, "decision": req.Decision, "decided_at": decided, "decided_by": actor, "reason": reason})
}
