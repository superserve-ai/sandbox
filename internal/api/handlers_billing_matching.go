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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type matchingRuleRequest struct {
	MatchingBps       int32      `json:"matching_bps"`
	CapCents          int64      `json:"cap_cents"`
	PriorMatchedCents int64      `json:"prior_matched_cents"`
	EffectiveFrom     *time.Time `json:"effective_from"`
	Reason            string     `json:"reason"`
}

type matchingReasonRequest struct {
	Reason string `json:"reason"`
}

// A match held for a reversed payment must be resolved: withhold ends it
// without a grant (its cap stays consumed), issue sends the grant anyway.
type matchingAcknowledgeRequest struct {
	Reason     string `json:"reason"`
	Resolution string `json:"resolution"`
}

func bindMatchingReason(c *gin.Context) (string, bool) {
	var req matchingReasonRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Reason) == "" {
		respondErrorMsg(c, "bad_request", "reason is required", http.StatusBadRequest)
		return "", false
	}
	return strings.TrimSpace(req.Reason), true
}

const matchingRuleJSON = `jsonb_build_object('contract_id',r.contract_id,'offer_key',c.offer_key,'matching_bps',r.matching_bps,'cap_cents',r.cap_cents,
 'prior_matched_cents',r.prior_matched_cents,'matched_cents',m.matched,'remaining_cents',greatest(r.cap_cents-r.prior_matched_cents-m.matched,0),
 'eligible_source',r.eligible_source,'effective_from',r.effective_from,'source',r.source,'created_by',r.created_by,'reason',r.reason,'created_at',r.created_at,
 'revoked_at',r.revoked_at,'revoked_by',r.revoked_by,'revoke_reason',r.revoke_reason)`

const matchingCreditJSON = `jsonb_build_object('id',x.id,'team_id',x.team_id,'contract_id',x.contract_id,'invoice_id',x.invoice_id,'period_start',x.period_start,'period_end',x.period_end,
 'usage_cents',x.usage_cents,'credit_applied_cents',x.credit_applied_cents,'discount_cents',x.discount_cents,'matchable_cents',x.matchable_cents,
 'amount_cents',x.amount_cents,'state',x.state,'skip_reason',x.skip_reason,'stripe_credit_grant_id',x.stripe_credit_grant_id,'issued_at',x.issued_at,
 'last_error',x.last_error,'flagged_at',x.flagged_at,'flag_reason',x.flag_reason,'acknowledged_at',x.acknowledged_at,'acknowledged_by',x.acknowledged_by,'acknowledgement_reason',x.acknowledgement_reason,'created_at',x.created_at)`

func (h *Handlers) GetTeamMatchingCredit(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	var raw []byte
	err = h.Pool.QueryRow(c.Request.Context(), `SELECT jsonb_build_object(
 'rules',(SELECT COALESCE(jsonb_agg(`+matchingRuleJSON+` ORDER BY r.created_at DESC),'[]') FROM billing_contract_matching_rule r
   JOIN billing_commercial_contract c ON c.id=r.contract_id
   CROSS JOIN LATERAL (SELECT COALESCE(sum(amount_cents),0) matched FROM billing_matching_credit WHERE contract_id=r.contract_id) m WHERE r.team_id=$1),
 'credits',(SELECT COALESCE(jsonb_agg(`+matchingCreditJSON+` ORDER BY x.created_at DESC),'[]') FROM
   (SELECT * FROM billing_matching_credit WHERE team_id=$1 ORDER BY created_at DESC LIMIT 200) x))`, team).Scan(&raw)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

func (h *Handlers) ListMatchingCreditFlags(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	var raw []byte
	err := h.Pool.QueryRow(c.Request.Context(), `SELECT COALESCE(jsonb_agg(`+matchingCreditJSON+` ORDER BY x.flagged_at),'[]') FROM
 (SELECT * FROM billing_matching_credit WHERE flagged_at IS NOT NULL AND acknowledged_at IS NULL ORDER BY flagged_at LIMIT 200) x`).Scan(&raw)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(`{"flags":`+string(raw)+`}`))
}

// Attaches a matching rule to the team's current arrangement so hand-managed
// deals move into the system. Cap already matched by hand is carried over.
func (h *Handlers) AttachTeamMatchingRule(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	var req matchingRuleRequest
	if err = c.ShouldBindJSON(&req); err != nil || req.MatchingBps < 1 || req.MatchingBps > 10000 || req.CapCents <= 0 || req.PriorMatchedCents < 0 || req.PriorMatchedCents > req.CapCents || strings.TrimSpace(req.Reason) == "" {
		respondErrorMsg(c, "bad_request", "matching_bps must be 1-10000, cap_cents positive, prior_matched_cents between 0 and cap_cents, and reason is required", http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	var contract uuid.UUID
	var anchor time.Time
	var tracked bool
	err = tx.QueryRow(ctx, `SELECT c.id,c.entitlement_anchor,EXISTS(SELECT 1 FROM billing_entitlement_work w WHERE w.contract_id=c.id)
 FROM billing_commercial_contract c WHERE c.team_id=$1 AND c.status='active' AND (c.ends_at IS NULL OR c.ends_at>clock_timestamp()) FOR UPDATE`, team).Scan(&contract, &anchor, &tracked)
	if errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "conflict", "team has no active commercial contract to attach matching to", http.StatusConflict)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if !tracked {
		respondErrorMsg(c, "conflict", "contract is not managed by the entitlement worker", http.StatusConflict)
		return
	}
	current, _, ok := billing.AnniversaryPeriod(anchor, h.nowUTC())
	if !ok {
		current = anchor
	}
	effective := current
	if req.EffectiveFrom != nil {
		effective = req.EffectiveFrom.UTC().Truncate(time.Second)
	}
	if effective.Before(current) {
		respondErrorMsg(c, "bad_request", "effective_from cannot precede the current billing period; past usage is never matched retroactively", http.StatusBadRequest)
		return
	}
	err = insertContractMatchingRule(ctx, tx, matchingRule{ContractID: contract, TeamID: team, Terms: matchingTerms{MatchingBps: req.MatchingBps, CapCents: req.CapCents}, PriorMatchedCents: req.PriorMatchedCents, EffectiveFrom: effective, Source: "staff", Actor: &actor, Reason: new(strings.TrimSpace(req.Reason))})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		respondErrorMsg(c, "conflict", "contract already has a matching rule", http.StatusConflict)
		return
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"contract_id": contract, "matching_bps": req.MatchingBps, "cap_cents": req.CapCents, "prior_matched_cents": req.PriorMatchedCents, "effective_from": effective, "source": "staff", "created_by": actor, "reason": strings.TrimSpace(req.Reason)})
}

// Revocation stops matching for usage periods that start afterwards; credit
// already earned is still issued.
func (h *Handlers) RevokeTeamMatchingRule(c *gin.Context) {
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
	var contract uuid.UUID
	var revoked time.Time
	err = h.Pool.QueryRow(c.Request.Context(), `UPDATE billing_contract_matching_rule r SET revoked_at=clock_timestamp(),revoked_by=$2,revoke_reason=$3
 FROM billing_commercial_contract c WHERE c.id=r.contract_id AND r.team_id=$1 AND c.status<>'ended' AND r.revoked_at IS NULL RETURNING r.contract_id,r.revoked_at`, team, actor, reason).Scan(&contract, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "not_found", "team has no active matching rule", http.StatusNotFound)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"contract_id": contract, "revoked_at": revoked, "revoked_by": actor, "revoke_reason": reason})
}

func (h *Handlers) AcknowledgeMatchingCreditFlag(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	team, err := internalTeamID(c)
	if err != nil {
		return
	}
	credit, err := parseUUIDParam(c, "credit_id")
	if err != nil {
		return
	}
	var req matchingAcknowledgeRequest
	if err = c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Reason) == "" || (req.Resolution != "" && req.Resolution != "withhold" && req.Resolution != "issue") {
		respondErrorMsg(c, "bad_request", "reason is required; resolution must be withhold or issue", http.StatusBadRequest)
		return
	}
	reason := strings.TrimSpace(req.Reason)
	acknowledged, state, err := acknowledgeMatchingFlag(c.Request.Context(), h.Pool, team, credit, actor, reason, req.Resolution)
	if errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "conflict", "no matching unacknowledged flag; pending needs withhold or issue, uncertain needs explicit issue or continued provider recovery, and completed states accept no resolution", http.StatusConflict)
		return
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": credit, "state": state, "acknowledged_at": acknowledged, "acknowledged_by": actor, "acknowledgement_reason": reason})
}

func acknowledgeMatchingFlag(ctx context.Context, q db.DBTX, team, credit, actor uuid.UUID, reason, resolution string) (time.Time, string, error) {
	var acknowledged time.Time
	var state string
	err := q.QueryRow(ctx, `UPDATE billing_matching_credit SET acknowledged_at=clock_timestamp(),acknowledged_by=$3,acknowledgement_reason=$4,
 state=CASE WHEN state='pending' AND $5='withhold' THEN 'withheld' ELSE state END,next_attempt_at=clock_timestamp()
 WHERE id=$1 AND team_id=$2 AND flagged_at IS NOT NULL AND acknowledged_at IS NULL
 AND ((state='pending' AND $5 IN ('withhold','issue')) OR (state='uncertain' AND $5='issue') OR (state NOT IN ('pending','uncertain') AND $5='')) RETURNING acknowledged_at,state`, credit, team, actor, reason, resolution).Scan(&acknowledged, &state)
	return acknowledged, state, err
}
