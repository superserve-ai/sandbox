package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/db"
)

func (s *YCOfferAcceptanceService) available() bool {
	return s != nil && s.Pool != nil && s.Shared != nil && s.Region != "" && s.Authorize != nil
}

func (s *YCOfferAcceptanceService) rpc(ctx context.Context, q db.DBTX, op string, p any) (json.RawMessage, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = q.QueryRow(ctx, `SELECT public.yc_offer_acceptance_rpc($1,$2::jsonb)`, op, raw).Scan(&out)
	return out, err
}

func ycAcceptanceParameters(r YCAcceptanceRecord) map[string]any {
	return map[string]any{"acceptance_id": r.ID, "claim_id": r.ClaimID, "team_id": r.TeamID, "user_id": r.UserID, "home_region": r.HomeRegion,
		"company_identity": r.Company, "approval_id": r.ApprovalID, "approval_revision": r.ApprovalRevision, "offer_key": r.OfferKey, "offer_version": r.OfferVersion,
		"terms_digest": r.TermsDigest, "renewal_terms_digest": r.RenewalTermsDigest, "request_id": r.RequestID, "accepted_at": r.AcceptedAt, "assignment_id": r.AssignmentID}
}

func loadYCAcceptance(ctx context.Context, q db.DBTX, team, claim uuid.UUID) (YCAcceptanceRecord, error) {
	var r YCAcceptanceRecord
	var authority, terms, renewal []byte
	err := q.QueryRow(ctx, `SELECT id,authority,terms,renewal_terms,terms_digest,renewal_terms_digest,pricing_at,request_id,accepted_at,assignment_id,operation_id,state FROM yc_offer_acceptance WHERE team_id=$1 AND claim_id=$2`, team, claim).
		Scan(&r.ID, &authority, &terms, &renewal, &r.TermsDigest, &r.RenewalTermsDigest, &r.PricingAt, &r.RequestID, &r.AcceptedAt, &r.AssignmentID, &r.OperationID, &r.State)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(authority, &r.YCAcceptanceAuthority); err != nil {
		return r, err
	}
	if err = json.Unmarshal(terms, &r.Terms); err != nil {
		return r, err
	}
	err = json.Unmarshal(renewal, &r.RenewalTerms)
	if err == nil && (r.TeamID != team || r.ClaimID != claim || ycAcceptanceDigest(r.Terms) != r.TermsDigest || ycAcceptanceDigest(r.RenewalTerms) != r.RenewalTermsDigest) {
		err = errYCAcceptanceConflict
	}
	return r, err
}

func rollbackYCAcceptance(ctx context.Context, tx pgx.Tx) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(cleanup)
}

// Same team/account order as signup admission. The existing claim intent is the
// durable fence against a second checkout while shared confirmation is retried.
func (s *YCOfferAcceptanceService) lockNewSignup(ctx context.Context, tx pgx.Tx, a YCAcceptanceAuthority) error {
	var home string
	var created time.Time
	if err := tx.QueryRow(ctx, `SELECT home_region,created_at FROM team WHERE id=$1 FOR NO KEY UPDATE`, a.TeamID).Scan(&home, &created); err != nil {
		return err
	}
	if home != s.Region || home != a.HomeRegion || a.ClaimCreatedAt.IsZero() || created.Before(a.ClaimCreatedAt) {
		return errYCAcceptanceConflict
	}
	if _, err := tx.Exec(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, a.TeamID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT team_id FROM billing_signup_choice WHERE team_id=$1 FOR UPDATE`, a.TeamID); err != nil {
		return err
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM yc_claim_team_intent WHERE team_id=$1 AND claim_id=$2 AND user_id=$3 AND released_at IS NULL)
 AND EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=$1 AND state='selecting')
 AND NOT EXISTS(SELECT 1 FROM stripe_promotion_migration_fence WHERE team_id=$1)
 AND NOT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1)
 AND NOT EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND (stripe_customer_id IS NOT NULL OR stripe_subscription_id IS NOT NULL OR checkout_initializing_at IS NOT NULL OR stripe_activation_credit_reserved_at IS NOT NULL OR stripe_activation_credit_grant_id IS NOT NULL))`, a.TeamID, a.ClaimID, a.UserID).Scan(&allowed)
	if err == nil && !allowed {
		err = errYCAcceptanceConflict
	}
	return err
}

func (s *YCOfferAcceptanceService) Offer(ctx context.Context, user, team, claim uuid.UUID) (YCAcceptanceRecord, error) {
	var r YCAcceptanceRecord
	if !s.available() {
		return r, errYCAcceptanceUnavailable
	}
	if err := s.Authorize(ctx, user, team); err != nil {
		return r, err
	}
	raw, err := s.rpc(ctx, s.Shared, "offer", map[string]any{"claim_id": claim, "team_id": team, "user_id": user, "home_region": s.Region})
	if err != nil {
		return r, err
	}
	var a YCAcceptanceAuthority
	if err = json.Unmarshal(raw, &a); err != nil {
		return r, err
	}
	r, err = loadYCAcceptance(ctx, s.Pool, team, claim)
	if err == nil {
		if !r.YCAcceptanceAuthority.equal(a) {
			return r, errYCAcceptanceConflict
		}
		return r, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return r, err
	}
	if s.Catalog == nil {
		return r, errYCAcceptanceUnavailable
	}
	disclosure, err := s.Catalog.Resolve(ctx, a)
	if err != nil {
		return r, err
	}
	if err = disclosure.validate(a); err != nil {
		return r, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollbackYCAcceptance(ctx, tx)
	if err = s.lockNewSignup(ctx, tx, a); err != nil {
		return r, err
	}
	authority, _ := json.Marshal(a)
	terms, _ := json.Marshal(disclosure.Terms)
	renewal, _ := json.Marshal(disclosure.RenewalTerms)
	_, err = tx.Exec(ctx, `INSERT INTO yc_offer_acceptance(id,claim_id,team_id,user_id,home_region,authority,terms,renewal_terms,terms_digest,renewal_terms_digest,pricing_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`, uuid.New(), claim, team, user, s.Region, authority, terms, renewal, ycAcceptanceDigest(disclosure.Terms), ycAcceptanceDigest(disclosure.RenewalTerms), disclosure.PricingAt)
	if err != nil {
		return r, err
	}
	r, err = loadYCAcceptance(ctx, tx, team, claim)
	if err != nil {
		return r, err
	}
	if !r.YCAcceptanceAuthority.equal(a) {
		return r, errYCAcceptanceConflict
	}
	return r, tx.Commit(ctx)
}

type ycAcceptanceRequest struct {
	ClaimID            uuid.UUID `json:"claim_id"`
	TeamID             uuid.UUID `json:"team_id"`
	AcceptanceID       uuid.UUID `json:"acceptance_id"`
	RequestID          uuid.UUID `json:"request_id"`
	ApprovalRevision   int64     `json:"approval_revision"`
	TermsDigest        string    `json:"terms_digest"`
	RenewalTermsDigest string    `json:"renewal_terms_digest"`
}

func (s *YCOfferAcceptanceService) Accept(ctx context.Context, user uuid.UUID, in ycAcceptanceRequest) (YCAcceptanceRecord, error) {
	var r YCAcceptanceRecord
	if !s.available() {
		return r, errYCAcceptanceUnavailable
	}
	if err := s.Authorize(ctx, user, in.TeamID); err != nil {
		return r, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollbackYCAcceptance(ctx, tx)
	r, err = loadYCAcceptance(ctx, tx, in.TeamID, in.ClaimID)
	if err != nil {
		return r, err
	}
	if r.UserID != user || r.ID != in.AcceptanceID || in.RequestID == uuid.Nil || r.ApprovalRevision != in.ApprovalRevision || r.TermsDigest != in.TermsDigest || r.RenewalTermsDigest != in.RenewalTermsDigest {
		return r, errYCAcceptanceConflict
	}
	if r.AcceptedAt != nil {
		if r.RequestID == nil || *r.RequestID != in.RequestID {
			return r, errYCAcceptanceConflict
		}
		return r, nil
	}
	if err = s.lockNewSignup(ctx, tx, r.YCAcceptanceAuthority); err != nil {
		return r, err
	}
	_, err = tx.Exec(ctx, `UPDATE yc_offer_acceptance SET request_id=$2,accepted_at=clock_timestamp(),state='confirming' WHERE id=$1 AND state='offered'`, r.ID, in.RequestID)
	if err != nil {
		return r, err
	}
	r, err = loadYCAcceptance(ctx, tx, in.TeamID, in.ClaimID)
	if err != nil {
		return r, err
	}
	if r.RequestID == nil || *r.RequestID != in.RequestID {
		return r, errYCAcceptanceConflict
	}
	shared, err := s.Shared.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer rollbackYCAcceptance(ctx, shared)
	if _, err = shared.Exec(ctx, "SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='3s'"); err != nil {
		return r, err
	}
	raw, err := s.rpc(ctx, shared, "offer", map[string]any{"claim_id": r.ClaimID, "team_id": r.TeamID, "user_id": r.UserID, "home_region": r.HomeRegion})
	if err != nil {
		return r, err
	}
	var authority YCAcceptanceAuthority
	if err = json.Unmarshal(raw, &authority); err != nil {
		return r, err
	}
	if !authority.equal(r.YCAcceptanceAuthority) {
		return r, errYCAcceptanceConflict
	}
	return r, tx.Commit(ctx)
}

// WithGuard holds only shared Auth locks. The callback must not acquire regional
// rows. A lost connection can leave a remote outcome unknown; it is never proof
// that the provider performed no operation.
func (s *YCOfferAcceptanceService) WithGuard(ctx context.Context, r YCAcceptanceRecord, f func(context.Context) error) error {
	return s.withGuard(ctx, r, "guard", f)
}

// WithSuccessorGuard checks the current requesting administrator while retaining
// the original accepted identity as shared authority. Like WithGuard, its callback
// is network-only; it does not authorize a regional financial commit.
func (s *YCOfferAcceptanceService) WithSuccessorGuard(ctx context.Context, r YCAcceptanceRecord, requester uuid.UUID, f func(context.Context) error) error {
	return s.withGuardForActor(ctx, r, "guard", requester, f)
}

func (s *YCOfferAcceptanceService) withGuard(ctx context.Context, r YCAcceptanceRecord, op string, f func(context.Context) error) error {
	return s.withGuardForActor(ctx, r, op, r.UserID, f)
}

func (s *YCOfferAcceptanceService) withGuardForActor(ctx context.Context, r YCAcceptanceRecord, op string, actor uuid.UUID, f func(context.Context) error) error {
	if !s.available() || actor == uuid.Nil || f == nil || r.AcceptedAt == nil || r.RequestID == nil || r.HomeRegion != s.Region {
		return errYCAcceptanceUnavailable
	}
	if err := s.Authorize(ctx, actor, r.TeamID); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.Shared.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackYCAcceptance(ctx, tx)
	if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout='1s'; SET LOCAL idle_in_transaction_session_timeout='25s'`); err != nil {
		return err
	}
	if _, err = s.rpc(ctx, tx, op, ycAcceptanceParameters(r)); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = f(ctx); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "SELECT 1")
	return err
}

// Financial admission uses a current permission read, not the general UI cache.
func (h *Handlers) authorizeYCAcceptance(ctx context.Context, user, team uuid.UUID) error {
	if h.Pool == nil || user == uuid.Nil || team == uuid.Nil {
		return errYCAcceptanceUnavailable
	}
	if err := authz.New(h.Pool).RequireTeamPermission(ctx, user, team, "billing:write"); err != nil {
		return err
	}
	var home string
	if err := h.Pool.QueryRow(ctx, `SELECT home_region FROM public.team WHERE id=$1`, team).Scan(&home); err != nil {
		return err
	}
	if home != ycClaimRegion() {
		return errYCAcceptanceConflict
	}
	return nil
}

func (h *Handlers) ycOfferHandler(c *gin.Context, operation string) {
	if !c.GetBool("yc_acceptance_verified") || actorIDFromContext(c) == nil {
		respondError(c, ErrForbidden)
		return
	}
	var in ycAcceptanceRequest
	if !decodePromotionRequest(c, &in) {
		return
	}
	if in.ClaimID == uuid.Nil || in.TeamID == uuid.Nil {
		respondErrorMsg(c, "invalid_request", "Claim and team required.", 400)
		return
	}
	user := *actorIDFromContext(c)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	if err := h.authorizeYCAcceptance(ctx, user, in.TeamID); err != nil {
		respondError(c, ErrForbidden)
		return
	}
	s := h.YCOfferAcceptance
	if !s.available() {
		respondErrorMsg(c, "acceptance_unavailable", "Offer service unavailable.", 503)
		return
	}
	var r YCAcceptanceRecord
	var err error
	switch operation {
	case "offer":
		r, err = loadYCAcceptance(ctx, s.Pool, in.TeamID, in.ClaimID)
		if errors.Is(err, pgx.ErrNoRows) {
			r, err = s.Offer(ctx, user, in.TeamID, in.ClaimID)
		}
		if err == nil {
			r, err = s.Status(ctx, user, in.TeamID, in.ClaimID)
		}
	case "accept":
		r, err = s.Accept(ctx, user, in)
		if err == nil {
			r, err = s.Status(ctx, user, in.TeamID, in.ClaimID)
		}
	case "status":
		r, err = s.Status(ctx, user, in.TeamID, in.ClaimID)
	}
	if errors.Is(err, pgx.ErrNoRows) && operation == "status" {
		c.JSON(200, gin.H{"state": "acceptance_required", "ready": false, "financial_authority": YCFinancialState{Kind: "accepted_offer", State: "acceptance_pending"}})
		return
	}
	if err != nil {
		if errors.Is(err, errYCAcceptanceConflict) {
			respondErrorMsg(c, "acceptance_conflict", "Offer or account requires review.", 409)
		} else {
			ycClaimError(c, err)
		}
		return
	}
	c.Header("Cache-Control", "private, no-store")
	status := http.StatusOK
	if operation == "accept" && r.State == "confirming" {
		status = http.StatusAccepted
	}
	c.JSON(status, r)
}

func (h *Handlers) YCOffer(c *gin.Context)       { h.ycOfferHandler(c, "offer") }
func (h *Handlers) AcceptYCOffer(c *gin.Context) { h.ycOfferHandler(c, "accept") }
func (h *Handlers) YCOfferStatus(c *gin.Context) { h.ycOfferHandler(c, "status") }
