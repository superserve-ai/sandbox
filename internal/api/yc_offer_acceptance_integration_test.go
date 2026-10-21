package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/ycclaims"
)

type acceptanceCatalogFixture struct {
	disclosure          YCAcceptanceDisclosure
	assignment          uuid.UUID
	calls               int
	loseAcknowledgement bool
}

func (f *acceptanceCatalogFixture) Resolve(context.Context, YCAcceptanceAuthority) (YCAcceptanceDisclosure, error) {
	return f.disclosure, nil
}
func (f *acceptanceCatalogFixture) Assign(context.Context, YCAcceptanceRecord) (uuid.UUID, error) {
	f.calls++
	if f.assignment == uuid.Nil {
		f.assignment = uuid.New()
	}
	if f.loseAcknowledgement {
		f.loseAcknowledgement = false
		return uuid.Nil, errors.New("lost assignment acknowledgement")
	}
	return f.assignment, nil
}

type acceptanceProvisioningFixture struct {
	statusHook          func()
	operation           uuid.UUID
	calls               int
	loseAcknowledgement bool
	status              YCAcceptanceProvisioningStatus
}

func (f *acceptanceProvisioningFixture) Enqueue(context.Context, uuid.UUID, uuid.UUID) (uuid.UUID, error) {
	f.calls++
	if f.operation == uuid.Nil {
		f.operation = uuid.New()
	}
	if f.loseAcknowledgement {
		f.loseAcknowledgement = false
		return uuid.Nil, errors.New("lost operation acknowledgement")
	}
	return f.operation, nil
}
func (f *acceptanceProvisioningFixture) Status(context.Context, uuid.UUID, uuid.UUID) (YCAcceptanceProvisioningStatus, error) {
	if f.statusHook != nil {
		f.statusHook()
	}
	return f.status, nil
}

func acceptanceFixture(t *testing.T) (*YCOfferAcceptanceService, *Handlers, YCAcceptanceRecord, *acceptanceCatalogFixture, *acceptanceProvisioningFixture) {
	return acceptanceFixtureBeforeApproval(t, nil)
}

func acceptanceFixtureBeforeApproval(t *testing.T, before func(*Handlers, uuid.UUID)) (*YCOfferAcceptanceService, *Handlers, YCAcceptanceRecord, *acceptanceCatalogFixture, *acceptanceProvisioningFixture) {
	t.Helper()
	pool := staffTestPool(t)
	ctx := context.Background()
	h := &Handlers{Pool: pool, PromotionAuthPool: pool}
	migration, err := os.ReadFile(filepath.Join("..", "..", "supabase", "migrations", "20261021135340_yc_offer_acceptance.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	email := uuid.NewString() + "@example.test"
	user, team := uuid.New(), uuid.New()
	raw, err := h.ycClaimRPC(ctx, "submit", gin.H{"submitted_email": email, "founder_email": "founder@example.test", "company_identity": "https://www.ycombinator.com/companies/" + uuid.NewString(), "evidence": gin.H{"verified": true}, "verification_reference": ycclaims.Hash(email), "state": "manual_review", "reason": "email_mismatch"})
	if err != nil {
		t.Fatal(err)
	}
	var claim struct {
		ID uuid.UUID `json:"id"`
	}
	if err = json.Unmarshal(raw, &claim); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth.users(id,email,email_confirmed_at,created_at) VALUES($1,$2,now(),clock_timestamp())`, []any{user, email}},
		{`INSERT INTO team VALUES($1,clock_timestamp(),'use')`, []any{team}},
		{`INSERT INTO billing_signup_choice VALUES($1,'selecting',NULL)`, []any{team}},
	} {
		if _, err = pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if before != nil {
		before(h, claim.ID)
	}
	p := gin.H{"id": claim.ID, "user_id": user, "team_id": team, "home_region": "use", "actor_id": uuid.New(), "request_id": uuid.New(), "expected_revision": 0, "reason": "Reviewed synthetic signup", "evidence_reference": "synthetic-review"}
	if _, err = h.ycBindWithIntentRPC(ctx, "approve", p, h.ycStaffRPC); err != nil {
		t.Fatal(err)
	}
	terms := YCAcceptanceTerms{OfferKey: "yc_2026", OfferVersion: 1, Currency: "usd", TermMonths: 12, ChargeAmountCents: 1200000, ChargeIntervalMonths: 12, InitialFeeWaived: true, MonthlyAllowanceCents: []int64{3000000, 3000000, 3000000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000}, PaymentRequirement: "eligible_credit_or_verified_payment", RateCardKey: "payg", DefaultSuccessorFamily: "pro_annual"}
	for _, resource := range []string{"vcpu", "memory_gib", "storage_gib"} {
		terms.ResourceRates = append(terms.ResourceRates, YCAcceptanceRate{ID: uuid.New(), Resource: resource, Unit: "second", PriceUSD: "0.000001000000", Currency: "USD"})
	}
	renewal := terms
	renewal.OfferKey = "pro_annual"
	renewal.InitialFeeWaived = false
	renewal.PaymentRequirement = "verified_payment"
	renewal.MonthlyAllowanceCents = []int64{100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000, 100000}
	catalog := &acceptanceCatalogFixture{disclosure: YCAcceptanceDisclosure{Terms: terms, RenewalTerms: renewal, PricingAt: time.Now().UTC()}}
	provisioner := &acceptanceProvisioningFixture{}
	s := &YCOfferAcceptanceService{Pool: pool, Shared: pool, Region: "use", Catalog: catalog, Provisioning: provisioner, Authorize: func(_ context.Context, u, tm uuid.UUID) error {
		if u != user || tm != team {
			return errYCAcceptanceConflict
		}
		return nil
	}}
	r, err := s.Offer(ctx, user, team, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s, h, r, catalog, provisioner
}
func acceptanceRequest(r YCAcceptanceRecord) ycAcceptanceRequest {
	return ycAcceptanceRequest{ClaimID: r.ClaimID, TeamID: r.TeamID, AcceptanceID: r.ID, RequestID: uuid.New(), ApprovalRevision: r.ApprovalRevision, TermsDigest: r.TermsDigest, RenewalTermsDigest: r.RenewalTermsDigest}
}

func TestYCAcceptanceDurableHandoff(t *testing.T) {
	s, _, offered, catalog, provisioner := acceptanceFixture(t)
	ctx := context.Background()
	if work, err := s.RunOnce(ctx); err != nil || work {
		t.Fatalf("approval alone dispatched: %v %v", work, err)
	}
	in := acceptanceRequest(offered)
	bad := in
	bad.TermsDigest = ycclaims.Hash("changed")
	if _, err := s.Accept(ctx, offered.UserID, bad); !errors.Is(err, errYCAcceptanceConflict) {
		t.Fatal("changed terms accepted", err)
	}
	if _, err := s.Accept(ctx, uuid.New(), in); err == nil {
		t.Fatal("wrong account accepted")
	}
	accepted, err := s.Accept(ctx, offered.UserID, in)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.Accept(ctx, offered.UserID, in)
	if err != nil || !replay.AcceptedAt.Equal(*accepted.AcceptedAt) {
		t.Fatal("acceptance retry changed identity", err)
	}
	catalog.loseAcknowledgement = true
	if work, err := s.RunOnce(ctx); !work || err == nil {
		t.Fatal("lost assignment response not surfaced")
	}
	var state string
	if err = s.Pool.QueryRow(ctx, `SELECT state FROM yc_offer_acceptance WHERE id=$1`, offered.ID).Scan(&state); err != nil || state != "accepted" {
		t.Fatal(state, err)
	}
	if _, err = s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET next_attempt_at=now() WHERE id=$1`, offered.ID); err != nil {
		t.Fatal(err)
	}
	// Restart with the same durable stores and adapters, without any request state.
	restarted := *s
	if work, err := restarted.RunOnce(ctx); !work || err != nil {
		t.Fatal(work, err)
	}
	final, err := loadYCAcceptance(ctx, s.Pool, offered.TeamID, offered.ClaimID)
	if err != nil || final.AssignmentID == nil || *final.AssignmentID != catalog.assignment || final.OperationID == nil || *final.OperationID != provisioner.operation || catalog.calls != 2 || provisioner.calls != 1 {
		t.Fatalf("handoff did not converge: %+v %v", final, err)
	}
	if work, err := s.RunOnce(ctx); err != nil || work {
		t.Fatal("completed handoff was requeued", err)
	}
	provisioner.status = YCAcceptanceProvisioningStatus{OperationID: provisioner.operation, State: "grant_pending", Ready: true}
	status, err := s.Status(ctx, offered.UserID, offered.TeamID, offered.ClaimID)
	if err != nil || status.Ready {
		t.Fatal("pending grant reported ready", err)
	}
	var legacyAllowed bool
	if err = s.Shared.QueryRow(ctx, `SELECT public.lock_yc_activation_authority($1,$2,'use')`, offered.ApprovalID, offered.TeamID).Scan(&legacyAllowed); err != nil || legacyAllowed {
		t.Fatal("acceptance weakened legacy gate", err)
	}
}

func TestYCAcceptanceConcurrentRequests(t *testing.T) {
	s, _, r, _, _ := acceptanceFixture(t)
	in := acceptanceRequest(r)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Accept(ctx, r.UserID, in); results <- err }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	changed := in
	changed.RequestID = uuid.New()
	if _, err := s.Accept(ctx, r.UserID, changed); err == nil {
		t.Fatal("second request replaced acceptance")
	}
	wrongRegion := *s
	wrongRegion.Region = "usw"
	if _, err := wrongRegion.Offer(ctx, r.UserID, r.TeamID, r.ClaimID); err == nil {
		t.Fatal("cross-region acceptance admitted")
	}
}

func TestYCAcceptanceGuardSerializesIdentityAndRevocation(t *testing.T) {
	s, h, r, _, _ := acceptanceFixture(t)
	ctx := context.Background()
	in := acceptanceRequest(r)
	r, err := s.Accept(ctx, r.UserID, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.rpc(ctx, s.Shared, "accept", ycAcceptanceParameters(r)); err != nil {
		t.Fatal(err)
	}
	// Mail retry increments claim revision but does not change economic approval.
	var revision int64
	if err = s.Shared.QueryRow(ctx, `SELECT revision FROM yc_claim WHERE id=$1`, r.ClaimID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	_, err = h.ycStaffRPC(ctx, "retry-approval-email", gin.H{"id": r.ClaimID, "actor_id": uuid.New(), "request_id": uuid.New(), "expected_revision": revision, "reason": "retry synthetic mail", "evidence_reference": "synthetic", "home_region": "use"})
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithGuard(ctx, r, func(context.Context) error {
		for _, query := range []string{`SELECT id FROM auth.users WHERE id=$1 FOR UPDATE NOWAIT`, `SELECT approval_id FROM yc_company_activation_authority WHERE approved_by IS NOT NULL AND team_id=$1 FOR UPDATE NOWAIT`} {
			id := r.UserID
			if strings.Contains(query, "yc_company_activation_authority") {
				id = r.TeamID
			}
			tx, e := s.Shared.Begin(ctx)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, query, id)
			_ = tx.Rollback(ctx)
			if e == nil {
				t.Error("guard did not serialize identity or authority")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Shared.Exec(ctx, `UPDATE auth.users SET email='changed@example.test' WHERE id=$1`, r.UserID); err != nil {
		t.Fatal(err)
	}
	called := false
	if err = s.WithGuard(ctx, r, func(context.Context) error { called = true; return nil }); err == nil || called {
		t.Fatal("changed identity dispatched")
	}
	// A separate fixture exercises revoke first, without relying on the email fence.
	s2, h2, r2, _, _ := acceptanceFixture(t)
	r2, err = s2.Accept(ctx, r2.UserID, acceptanceRequest(r2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s2.rpc(ctx, s2.Shared, "accept", ycAcceptanceParameters(r2)); err != nil {
		t.Fatal(err)
	}
	if _, err = h2.ycClaimRPC(ctx, "revoke", gin.H{"id": r2.ClaimID, "actor_id": uuid.New(), "reason": "synthetic revoke", "evidence_reference": "synthetic", "home_region": "use"}); err != nil {
		t.Fatal(err)
	}
	if err = s2.WithGuard(ctx, r2, func(context.Context) error { t.Error("revoked approval dispatched"); return nil }); err == nil {
		t.Fatal("revocation ignored")
	}
}

func TestYCPreferredReviewBindsExactApprovedRecipient(t *testing.T) {
	pool := staffTestPool(t)
	h := &Handlers{Pool: pool, PromotionAuthPool: pool}
	ctx := context.Background()
	original := "original@example.test"
	preferred := "preferred@example.test"
	user, team := uuid.New(), uuid.New()
	company := "https://www.ycombinator.com/companies/example-team"
	raw, err := h.ycClaimRPC(ctx, "submit", gin.H{"submitted_email": original, "founder_email": original, "company_identity": company, "evidence": gin.H{"verified": true}, "verification_reference": ycclaims.Hash("synthetic-link"), "state": "manual_review", "reason": "review"})
	if err != nil {
		t.Fatal(err)
	}
	var claim struct {
		ID uuid.UUID `json:"id"`
	}
	if err = json.Unmarshal(raw, &claim); err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth.users(id,email,email_confirmed_at,created_at) VALUES($1,$2,now(),clock_timestamp())`, []any{user, preferred}},
		{`INSERT INTO team VALUES($1,clock_timestamp(),'use')`, []any{team}},
		{`INSERT INTO billing_signup_choice VALUES($1,'selecting',NULL)`, []any{team}},
	} {
		if _, err = pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	p := gin.H{"id": claim.ID, "user_id": user, "team_id": team, "request_id": uuid.New(), "home_region": "use", "verification_reference": ycclaims.Hash("synthetic-link"), "company_identity": company}
	raw, err = h.ycBindWithIntentRPC(ctx, "review", p, h.ycPreferredRPC)
	if err != nil {
		t.Fatal(err)
	}
	var review struct {
		ID       uuid.UUID `json:"review_request_id"`
		Revision int64     `json:"review_revision"`
	}
	if err = json.Unmarshal(raw, &review); err != nil {
		t.Fatal(err)
	}
	if _, err = h.ycBindWithIntentRPC(ctx, "review", p, h.ycPreferredRPC); err != nil {
		t.Fatal("review replay", err)
	}
	list, err := h.ycPreferredRPC(ctx, "lookup", gin.H{"user_id": user})
	if err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Claims []json.RawMessage `json:"claims"`
	}
	if err = json.Unmarshal(list, &listed); err != nil || len(listed.Claims) != 1 {
		t.Fatal("preferred account cannot resume", string(list), err)
	}
	decision := gin.H{"id": claim.ID, "user_id": user, "team_id": team, "actor_id": uuid.New(), "request_id": uuid.New(), "expected_revision": review.Revision, "home_region": "use", "reason": "Approve exact preferred identity", "evidence_reference": "synthetic-review", "review_request_id": review.ID, "review_revision": review.Revision}
	wrong := gin.H{}
	for k, v := range decision {
		wrong[k] = v
	}
	wrong["review_request_id"] = uuid.New()
	if _, err = h.ycBindWithIntentRPC(ctx, "approve", wrong, h.ycStaffRPC); err == nil {
		t.Fatal("different review approved")
	}
	if _, err = h.ycBindWithIntentRPC(ctx, "approve", decision, h.ycStaffRPC); err != nil {
		t.Fatal(err)
	}
	var recipient, unchanged string
	if err = pool.QueryRow(ctx, `SELECT m.approved_email,c.submitted_email FROM yc_claim_approval_mail m JOIN yc_claim c ON c.id=m.claim_id WHERE c.id=$1`, claim.ID).Scan(&recipient, &unchanged); err != nil || recipient != preferred || unchanged != original {
		t.Fatal("recipient/evidence mismatch", recipient, unchanged, err)
	}
	s := &YCOfferAcceptanceService{Shared: pool}
	if _, err = s.rpc(ctx, pool, "offer", gin.H{"claim_id": claim.ID, "team_id": team, "user_id": user, "home_region": "use"}); err != nil {
		t.Fatal("approved preferred identity cannot accept", err)
	}
	// Commit a financial receipt for B so lifecycle isolation covers the durable
	// invalidation path as well as read-time acceptance validation.
	authorityRaw, e := s.rpc(ctx, pool, "offer", gin.H{"claim_id": claim.ID, "team_id": team, "user_id": user, "home_region": "use"})
	if e != nil {
		t.Fatal(e)
	}
	var authority YCAcceptanceAuthority
	if e = json.Unmarshal(authorityRaw, &authority); e != nil {
		t.Fatal(e)
	}
	acceptedAt, request, assignment, operation := time.Now().UTC(), uuid.New(), uuid.New(), uuid.New()
	financialRecord := YCAcceptanceRecord{YCAcceptanceAuthority: authority, ID: uuid.New(), RequestID: &request, AcceptedAt: &acceptedAt, AssignmentID: &assignment, OperationID: &operation, TermsDigest: ycclaims.Hash("preferred initial"), RenewalTermsDigest: ycclaims.Hash("preferred successor")}
	for _, op := range []string{"accept", "link"} {
		if _, e = s.rpc(ctx, pool, op, ycAcceptanceParameters(financialRecord)); e != nil {
			t.Fatal(e)
		}
	}
	var financialReceipt YCFinancialAuthorization
	if e = ycFinancialRPC(ctx, pool, "issue", financialParams(financialRecord), &financialReceipt); e != nil {
		t.Fatal(e)
	}
	// Staff approved B explicitly. An unrelated account later using A cannot
	// revoke that decision, but B and the claim/company authority remain fences.
	originalUser := uuid.New()
	for _, change := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth.users(id,email,email_confirmed_at) VALUES($1,$2,now())`, []any{originalUser, original}},
		{`UPDATE auth.users SET email='unrelated@example.test' WHERE id=$1`, []any{originalUser}},
		{`DELETE FROM auth.users WHERE id=$1`, []any{originalUser}},
	} {
		if _, err = pool.Exec(ctx, change.sql, change.args...); err != nil {
			t.Fatal(err)
		}
		if _, err = s.rpc(ctx, pool, "offer", gin.H{"claim_id": claim.ID, "team_id": team, "user_id": user, "home_region": "use"}); err != nil {
			t.Fatal("original account lifecycle stranded preferred approval", err)
		}
		var financialState YCFinancialState
		if e = ycFinancialRPC(ctx, pool, "state", gin.H{"claim_id": claim.ID, "automated": true}, &financialState); e != nil || !financialState.valid() {
			t.Fatal("original A invalidated B permit", financialState, e)
		}
	}
	for _, change := range []struct {
		sql string
		id  uuid.UUID
	}{
		{`UPDATE auth.users SET deleted_at=now() WHERE id=$1`, user},
		{`UPDATE yc_claim SET state='revoked' WHERE id=$1`, claim.ID},
		{`UPDATE yc_company_activation_authority SET revoked_at=now(),revoked_by=approved_by,revision=revision+1 WHERE claim_id=$1`, claim.ID},
	} {
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, change.sql, change.id); e != nil {
			rollbackYCAcceptance(ctx, tx)
			t.Fatal(e)
		}
		_, e = s.rpc(ctx, tx, "offer", gin.H{"claim_id": claim.ID, "team_id": team, "user_id": user, "home_region": "use"})
		rollbackYCAcceptance(ctx, tx)
		if e == nil {
			t.Fatal("revoked preferred authority admitted", change.sql)
		}
	}
	if _, err = pool.Exec(ctx, `UPDATE auth.users SET email='changed@example.test' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if _, err = s.rpc(ctx, pool, "offer", gin.H{"claim_id": claim.ID, "team_id": team, "user_id": user, "home_region": "use"}); err == nil {
		t.Fatal("stale preferred identity accepted")
	}
}

func TestYCAcceptanceRejectsTemporaryAuthoritySubstitution(t *testing.T) {
	s, _, r, _, _ := acceptanceFixture(t)
	ctx := context.Background()
	tx, err := s.Shared.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackYCAcceptance(ctx, tx)
	for _, table := range []string{"yc_claim", "yc_company_activation_authority", "yc_preferred_identity_review", "yc_claim_decision"} {
		if _, err = tx.Exec(ctx, "CREATE TEMP TABLE "+table+" AS TABLE public."+table); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, "GRANT ALL ON pg_temp."+table+" TO promotion_evidence_proxy"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE public.yc_company_activation_authority SET revoked_at=now(),revoked_by=approved_by,revision=revision+1 WHERE claim_id=$1`, r.ClaimID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE promotion_evidence_proxy`); err != nil {
		t.Fatal(err)
	}
	_, err = s.rpc(ctx, tx, "offer", gin.H{"claim_id": r.ClaimID, "team_id": r.TeamID, "user_id": r.UserID, "home_region": "use"})
	if err == nil || !strings.Contains(err.Error(), "approval unavailable") {
		t.Fatal("temporary stale authority substituted for revoked global authority", err)
	}
}

func TestYCAcceptanceRejectsHistoricalTeam(t *testing.T) {
	s, _, r, _, _ := acceptanceFixture(t)
	ctx := context.Background()
	if _, err := s.Pool.Exec(ctx, `UPDATE team SET created_at=created_at-interval '1 day' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); !errors.Is(err, errYCAcceptanceConflict) {
		t.Fatal("historical team accepted", err)
	}
}

func TestYCAcceptanceLostProvisioningAcknowledgement(t *testing.T) {
	s, _, r, catalog, provider := acceptanceFixture(t)
	ctx := context.Background()
	if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); err != nil {
		t.Fatal(err)
	}
	provider.loseAcknowledgement = true
	if work, err := s.RunOnce(ctx); !work || err == nil {
		t.Fatal("lost operation response not surfaced", work, err)
	}
	first := provider.operation
	if _, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET next_attempt_at=now() WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if work, err := s.RunOnce(ctx); !work || err != nil {
		t.Fatal(work, err)
	}
	got, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
	if err != nil || got.OperationID == nil || *got.OperationID != first || provider.calls != 2 || catalog.calls != 1 {
		t.Fatal("operation retry changed durable identity", got, err)
	}
}

func TestYCAcceptanceAuditedHoldRetry(t *testing.T) {
	s, _, r, _, _ := acceptanceFixture(t)
	ctx := context.Background()
	actor := uuid.New()
	if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); err != nil {
		t.Fatal(err)
	}
	hold := ycAcceptanceControl{RequestID: uuid.New(), AcceptanceID: r.ID, Action: "hold", Reason: "Synthetic investigation"}
	if err := s.control(ctx, actor, hold); err != nil {
		t.Fatal(err)
	}
	if err := s.control(ctx, actor, hold); err != nil {
		t.Fatal("exact audited replay", err)
	}
	if err := s.control(ctx, uuid.New(), hold); err == nil {
		t.Fatal("actor changed on audit replay")
	}
	if work, err := s.RunOnce(ctx); work || err != nil {
		t.Fatal("held acceptance dispatched", work, err)
	}
	retry := ycAcceptanceControl{RequestID: uuid.New(), AcceptanceID: r.ID, Action: "retry", Reason: "Reviewed synthetic recovery"}
	if err := s.control(ctx, actor, retry); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET lease_id=$2,lease_until=now()+interval '1 minute' WHERE id=$1`, r.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	hold.RequestID = uuid.New()
	if err := s.control(ctx, actor, hold); err == nil {
		t.Fatal("control overtook active consumer")
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET lease_id=NULL,lease_until=NULL WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.control(ctx, actor, hold); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Shared.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, actor); err != nil {
		t.Fatal(err)
	}
	retry.RequestID = uuid.New()
	if err := s.control(ctx, actor, retry); err == nil {
		t.Fatal("retry overrode revoked authority")
	}
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM yc_offer_acceptance_control WHERE acceptance_id=$1`, r.ID).Scan(&n); err != nil || n != 3 {
		t.Fatal("audit did not preserve exactly committed actions", n, err)
	}
}

func TestYCAcceptanceDependenciesIgnoreTemporaryRelations(t *testing.T) {
	s, _, r, _, _ := acceptanceFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name, table, query string
		args               []any
		wantError          bool
		want               string
	}{
		{"legacy dispatch fence", "yc_claim", `SELECT public.lock_yc_activation_authority($1,$2,'use')::text`, []any{r.ApprovalID, r.TeamID}, false, "false"},
		{"nested reservation fence", "yc_claim", `SELECT to_jsonb(public.reserve_yc_activation_authority($1,$2,'use',$3,'operator','synthetic',$4))::text`, []any{r.Company, r.TeamID, uuid.New(), r.ClaimID}, true, "customer acceptance"},
		{"nested claim read", "yc_claim", `SELECT public.yc_preferred_staff_rpc('operator-get',jsonb_build_object('id',$1::uuid))->>'id'`, []any{r.ClaimID}, false, r.ClaimID.String()},
		{"nested staff fence", "yc_claim", `SELECT public.yc_preferred_staff_rpc('activation-allowed',jsonb_build_object('team_id',$1::uuid))->>'allowed'`, []any{r.TeamID}, false, "false"},
		{"nested claim view", "yc_claim_decision", `SELECT public.yc_preferred_staff_rpc('operator-get',jsonb_build_object('id',$1::uuid))->>'approval_method'`, []any{r.ClaimID}, false, "operator"},
		{"approval mail", "yc_claim_approval_mail", `SELECT public.yc_claim_approval_mail_rpc('lease',jsonb_build_object('lease_id',$1::uuid))->>'claim_id'`, []any{uuid.New()}, false, r.ClaimID.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := s.Shared.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackYCAcceptance(ctx, tx)
			if _, err = tx.Exec(ctx, "CREATE TEMP TABLE "+tc.table+" AS TABLE public."+tc.table+" WITH NO DATA"); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, "GRANT ALL ON pg_temp."+tc.table+" TO promotion_evidence_proxy; SET LOCAL ROLE promotion_evidence_proxy"); err != nil {
				t.Fatal(err)
			}
			var result *string
			err = tx.QueryRow(ctx, tc.query, tc.args...).Scan(&result)
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatal("temporary relation changed authority fence", result, err)
				}
			} else if err != nil || result == nil || *result != tc.want {
				t.Fatal("temporary relation changed authoritative result", result, err)
			}
		})
	}
}

func TestYCAcceptanceHTTPResumeAndReplayProjectPublicStatus(t *testing.T) {
	s, h, r, _, provider := acceptanceFixture(t)
	ctx := context.Background()
	h.YCOfferAcceptance = s
	role, permission := uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO roles VALUES($1,'team')`, []any{role}},
		{`INSERT INTO permissions VALUES($1,'billing:write')`, []any{permission}},
		{`INSERT INTO role_permissions VALUES($1,$2)`, []any{role, permission}},
		{`INSERT INTO user_role_assignments VALUES($1,$2,'team',$3,NULL)`, []any{r.UserID, role, r.TeamID}},
		{`INSERT INTO team_memberships VALUES($1,$2,'active')`, []any{r.TeamID, r.UserID}},
	} {
		if _, err := s.Pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	in := acceptanceRequest(r)
	if _, err := s.Accept(ctx, r.UserID, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	provider.status = YCAcceptanceProvisioningStatus{OperationID: provider.operation, State: "funding_pending"}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Signature boundary is covered separately; this fixture begins after it.
	router.Use(func(c *gin.Context) { c.Set("actor_id", r.UserID); c.Set("yc_acceptance_verified", true) })
	router.POST("/offer", h.YCOffer)
	router.POST("/accept", h.AcceptYCOffer)
	for _, path := range []string{"/offer", "/accept"} {
		raw, _ := json.Marshal(in)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(raw)))
		var got YCAcceptanceRecord
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 || got.State != "funding_pending" || got.Ready {
			t.Fatal("internal dispatch leaked into public resume", path, w.Code, w.Body.String(), err)
		}
	}
	// A permission already read by the UI cache cannot authorize new financial work.
	if _, err := h.ycClaimTeam(ctx, r.UserID, r.TeamID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE user_role_assignments SET revoked_at=now() WHERE user_id=$1`, r.UserID); err != nil {
		t.Fatal(err)
	}
	if err := h.authorizeYCAcceptance(ctx, r.UserID, r.TeamID); err == nil {
		t.Fatal("cached permission survived revocation")
	}
}

func TestYCAcceptancePendingHTTPRejectsChangedApproval(t *testing.T) {
	for _, confirming := range []bool{false, true} {
		t.Run(map[bool]string{false: "offered", true: "confirming"}[confirming], func(t *testing.T) {
			s, h, r, catalog, _ := acceptanceFixture(t)
			ctx := context.Background()
			h.YCOfferAcceptance = s
			role, permission := uuid.New(), uuid.New()
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO roles VALUES($1,'team')`, []any{role}},
				{`INSERT INTO permissions VALUES($1,'billing:write')`, []any{permission}},
				{`INSERT INTO role_permissions VALUES($1,$2)`, []any{role, permission}},
				{`INSERT INTO user_role_assignments VALUES($1,$2,'team',$3,NULL)`, []any{r.UserID, role, r.TeamID}},
				{`INSERT INTO team_memberships VALUES($1,$2,'active')`, []any{r.TeamID, r.UserID}},
			} {
				if _, err := s.Pool.Exec(ctx, q.sql, q.args...); err != nil {
					t.Fatal(err)
				}
			}
			if confirming {
				if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.Status(ctx, r.UserID, r.TeamID, r.ClaimID)
			if err != nil || before.State != map[bool]string{false: "offered", true: "confirming"}[confirming] {
				t.Fatal("unchanged pending approval rejected", before.State, err)
			}
			if _, err := s.Shared.Exec(ctx, `INSERT INTO public.yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference) VALUES($1,100,'operator',gen_random_uuid(),'review','synthetic')`, r.ClaimID); err != nil {
				t.Fatal(err)
			}
			requireFinancialState(t, s, r, "acceptance_pending", 0)
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(func(c *gin.Context) { c.Set("actor_id", r.UserID); c.Set("yc_acceptance_verified", true) })
			router.POST("/offer", h.YCOffer)
			router.POST("/status", h.YCOfferStatus)
			for _, path := range []string{"/offer", "/status"} {
				raw, _ := json.Marshal(acceptanceRequest(r))
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(raw)))
				if w.Code != 409 || !strings.Contains(w.Body.String(), "acceptance_conflict") {
					t.Fatal("stale approval still offered", path, w.Code, w.Body.String())
				}
			}
			stored, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
			if err != nil || !stored.YCAcceptanceAuthority.equal(r.YCAcceptanceAuthority) || stored.TermsDigest != r.TermsDigest || stored.RenewalTermsDigest != r.RenewalTermsDigest || !stored.PricingAt.Equal(r.PricingAt) || catalog.calls != 0 {
				t.Fatal("status changed frozen disclosure", stored, catalog.calls, err)
			}
		})
	}
}

func TestYCAcceptanceExpiredFinalLeaseBecomesRecoverableHold(t *testing.T) {
	s, _, r, _, _ := acceptanceFixture(t)
	ctx := context.Background()
	if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET attempts=8,lease_id=$2,lease_until=now()-interval '1 second' WHERE id=$1`, r.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if work, err := s.RunOnce(ctx); !work || err != nil {
		t.Fatal(work, err)
	}
	current, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
	if err != nil || current.State != "held" {
		t.Fatal("exhausted lease stranded", current, err)
	}
	if err = s.control(ctx, uuid.New(), ycAcceptanceControl{RequestID: uuid.New(), AcceptanceID: r.ID, Action: "retry", Reason: "Reviewed expired lease"}); err != nil {
		t.Fatal("held item not recoverable", err)
	}
}
