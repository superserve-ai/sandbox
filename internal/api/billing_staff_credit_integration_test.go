//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type staffCreditStripe struct {
	t        *testing.T
	mu       sync.Mutex
	customer string
	grants   []entitlementGrant
	creates  int
	keys     []string
	lose     bool
	tamper   bool
}

func (s *staffCreditStripe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && r.URL.Path == "/v1/billing/credit_balance_summary" {
		for _, grant := range s.grants {
			if grant.ID == r.URL.Query().Get("filter[credit_grant]") {
				_ = json.NewEncoder(w).Encode(map[string]any{"balances": []any{map[string]any{"ledger_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": grant.Amount.Monetary.Value}}}}})
				return
			}
		}
		s.t.Error("balance requested for unknown grant")
		http.Error(w, "unknown grant", 500)
		return
	}
	if r.URL.Path != "/v1/billing/credit_grants" {
		s.t.Errorf("unexpected provider request %s %s", r.Method, r.URL)
		http.Error(w, "unexpected", 500)
		return
	}
	if r.Method == http.MethodGet {
		if r.URL.Query().Get("customer") != s.customer {
			s.t.Errorf("grant inventory read for another customer")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": s.grants, "has_more": false})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.t.Error(err)
	}
	s.creates++
	s.keys = append(s.keys, r.Header.Get("Idempotency-Key"))
	var g entitlementGrant
	g.ID = fmt.Sprintf("credgr_staff_%d_%s", s.creates, uuid.NewString())
	g.Customer = r.PostForm.Get("customer")
	g.EffectiveAt = time.Now().Unix()
	g.Created = g.EffectiveAt
	g.Category = r.PostForm.Get("category")
	g.Amount.Type = r.PostForm.Get("amount[type]")
	g.Amount.Monetary.Currency = r.PostForm.Get("amount[monetary][currency]")
	fmt.Sscan(r.PostForm.Get("amount[monetary][value]"), &g.Amount.Monetary.Value)
	fmt.Sscan(r.PostForm.Get("priority"), &g.Priority)
	fmt.Sscan(r.PostForm.Get("expires_at"), &g.ExpiresAt)
	g.Applicability.Scope.PriceType = r.PostForm.Get("applicability_config[scope][price_type]")
	g.Metadata = map[string]string{"staff_credit_grant": r.PostForm.Get("metadata[staff_credit_grant]")}
	if s.tamper {
		g.Amount.Monetary.Value++
	}
	s.grants = append(s.grants, g)
	if s.lose {
		s.lose = false
		http.Error(w, `{"error":{"message":"response lost"}}`, 503)
		return
	}
	_ = json.NewEncoder(w).Encode(g)
}

func newStaffCreditFixture(t *testing.T, withCustomer bool) (*Handlers, uuid.UUID, *staffCreditStripe) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("DATABASE_URL must name a migrated disposable test database")
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := &Handlers{Pool: pool, DB: db.New(pool)}
	team, err := h.DB.CreateTeam(t.Context(), "staff-credit-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	s := &staffCreditStripe{t: t, customer: "cus_" + uuid.NewString()}
	if withCustomer {
		if _, err = pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, team.ID, s.customer); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	h.Stripe = &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}
	return h, team.ID, s
}

func TestStaffCreditGrantIssuesOnce(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	actor := uuid.New()
	req := staffCreditRequest{Key: "goodwill-1", AmountCents: 25000, Reason: "Usage billed during an outage"}
	credit, err := h.grantStaffCredit(t.Context(), team, actor, req)
	if err != nil || credit.State != "issued" || credit.GrantID == nil || credit.RequestedBy != actor {
		t.Fatalf("credit not issued: %+v %v", credit, err)
	}
	g := s.grants[0]
	if g.Amount.Monetary.Value != 25000 || g.Applicability.Scope.PriceType != "metered" || g.Priority != 50 || g.ExpiresAt != 0 || g.Category != "promotional" {
		t.Fatalf("grant is not a metered-only credit with the requested terms: %+v", g)
	}
	if err = creditScope(g, s.customer, time.Now().Unix(), nil); err != nil {
		t.Fatalf("invoice reconciliation would not recognize the grant: %v", err)
	}
	again, err := h.grantStaffCredit(t.Context(), team, actor, req)
	if err != nil || again.ID != credit.ID || s.creates != 1 {
		t.Fatalf("repeated request granted again: %d creates %v", s.creates, err)
	}
	other := req
	other.AmountCents = 30000
	if _, err = h.grantStaffCredit(t.Context(), team, actor, other); !errors.Is(err, errStaffCreditConflict) {
		t.Fatalf("idempotency key reused for a different amount: %v", err)
	}
	other = req
	other.Reason = "A different reason"
	if _, err = h.grantStaffCredit(t.Context(), team, actor, other); !errors.Is(err, errStaffCreditConflict) {
		t.Fatalf("idempotency key reused for a different reason: %v", err)
	}
	if _, err = h.Pool.Exec(t.Context(), `UPDATE billing_staff_credit_grant SET amount_cents=1 WHERE id=$1`, credit.ID); err == nil {
		t.Fatal("issued credit was edited")
	}
}

func TestStaffCreditGrantAdoptsLostResponse(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	s.lose = true
	req := staffCreditRequest{Key: "goodwill-2", AmountCents: 5000, Reason: "Correction"}
	credit, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req)
	if err == nil || credit.State != "pending" {
		t.Fatalf("lost response treated as issued: %+v %v", credit, err)
	}
	credit, err = h.grantStaffCredit(t.Context(), team, uuid.New(), req)
	if err != nil || credit.State != "issued" || s.creates != 1 || *credit.GrantID != s.grants[0].ID {
		t.Fatalf("retry did not adopt the existing grant: creates=%d %+v %v", s.creates, credit, err)
	}
}

func TestStaffCreditGrantRejectsMismatchedProviderGrant(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	s.tamper = true
	credit, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "k", AmountCents: 100, Reason: "r"})
	if !errors.Is(err, errStaffCreditReview) || credit.State != "pending" {
		t.Fatalf("mismatched grant recorded as issued: %+v %v", credit, err)
	}
	s.mu.Lock()
	s.tamper = false
	s.grants[0].Amount.Monetary.Value = 100
	s.grants[0].VoidedAt = time.Now().Unix()
	s.mu.Unlock()
	if credit, err = h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "k", AmountCents: 100, Reason: "r"}); !errors.Is(err, errStaffCreditReview) || s.creates != 1 {
		t.Fatalf("a voided grant was replaced by a second grant: creates=%d %v", s.creates, err)
	}
}

func expireStaffCreditAttempts(t *testing.T, h *Handlers, team uuid.UUID) {
	t.Helper()
	conn, err := h.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(t.Context(), `RESET session_replication_role`)
	if _, err = conn.Exec(t.Context(), `UPDATE billing_staff_credit_grant SET attempted_at=attempted_at-interval '10 minutes' WHERE team_id=$1`, team); err != nil {
		t.Fatal(err)
	}
}

func TestStaffCreditGrantFollowsCurrentCustomer(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	s.lose = true
	req := staffCreditRequest{Key: "k", AmountCents: 100, Reason: "r"}
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req); err == nil {
		t.Fatal("lost response treated as issued")
	}
	replacement := "cus_replacement_" + uuid.NewString()
	if _, err := h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team, replacement); err == nil {
		t.Fatal("billing customer replaced while a staff credit attempt could still reach Stripe")
	}
	expireStaffCreditAttempts(t, h, team)
	if _, err := h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team, replacement); err != nil {
		t.Fatal(err)
	}
	credit, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req)
	if err != nil || credit.State != "issued" || s.creates != 1 {
		t.Fatalf("grant already created for the previous customer was not recorded: creates=%d %+v %v", s.creates, credit, err)
	}
	s.mu.Lock()
	s.lose = true
	s.mu.Unlock()
	next := staffCreditRequest{Key: "k2", AmountCents: 100, Reason: "r"}
	if _, err = h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team, s.customer); err != nil {
		t.Fatal(err)
	}
	if _, err = h.grantStaffCredit(t.Context(), team, uuid.New(), next); err == nil {
		t.Fatal("lost response treated as issued")
	}
	s.mu.Lock()
	s.grants = s.grants[:1]
	s.mu.Unlock()
	expireStaffCreditAttempts(t, h, team)
	if _, err = h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err = h.grantStaffCredit(t.Context(), team, uuid.New(), next); !errors.Is(err, errStaffCreditConflict) || s.creates != 2 {
		t.Fatalf("pending credit issued to the previous customer: creates=%d %v", s.creates, err)
	}
}

func TestStaffCreditGrantWaitsForPeriodClose(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	end := time.Now().UTC().Add(-9 * 24 * time.Hour).Truncate(time.Second)
	anchor := time.Date(end.Year(), end.Month()-1, min(end.Day(), 28), end.Hour(), end.Minute(), end.Second(), 0, time.UTC)
	_, end, _ = billing.AnniversaryPeriod(anchor, anchor)
	enrollStaffCreditCalendar(t, h, team, s, anchor, anchor.AddDate(0, -1, 0))
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2::timestamptz-interval '1 month',$2,'open')`, team, end); err != nil {
		t.Fatal(err)
	}
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "k", AmountCents: 100, Reason: "r"}); !errors.Is(err, errStaffCreditConflict) || s.creates != 0 {
		t.Fatalf("credit granted while the previous invoice was closing: %v", err)
	}
	contract := uuid.New()
	func() {
		conn, err := h.Pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		if _, err = conn.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		defer conn.Exec(context.WithoutCancel(t.Context()), `RESET session_replication_role`)
		if _, err = conn.Exec(t.Context(), `INSERT INTO billing_commercial_contract(id,team_id,offer_key,status,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_anchor) VALUES($1,$2,'pro_monthly','ended',$3::timestamptz-interval '6 months',$3::timestamptz-interval '2 months',$4,'sub_ended','price_base',120000,1,100000,$3::timestamptz-interval '6 months')`, contract, team, end, s.customer); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "after-contract", AmountCents: 100, Reason: "r"}); !errors.Is(err, errStaffCreditConflict) || s.creates != 0 {
		t.Fatalf("a team back on the usage-only ledger after its contract ended was not held: %v", err)
	}
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "k2", AmountCents: 100, Reason: "r"}); !errors.Is(err, errStaffCreditConflict) || s.creates != 0 {
		t.Fatalf("credit granted while an old usage-ledger period was unreleased: %v", err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan,state) SELECT team_id,period_start,period_end,'in_staff_credit_'||team_id,'{}'::jsonb,'released' FROM team_billing_period WHERE team_id=$1`, team); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,clock_timestamp()-interval '1 day',clock_timestamp()+interval '2 minutes','open')`, team); err != nil {
		t.Fatal(err)
	}
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "ending", AmountCents: 100, Reason: "r"}); !errors.Is(err, errStaffCreditConflict) || s.creates != 0 {
		t.Fatalf("credit granted moments before the period it would land after ends: %v", err)
	}
	if _, err := h.Pool.Exec(t.Context(), `DELETE FROM team_billing_period WHERE team_id=$1 AND period_end>clock_timestamp()`, team); err != nil {
		t.Fatal(err)
	}
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "k2", AmountCents: 100, Reason: "r"}); err != nil || s.creates != 1 {
		t.Fatalf("credit could not resume after the old period was released: %v", err)
	}
}

func TestStaffCreditIsRecognizedByAllowanceChecks(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	credit, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "k", AmountCents: 100, Reason: "r"})
	if err != nil {
		t.Fatal(err)
	}
	staff, err := h.issuedStaffCredits(t.Context(), h.Pool, s.customer)
	if _, listed := staff[*credit.GrantID]; err != nil || !listed {
		t.Fatalf("issued staff credit not listed: %v %v", staff, err)
	}
	if err = h.Stripe.(*stripeHTTPClient).ycGrantPreflight(t.Context(), s.customer, "", "", staff); err != nil {
		t.Fatalf("staff credit blocks YC grant preflight: %v", err)
	}
	if err = h.Stripe.(*stripeHTTPClient).ycGrantPreflight(t.Context(), s.customer, "", "", nil); err == nil {
		t.Fatal("unknown live grant no longer conflicts with YC approval")
	}
}

func TestStaffCreditGrantRequiresCustomerAndStaff(t *testing.T) {
	h, team, _ := newStaffCreditFixture(t, false)
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "k", AmountCents: 100, Reason: "r"}); !errors.Is(err, errStaffCreditNoCustomer) {
		t.Fatalf("credit granted without a billing customer: %v", err)
	}
	for _, call := range []struct {
		handler func(*gin.Context)
		body    string
	}{{h.CreateStaffCreditGrant, `{"idempotency_key":"k","amount_cents":100,"reason":"r"}`}, {h.ListStaffCreditGrants, ``}} {
		for _, actor := range []struct {
			header string
			want   int
		}{{"", http.StatusUnauthorized}, {uuid.NewString(), http.StatusForbidden}} {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(call.body))
			if actor.header != "" {
				c.Request.Header.Set(internalActorHeader, actor.header)
			}
			c.Params = gin.Params{{Key: "team_id", Value: team.String()}}
			call.handler(c)
			if w.Code != actor.want {
				t.Fatalf("staff credit endpoint with actor %q: got %d want %d", actor.header, w.Code, actor.want)
			}
		}
	}
}

func TestStaffCreditGrantRejectsExpiry(t *testing.T) {
	if _, err := decodeStaffCreditRequest(strings.NewReader(`{"idempotency_key":"k","amount_cents":100,"reason":"r","expires_at":"2030-01-01T00:00:00Z"}`)); err == nil {
		t.Fatal("expiring credit request accepted")
	}
	if _, err := decodeStaffCreditRequest(strings.NewReader(`{"idempotency_key":"k","amount_cents":100,"reason":"r"}{"expires_at":"2030-01-01T00:00:00Z"}`)); err == nil {
		t.Fatal("trailing request accepted")
	}
	if _, err := decodeStaffCreditRequest(strings.NewReader(`{"idempotency_key":"k","amount_cents":100,"reason":"r"}`)); err != nil {
		t.Fatalf("valid credit request rejected: %v", err)
	}
	h, team, s := newStaffCreditFixture(t, true)
	tampered, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "ok", AmountCents: 100, Reason: "r"})
	if err != nil {
		t.Fatal(err)
	}
	staff, err := h.issuedStaffCredits(t.Context(), h.Pool, s.customer)
	if err != nil {
		t.Fatal(err)
	}
	g := s.grants[0]
	g.Metadata = map[string]string{"staff_credit_grant": uuid.NewString()}
	paid := s.grants[0]
	paid.Category = "paid"
	if isStaffCredit(g, staff) || isStaffCredit(paid, staff) || !isStaffCredit(s.grants[0], staff) || tampered.GrantID == nil {
		t.Fatal("staff credit recognition ignored the issued terms")
	}
}

func setPricingSwitch(t *testing.T, h *Handlers, version string) {
	t.Helper()
	ctx := context.WithoutCancel(t.Context())
	conn, err := h.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `SET session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(ctx, `RESET session_replication_role`)
	if _, err = conn.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version=$1`, version); err != nil {
		t.Fatal(err)
	}
}

func TestStaffCreditIgnoresPricingSwitch(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	var hasSwitch bool
	if err := h.Pool.QueryRow(t.Context(), `SELECT to_regclass('billing_pricing_switch') IS NOT NULL`).Scan(&hasSwitch); err != nil {
		t.Fatal(err)
	}
	if hasSwitch {
		var before string
		if err := h.Pool.QueryRow(t.Context(), `SELECT pricing_version FROM billing_pricing_switch`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { setPricingSwitch(t, h, before) })
		setPricingSwitch(t, h, "v2")
	}
	req := staffCreditRequest{Key: "issued-under-v2", AmountCents: 1500, Reason: "Top-up while pricing v2 was on"}
	credit, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req)
	if err != nil || credit.State != "issued" {
		t.Fatalf("credit not issued: %+v %v", credit, err)
	}
	if hasSwitch {
		setPricingSwitch(t, h, "legacy")
	}
	again, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req)
	if err != nil || again.ID != credit.ID || s.creates != 1 {
		t.Fatalf("replay after switch-off: %+v %d creates %v", again, s.creates, err)
	}
	staff, err := h.issuedStaffCredits(t.Context(), h.Pool, s.customer)
	if _, listed := staff[*credit.GrantID]; err != nil || !listed {
		t.Fatalf("credit issued before switch-off is no longer recognized: %v", err)
	}
	if err = creditScope(s.grants[0], s.customer, time.Now().Unix(), nil); err != nil {
		t.Fatalf("credit issued before switch-off is no longer spendable: %v", err)
	}
	if err = h.Stripe.(*stripeHTTPClient).ycGrantPreflight(t.Context(), s.customer, "", "", staff); err != nil {
		t.Fatalf("credit issued before switch-off blocks YC preflight: %v", err)
	}
	next, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "issued-after-switch-off", AmountCents: 500, Reason: "Top-up after switch-off"})
	if err != nil || next.State != "issued" || s.creates != 2 {
		t.Fatalf("staff credit refused with the switch off: %+v %v", next, err)
	}
}

func TestStaffCreditGrantWaitsForUnmeasuredPeriod(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	end := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	anchor := time.Date(end.Year(), end.Month()-1, min(end.Day(), 28), end.Hour(), end.Minute(), end.Second(), 0, time.UTC)
	_, end, _ = billing.AnniversaryPeriod(anchor, anchor)
	enrollStaffCreditCalendar(t, h, team, s, anchor, anchor.Add(time.Hour))
	req := staffCreditRequest{Key: "unmeasured", AmountCents: 100, Reason: "Correction"}
	credit, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req)
	if !errors.Is(err, errStaffCreditConflict) || s.creates != 0 {
		t.Fatalf("credit issued before delayed period was measured: state=%s creates=%d error=%v", credit.State, s.creates, err)
	}
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team, anchor, end); err != nil {
		t.Fatal(err)
	}
	period := billing.ExportPeriod{TeamID: team, Start: anchor, End: end}
	account, enrolled, err := h.invoiceAccountForPeriod(t.Context(), period)
	if err != nil || !enrolled {
		t.Fatalf("account unavailable: %v", err)
	}
	path, err := h.invoiceCreditPath(t.Context(), period, account, h.Pool)
	if err != nil || path != invoiceCreditsLedger {
		t.Fatalf("wrong delayed-period credit path: %v %v", path, err)
	}
	client := h.Stripe.(*stripeHTTPClient)
	if balance, err := client.invoiceCreditLedger(t.Context(), s.customer, end.Unix()); err != nil || balance != 0 {
		t.Fatalf("delayed invoice ledger blocked: balance=%d %v", balance, err)
	}
	if _, err = h.grantStaffCredit(t.Context(), team, uuid.New(), req); !errors.Is(err, errStaffCreditConflict) || s.creates != 0 {
		t.Fatalf("measured unreleased period was not protected: %v", err)
	}
	if _, err = h.Pool.Exec(t.Context(), `INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan,state) VALUES($1,$2,$3,$4,'{}'::jsonb,'released')`, team, anchor, end, "in_"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	issued, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req)
	if err != nil || issued.ID != credit.ID || issued.State != "issued" || s.creates != 1 {
		t.Fatalf("same request did not resume after release: creates=%d %+v %v", s.creates, issued, err)
	}
	if len(s.grants) != 1 || s.grants[0].EffectiveAt <= end.Unix() || s.grants[0].Amount.Monetary.Value != 100 {
		t.Fatal("provider did not model a newly effective positive grant")
	}
	if balance, err := client.invoiceCreditLedger(t.Context(), s.customer, time.Now().Unix()); err != nil || balance != 100 {
		t.Fatalf("new credit not usable for current usage: balance=%d %v", balance, err)
	}
	replay, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req)
	if err != nil || replay.ID != issued.ID || s.creates != 1 {
		t.Fatalf("retry created another grant: creates=%d %v", s.creates, err)
	}
}

func enrollStaffCreditCalendar(t *testing.T, h *Handlers, team uuid.UUID, s *staffCreditStripe, anchor, enrolled time.Time) {
	t.Helper()
	subscription := "sub_" + uuid.NewString()
	if _, err := h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET stripe_subscription_id=$2,stripe_subscription_status='active',commercial_billing_anchor=$3 WHERE team_id=$1`, team, subscription, anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','mtr_round',$4)`, team, s.customer, subscription, enrolled); err != nil {
		t.Fatal(err)
	}
}

func TestStaffCreditGrantProtectsUnmeasuredCalendarGap(t *testing.T) {
	h, team, s := newStaffCreditFixture(t, true)
	end := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	anchor := time.Date(end.Year(), end.Month()-2, min(end.Day(), 28), end.Hour(), end.Minute(), end.Second(), 0, time.UTC)
	_, middle, ok := billing.AnniversaryPeriod(anchor, anchor)
	if !ok {
		t.Fatal("missing calendar")
	}
	_, end, _ = billing.AnniversaryPeriod(anchor, middle)
	enrollStaffCreditCalendar(t, h, team, s, anchor, anchor.Add(time.Hour))
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team, middle, end); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan,state) VALUES($1,$2,$3,$4,'{}'::jsonb,'released')`, team, middle, end, "in_"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	req := staffCreditRequest{Key: "gap", AmountCents: 100, Reason: "Correction"}
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req); !errors.Is(err, errStaffCreditConflict) || s.creates != 0 {
		t.Fatalf("latest release hid an unmeasured older period: creates=%d error=%v", s.creates, err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, team, anchor, middle); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Pool.Exec(t.Context(), `INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan,state) VALUES($1,$2,$3,$4,'{}'::jsonb,'released')`, team, anchor, middle, "in_"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.grantStaffCredit(t.Context(), team, uuid.New(), req); err != nil || s.creates != 1 {
		t.Fatalf("credit did not resume after closing calendar gap: %v", err)
	}
}

func TestStaffCreditGrantRequiresEnrolledCalendar(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing_anchor=%t", missing), func(t *testing.T) {
			h, team, s := newStaffCreditFixture(t, true)
			anchor := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			enrollStaffCreditCalendar(t, h, team, s, anchor, anchor.Add(time.Minute))
			if missing {
				if _, err := h.Pool.Exec(t.Context(), `UPDATE team_billing_account SET commercial_billing_anchor=NULL WHERE team_id=$1`, team); err != nil {
					t.Fatal(err)
				}
			}
			credit, err := h.grantStaffCredit(t.Context(), team, uuid.New(), staffCreditRequest{Key: "calendar", AmountCents: 100, Reason: "Correction"})
			if missing {
				if !errors.Is(err, errStaffCreditConflict) || s.creates != 0 {
					t.Fatalf("missing enrolled calendar accepted: %v", err)
				}
			} else if err != nil || credit.State != "issued" || s.creates != 1 {
				t.Fatalf("fresh enrollment without ended periods rejected: %v", err)
			}
		})
	}
}
