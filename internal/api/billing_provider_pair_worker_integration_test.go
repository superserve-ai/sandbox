//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Only the authority adapter and provider boundary are fixtures here. The full
// committed shared-authority/fence composition is exercised in integration.
type pairWorkerAuthority struct {
	h       *Handlers
	invalid atomic.Bool
	calls   int
	before  func(int)
}

func (a *pairWorkerAuthority) WithProviderPairAuthority(ctx context.Context, b ContractProviderBinding, action func(context.Context, pgx.Tx) error) error {
	a.calls++
	if a.before != nil {
		a.before(a.calls)
	}
	if a.invalid.Load() {
		return errors.New("current authority invalid")
	}
	tx, err := a.h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = lockCommercialOfferAccount(ctx, tx, b.Identity.TeamID); err != nil {
		return err
	}
	if err = action(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type pairWorkerFixture struct {
	h           *Handlers
	b           ContractProviderBinding
	authority   *pairWorkerAuthority
	posts       atomic.Int32
	lost        atomic.Bool
	debt        atomic.Bool
	debtAtCheck atomic.Int32
	debtChecks  atomic.Int32
	grant       *entitlementGrant
	requests    atomic.Int32
}

func newPairWorkerFixture(t *testing.T, anchors ...time.Time) *pairWorkerFixture {
	t.Helper()
	h, team := fundingTransitionFixture(t)
	h.Config = &config.Config{BillingUsageEntitlementsEnabled: true}
	f := newPairFixture(t)
	f.p.Identity.TeamID = team
	f.fee.Metadata, f.usage.Metadata = pairMetadata(f.p.Identity, "fee"), pairMetadata(f.p.Identity, "usage")
	anchor := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if len(anchors) > 0 {
		anchor = anchors[0]
	}
	movePairFixture(f, anchor)
	for i := range f.p.Terms.Resources {
		f.p.Terms.Resources[i].UnitAmountDecimal = "3.6"
		f.usage.Items.Data[i].Price.UnitAmountDecimal = "3.6"
	}
	f.p.Identity.ProviderTermsDigest, _ = f.p.Terms.Digest()
	client := f.client(t)
	h.Stripe = client
	proof, err := client.verifyInitialProviderPair(t.Context(), f.p)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(t.Context(), sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE team SET home_region='use' WHERE id=$1`, team)
	exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_commercial_offer_assignments_enabled',true),($1,'billing_export_enabled',true)`, team)
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor) VALUES($1,$2,$3,'active',$4)`, team, f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Anchor)
	rates := []map[string]string{}
	for _, resource := range f.p.Terms.Resources {
		rates = append(rates, map[string]string{"resource": resource.ResourceKey, "plan_key": "payg", "currency": "USD", "unit": "second", "price_usd": "0.00001"})
	}
	raw, _ := json.Marshal(rates)
	exec(`INSERT INTO billing_commercial_offer_assignment(id,team_id,approval_id,company_identity,home_region,offer_key,offer_version,idempotency_key,rate_card_key,rate_ids,pricing_at,resource_rates,request,assigned_by,reason,reference) VALUES($1,$2,$3,'example-company','use','yc_2026',1,'initial','payg',$4,clock_timestamp(),$5,'{}',$6,'fixture','fixture')`, f.p.Identity.AssignmentID, team, uuid.New(), []uuid.UUID{uuid.New()}, raw, uuid.New())
	b, err := ActivateInitialProviderPair(t.Context(), tx, f.p.Identity.OperationID, proof)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, team, f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Terms.Rounding.PriceID, f.p.Terms.Rounding.EventName, f.p.Terms.Rounding.MeterID, f.p.Anchor)
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	wf := &pairWorkerFixture{h: h, b: b}
	wf.authority = &pairWorkerAuthority{h: h}
	h.ProviderPairEntitlementAuthority = wf.authority
	configurePairWorkerProvider(t, wf, f)
	return wf
}
func (f *pairWorkerFixture) revoke(t *testing.T) {
	t.Helper()
	f.authority.invalid.Store(true)
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if err = RevokeProviderPairAuthority(t.Context(), tx, f.b.ContractID, f.b.Identity); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}
func TestProviderPairWorkerRefreshAndRecovery(t *testing.T) {
	for _, mode := range []string{"refresh", "revoke_before_dispatch", "revoke_after_intent", "invalid_shared", "adapter_missing", "recover_after_revoke"} {
		t.Run(mode, func(t *testing.T) {
			f := newPairWorkerFixture(t)
			// A stale seed cannot authorize work; renewal must come from current durable
			// shared authority under the finalized regional fence, not elapsed TTL.
			if _, err := f.h.Pool.Exec(t.Context(), `ALTER TABLE billing_provider_pair_waiver DISABLE TRIGGER billing_provider_pair_waiver_guard`); err != nil {
				t.Fatal(err)
			}
			_, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_provider_pair_waiver SET authority_checked_at=clock_timestamp()-interval '2 minutes',authority_valid_until=clock_timestamp()-interval '90 seconds' WHERE contract_id=$1`, f.b.ContractID)
			_, enableErr := f.h.Pool.Exec(t.Context(), `ALTER TABLE billing_provider_pair_waiver ENABLE TRIGGER billing_provider_pair_waiver_guard`)
			if err != nil || enableErr != nil {
				t.Fatal(err, enableErr)
			}
			if mode == "revoke_before_dispatch" {
				f.revoke(t)
			}
			if mode == "revoke_after_intent" {
				f.authority.before = func(call int) {
					if call == 3 {
						f.revoke(t)
					}
				}
			}
			if mode == "invalid_shared" {
				f.authority.invalid.Store(true)
			}
			if mode == "adapter_missing" {
				f.h.ProviderPairEntitlementAuthority = nil
			}
			if mode == "recover_after_revoke" {
				f.lost.Store(true)
			}
			_, err = f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID)
			if mode == "revoke_before_dispatch" || mode == "revoke_after_intent" || mode == "invalid_shared" || mode == "adapter_missing" {
				if (mode != "revoke_before_dispatch" && err == nil) || f.posts.Load() != 0 {
					t.Fatal("revoked authority dispatched", err)
				}
				return
			}
			if mode == "recover_after_revoke" {
				if err == nil {
					t.Fatal("missing lost response")
				}
				f.revoke(t)
				_, err = f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID)
			}
			if err != nil {
				t.Fatal(err)
			}
			e, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.b.Identity.TeamID, Kind: "metered_usage"})
			if err != nil || e.State != "issued" || !e.PairedWaiverID.Valid || e.AmountCents != 3000000 || f.posts.Load() != 1 {
				t.Fatalf("initial paired grant: %+v posts%d %v", e, f.posts.Load(), err)
			}
			var legacy int
			var ends, valid time.Time
			if err = f.h.Pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM billing_yc_operation WHERE team_id=$1),ends_at,authority_valid_until FROM billing_provider_pair_waiver WHERE contract_id=$2`, f.b.Identity.TeamID, f.b.ContractID).Scan(&legacy, &ends, &valid); err != nil || legacy != 0 || !ends.Equal(*f.b.EndsAt) {
				t.Fatal("legacy rows or extended term", err)
			}
			if mode == "refresh" && !valid.After(time.Now()) {
				t.Fatal("waiver freshness did not refresh")
			}
		})
	}
}

func TestProviderPairRevokedPendingWorkIsNotPlatformFailure(t *testing.T) {
	f := newPairWorkerFixture(t, time.Now().UTC().AddDate(0, -1, 0).Add(10*time.Minute).Truncate(time.Second))
	start, end := f.b.Anchor, annualBoundary(f.b.Anchor, 1)
	_, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_commercial_contract SET collection_has_overdue_balance=false,collection_checked_at=clock_timestamp(),collection_valid_until=clock_timestamp()+interval '1 minute',collection_evidence=jsonb_build_object('gate','finalized_invoice_gate_v1','period_start',$2::timestamptz,'period_end',$3::timestamptz),revision=revision+1 WHERE id=$1`, f.b.ContractID, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.DB.ClaimCurrentUsageEntitlement(t.Context(), db.ClaimCurrentUsageEntitlementParams{TeamID: f.b.Identity.TeamID, ContractID: f.b.ContractID}); err != nil {
		t.Fatal(err)
	}
	f.revoke(t)
	token := uuid.New()
	_, err = f.h.Pool.Exec(t.Context(), `INSERT INTO billing_entitlement_work(contract_id,lease_token,lease_until,problem_since,failures) VALUES($1,$2,clock_timestamp()+interval '1 minute',clock_timestamp()-interval '10 minutes',5) ON CONFLICT(contract_id) DO UPDATE SET lease_token=$2,lease_until=clock_timestamp()+interval '1 minute',problem_since=clock_timestamp()-interval '10 minutes',failures=5`, f.b.ContractID, token)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.h.processEntitlementJob(t.Context(), entitlementJob{Contract: f.b.ContractID, Token: token}); err != nil {
		t.Fatal(err)
	}
	var failures int
	if err = f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_entitlement_withheld WHERE contract_id=$1 AND platform_failure_at IS NOT NULL`, f.b.ContractID).Scan(&failures); err != nil || failures != 0 || f.posts.Load() != 0 {
		t.Fatal("revocation fabricated platform delivery failure", failures, err)
	}
	plan := billing.InvoiceClosePlan{InvoiceEnd: end.Unix()}
	if err = f.h.prepareInvoiceCredits(t.Context(), billing.ExportPeriod{TeamID: f.b.Identity.TeamID, Start: start, End: end}, invoiceAccount{Customer: f.b.CustomerID, Subscription: f.b.UsageSubscriptionID, Price: f.b.Terms.Rounding.PriceID, Pair: &f.b}, "in_closing", &plan, f.h.Stripe.(*stripeHTTPClient)); err != nil {
		t.Fatal("revoked pending allowance blocked invoice closure", err)
	}
}

func TestProviderPairRevocationKeepsUncertainInvoiceBlocked(t *testing.T) {
	f := newPairWorkerFixture(t)
	f.lost.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); err == nil {
		t.Fatal("expected lost grant response")
	}
	f.revoke(t)
	start, end := f.b.Anchor, annualBoundary(f.b.Anchor, 1)
	plan := billing.InvoiceClosePlan{InvoiceEnd: end.Unix()}
	err := f.h.prepareInvoiceCredits(t.Context(), billing.ExportPeriod{TeamID: f.b.Identity.TeamID, Start: start, End: end}, invoiceAccount{Customer: f.b.CustomerID, Subscription: f.b.UsageSubscriptionID, Price: f.b.Terms.Rounding.PriceID, Pair: &f.b}, "in_closing", &plan, f.h.Stripe.(*stripeHTTPClient))
	if err == nil || !strings.Contains(err.Error(), "unresolved") {
		t.Fatal("revocation hid uncertain grant during invoice closure", err)
	}
}

func configurePairWorkerProvider(t *testing.T, wf *pairWorkerFixture, f *pairFixture) {
	f.serve = func(w http.ResponseWriter, req *http.Request) bool {
		wf.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/v1/invoices" && req.URL.Query().Get("status") == "open" && req.URL.Query().Get("limit") == "1" {
			check := wf.debtChecks.Add(1)
			if wf.debt.Load() || (wf.debtAtCheck.Load() > 0 && check >= wf.debtAtCheck.Load()) {
				json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]string{"id": "in_unpaid", "customer": f.p.CustomerID, "status": "open"}}})
				return true
			}
		}
		if req.URL.Path == "/v1/invoices" || req.URL.Path == "/v1/billing/credit_balance_transactions" {
			fmt.Fprint(w, `{"data":[]}`)
			return true
		}
		if req.URL.Path == "/v1/billing/credit_grants" {
			if req.Method == http.MethodGet {
				list := []any{}
				if wf.grant != nil {
					list = append(list, wf.grant)
				}
				json.NewEncoder(w).Encode(map[string]any{"data": list})
				return true
			}
			wf.posts.Add(1)
			_ = req.ParseForm()
			g := testEntitlementGrant()
			g.ID = "credgr_" + uuid.NewString()
			g.Customer = f.p.CustomerID
			g.Created = time.Now().Unix()
			g.EffectiveAt = g.Created
			g.Amount.Monetary.Value, _ = strconv.ParseInt(req.Form.Get("amount[monetary][value]"), 10, 64)
			g.ExpiresAt, _ = strconv.ParseInt(req.Form.Get("expires_at"), 10, 64)
			g.Metadata = map[string]string{"entitlement_id": req.Form.Get("metadata[entitlement_id]")}
			for i := range g.Applicability.Scope.Prices {
				g.Applicability.Scope.Prices[i].ID = req.Form.Get(fmt.Sprintf("applicability_config[scope][prices][%d][id]", i))
			}
			wf.grant = &g
			if wf.lost.Swap(false) {
				http.Error(w, "lost response", 503)
			} else {
				json.NewEncoder(w).Encode(g)
			}
			return true
		}
		if strings.HasPrefix(req.URL.Path, "/v1/billing/credit_grants/") {
			json.NewEncoder(w).Encode(wf.grant)
			return true
		}
		return false
	}
	wf.h.Stripe = f.client(t)
}

func TestProviderPairWorkerMonthlyMappedCashRefresh(t *testing.T) {
	for _, corrected := range []bool{false, true} {
		t.Run(fmt.Sprint(corrected), func(t *testing.T) {
			tx, b, f, h := monthlyPairMappingFixture(t, time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC))
			start, end, _ := billing.AnniversaryPeriod(b.Anchor, time.Now())
			offset := (start.Year()-b.FeeAnchor.Year())*12 + int(start.Month()-b.FeeAnchor.Month())
			payment := recordMonthlyPairCash(t, tx, b, f, offset)
			if _, err := ConfirmProviderPairMonthlyPayment(t.Context(), tx, b.ContractID, b.Identity, payment.ID); err != nil {
				t.Fatal(err)
			}
			for _, stmt := range []struct {
				sql  string
				args []any
			}{
				{`UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1`, []any{b.ContractID}},
				{`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`, []any{b.Identity.TeamID}},
				{`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{b.Identity.TeamID, b.CustomerID, b.UsageSubscriptionID, b.Terms.Rounding.PriceID, b.Terms.Rounding.EventName, b.Terms.Rounding.MeterID, start}},
				{`UPDATE billing_pro_payment_verification SET review_required=true WHERE invoice_id=$1`, []any{payment.InvoiceID}},
			} {
				if _, err := tx.Exec(t.Context(), stmt.sql, stmt.args...); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			h.Config = &config.Config{BillingUsageEntitlementsEnabled: true}
			wf := &pairWorkerFixture{h: h, b: b, authority: &pairWorkerAuthority{h: h}}
			h.ProviderPairEntitlementAuthority = wf.authority
			configurePairWorkerProvider(t, wf, f)
			if corrected {
				f.invoice.Lines.Data[0].Period.Start = annualBoundary(b.FeeAnchor, offset+1).Unix()
				f.invoice.Lines.Data[0].Period.End = annualBoundary(b.FeeAnchor, offset+2).Unix()
			}
			_, err := h.reconcileUsageEntitlement(t.Context(), b.ContractID)
			if corrected {
				if err == nil || wf.posts.Load() != 0 {
					t.Fatal("corrected receipt reused old allowance authority", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			e, err := h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: b.Identity.TeamID, Kind: "metered_usage"})
			if err != nil || e.State != "issued" || e.AmountCents != 100000 || !e.PeriodEnd.Equal(end) || wf.posts.Load() != 1 {
				t.Fatal("mapped monthly worker failed", e, err)
			}
			counter := countPairWorkerQueries(t, h)
			wf.requests.Store(0)
			began := time.Now()
			next, err := h.reconcileUsageEntitlement(t.Context(), b.ContractID)
			t.Logf("paid issued refresh: provider_requests=%d regional_statements=%d duration=%s", wf.requests.Load(), counter.calls.Load(), time.Since(began))
			if err != nil || wf.posts.Load() != 1 || next.After(time.Now().Add(21*time.Second)) {
				t.Fatal("mapped paid refresh lost bounded single grant", next, err)
			}
		})
	}
}

func TestProviderPairIssuedGrantRefreshesExpiredObservations(t *testing.T) {
	f := newPairWorkerFixture(t)
	ctx := t.Context()
	run := func(wantError bool) time.Time {
		t.Helper()
		token := uuid.New()
		if _, err := f.h.Pool.Exec(ctx, `UPDATE billing_entitlement_work SET lease_token=$2,lease_until=clock_timestamp()+interval '1 minute' WHERE contract_id=$1`, f.b.ContractID, token); err != nil {
			t.Fatal(err)
		}
		err := f.h.processEntitlementJob(ctx, entitlementJob{Contract: f.b.ContractID, Token: token})
		if (err != nil) != wantError {
			t.Fatal("worker error", err)
		}
		var next time.Time
		if err = f.h.Pool.QueryRow(ctx, `SELECT next_check_at FROM billing_entitlement_work WHERE contract_id=$1 AND lease_token IS NULL`, f.b.ContractID).Scan(&next); err != nil {
			t.Fatal(err)
		}
		return next
	}
	next := run(false)
	if next.After(time.Now().Add(21 * time.Second)) {
		t.Fatal("issued grant did not schedule bounded refresh", next)
	}
	var expires time.Time
	if err := f.h.Pool.QueryRow(ctx, `SELECT greatest(w.authority_valid_until,c.collection_valid_until) FROM billing_provider_pair_waiver w JOIN billing_commercial_contract c ON c.id=w.contract_id WHERE c.id=$1`, f.b.ContractID).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	// A deliberately late worker must fail closed until it refreshes real expired observations.
	if wait := time.Until(expires.Add(20 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	eligible := func() bool {
		t.Helper()
		var valid bool
		if err := f.h.Pool.QueryRow(ctx, `SELECT billing_contract_eligible(c,e.period_start,e.period_end) FROM billing_commercial_contract c JOIN billing_usage_entitlement e ON e.contract_id=c.id WHERE c.id=$1`, f.b.ContractID).Scan(&valid); err != nil {
			t.Fatal(err)
		}
		return valid
	}
	if eligible() {
		t.Fatal("late scheduler retained expired authority")
	}
	checkExpirySample := func(expired bool) {
		t.Helper()
		rows, err := f.h.entitlementCoveragePage(ctx, uuid.Nil, time.Now(), 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.Contract == f.b.ContractID {
				if (row.PairExpiryAge > 0) != expired {
					t.Fatal("paired refresh monitor lost actual proof expiry", row)
				}
				return
			}
		}
		t.Fatal("paired contract missing from bounded coverage sample")
	}
	checkExpirySample(true)
	counter := countPairWorkerQueries(t, f.h)
	for range 2 {
		counter.calls.Store(0)
		f.requests.Store(0)
		began := time.Now()
		next = run(false)
		t.Logf("issued refresh: provider_requests=%d regional_statements=%d duration=%s", f.requests.Load(), counter.calls.Load(), time.Since(began))
		if next.After(time.Now().Add(21*time.Second)) || !eligible() || f.posts.Load() != 1 {
			t.Fatal("issued grant refresh duplicated issuance or stalled", next, f.posts.Load())
		}
		checkExpirySample(false)
	}
	f.debt.Store(true)
	next = run(false)
	if eligible() || next.After(time.Now().Add(21*time.Second)) || f.posts.Load() != 1 {
		t.Fatal("new debt retained positive authorization", next)
	}
	f.debt.Store(false)
	run(false)
	if !eligible() {
		t.Fatal("settled debt did not recover fresh observation")
	}
	f.authority.invalid.Store(true)
	f.debt.Store(true)
	run(false)
	if eligible() || f.posts.Load() != 1 {
		t.Fatal("authority failure hid newly observed debt")
	}
	f.debt.Store(false)
	next = run(true)
	if next.After(time.Now().Add(11*time.Second)) || next.Before(time.Now()) || f.posts.Load() != 1 {
		t.Fatal("authority failure lost bounded retry", next)
	}
	f.revoke(t)
	run(false)
	e, err := f.h.DB.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: f.b.Identity.TeamID, Kind: "metered_usage"})
	if err != nil || eligible() || e.State != "issued" || f.posts.Load() != 1 {
		t.Fatal("revocation lost grant history or retained new authority", err)
	}
}

func TestProviderPairFinalDebtObservationDeniesGrant(t *testing.T) {
	f := newPairWorkerFixture(t)
	f.debtAtCheck.Store(2)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); err != nil {
		t.Fatal(err)
	}
	var overdue bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT collection_has_overdue_balance FROM billing_commercial_contract WHERE id=$1`, f.b.ContractID).Scan(&overdue); err != nil || !overdue || f.posts.Load() != 0 {
		t.Fatal("final debt observation retained clean evidence", overdue, err)
	}
}

type pairWorkerQueryCounter struct {
	calls      atomic.Int32
	mu         sync.Mutex
	statements []string
}

func (c *pairWorkerQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	c.calls.Add(1)
	c.mu.Lock()
	c.statements = append(c.statements, data.SQL)
	c.mu.Unlock()
	return ctx
}
func (*pairWorkerQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func countPairWorkerQueries(t *testing.T, h *Handlers) *pairWorkerQueryCounter {
	t.Helper()
	counter := &pairWorkerQueryCounter{}
	cfg := h.Pool.Config()
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h.Pool = pool
	h.DB = db.New(pool)
	return counter
}
