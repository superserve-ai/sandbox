//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func currentPlanVersion(t *testing.T, family string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(), `SELECT id FROM billing_plan_version WHERE family=$1 AND pricing_version='legacy' AND state='published'`, family).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// publishPlanCopy publishes a new version of from's terms with the given
// overrides and returns its id.
func publishPlanCopy(t *testing.T, from uuid.UUID, set string, args ...any) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	err := testPool.QueryRow(ctx, `INSERT INTO billing_plan_version(family,version,`+catalogCopyColumns+`)
 SELECT family,(SELECT MAX(version)+1 FROM billing_plan_version x WHERE x.family=v.family),`+catalogCopyColumns+` FROM billing_plan_version v WHERE id=$1 RETURNING id`, from).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if set != "" {
		if _, err = testPool.Exec(ctx, `UPDATE billing_plan_version SET `+set+` WHERE id=$1`, append([]any{id}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,NULL)`, id); err != nil {
		t.Fatal(err)
	}
	return id
}

// setCatalogPlan publishes a family version for the test and restores the
// previous terms as a newer version afterwards.
func setCatalogPlan(t *testing.T, family, set string, args ...any) uuid.UUID {
	t.Helper()
	previous := currentPlanVersion(t, family)
	id := publishPlanCopy(t, previous, set, args...)
	t.Cleanup(func() { publishPlanCopy(t, previous, "") })
	return id
}

const catalogCopyColumns = `pricing_version,kind,public,display_name,price_label,tagline,features,sort_order,display_only,self_serve,monthly_fee_cents,annual_fee_cents,
 credit_schedule,matching_bps,cap_cents,allowance_period,allowance_on_exhausted,allowance_cents,allowance_compute_seconds,allowance_compute_vcpu,
 allowance_compute_memory_gib,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates`

// testFamily publishes a self-serve legacy subscription family of its own,
// sold at its configured Stripe price, and returns its offer key.
func testFamily(t *testing.T, monthlyCents, creditCents int64, sandboxes int32) string {
	t.Helper()
	family := "plan" + strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return 'a' + r - '0'
		}
		return r
	}, strings.ReplaceAll(uuid.NewString()[:8], "-", ""))
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(), `INSERT INTO billing_plan_version(family,version,kind,public,self_serve,display_name,monthly_fee_cents,credit_schedule,max_sandboxes)
		VALUES($1,1,'subscription',true,true,'Test plan',$2,$3::jsonb,$4) RETURNING id`, family, monthlyCents, monthlySchedule(creditCents), sandboxes).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `SELECT publish_billing_plan_version($1,NULL)`, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `SELECT retire_billing_plan_version(id,NULL) FROM billing_plan_version WHERE family=$1 AND state='published'`, family)
	})
	return family + "_monthly"
}

// sellFamily configures the fixture's Stripe price for a test family.
func sellFamily(f *proProviderFixture, offer string) {
	f.handlers.Config.StripePlanPriceIDs[offer] = "price_" + offer
}

func monthlySchedule(cents int64) string {
	return fmt.Sprintf(`[{"start_months":0,"repeat":null,"every_months":1,"amount_cents":%d,"expires_after_months":1}]`, cents)
}

func TestIntegration_PlanCatalogRejectsUnavailablePlan(t *testing.T) {
	offer := testFamily(t, 10000, 5000, 20)
	family := strings.TrimSuffix(offer, "_monthly")
	publishPlanCopy(t, currentPlanVersion(t, family), "self_serve=false")
	f, r, key := newProFixture(t, offer)
	sellFamily(f, offer)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(offer), 400, "invalid_offer")
}

func TestIntegration_PlanCatalogRetiredFamilyRejectsCheckout(t *testing.T) {
	previous := currentPlanVersion(t, "pro")
	if _, err := testPool.Exec(t.Context(), `SELECT retire_billing_plan_version($1,NULL)`, previous); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publishPlanCopy(t, previous, "") })
	var available bool
	if err := testPool.QueryRow(t.Context(), `SELECT bool_or(available) FROM billing_plan WHERE family='pro'`).Scan(&available); err != nil || available {
		t.Fatalf("retired family stays available to older binaries: %v %v", available, err)
	}
	_, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 400, "invalid_offer")
}

func TestIntegration_PlanCatalogPurchaseKeepsCheckoutTerms(t *testing.T) {
	offer := testFamily(t, 10000, 5000, 20)
	family := strings.TrimSuffix(offer, "_monthly")
	version := currentPlanVersion(t, family)
	f, r, key := newProFixture(t, offer)
	sellFamily(f, offer)
	f.amount = 10000
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	var frozen string
	if err := testPool.QueryRow(t.Context(), `SELECT request_payload->'PlanTerms'->>'VersionID' FROM billing_signup_choice WHERE team_id=$1`, f.team).Scan(&frozen); err != nil || frozen != version.String() {
		t.Fatalf("frozen version=%q err=%v want %s", frozen, err, version)
	}
	// A new version after checkout must not change the purchase in flight.
	publishPlanCopy(t, version, "self_serve=false,credit_schedule=$2::jsonb", monthlySchedule(7500))
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	f.status = "complete"
	f.paid = true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var amount, credit int64
	var sandboxes int32
	if err := testPool.QueryRow(t.Context(), `SELECT c.charge_amount_cents,c.entitlement_amount_cents,t.max_sandboxes FROM billing_commercial_contract c JOIN team t ON t.id=c.team_id
		WHERE c.team_id=$1 AND c.offer_key=$2 AND c.status='active'`, f.team, offer).Scan(&amount, &credit, &sandboxes); err != nil {
		t.Fatal(err)
	}
	if amount != 10000 || credit != 5000 || sandboxes != 20 {
		t.Fatalf("contract amount=%d credit=%d max_sandboxes=%d", amount, credit, sandboxes)
	}
}

func TestIntegration_PlanCatalogCreatesStripePriceForNewFee(t *testing.T) {
	version := setCatalogPlan(t, "pro", "monthly_fee_cents=150000")
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	creates, price := append([]string{}, f.priceCreates...), f.price
	f.mu.Unlock()
	if len(creates) != 1 || creates[0] != "plan-price-superserve_plan_"+version.String()+"_monthly" || price != "price_catalog_1" {
		t.Fatalf("price creates=%v price=%s", creates, price)
	}
	var base string
	var frozenAmount int64
	if err := testPool.QueryRow(t.Context(), `SELECT base_price_id,(request_payload->'PlanTerms'->>'Amount')::bigint FROM billing_signup_choice WHERE team_id=$1`, f.team).Scan(&base, &frozenAmount); err != nil || base != price || frozenAmount != 150000 {
		t.Fatalf("base=%s amount=%d err=%v", base, frozenAmount, err)
	}
	f.mu.Lock()
	f.status = "complete"
	f.paid = true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var amount int64
	var contractPrice string
	if err := testPool.QueryRow(t.Context(), `SELECT charge_amount_cents,base_price_id FROM billing_commercial_contract WHERE team_id=$1 AND status='active'`, f.team).Scan(&amount, &contractPrice); err != nil || amount != 150000 || contractPrice != price {
		t.Fatalf("contract amount=%d price=%s err=%v", amount, contractPrice, err)
	}
}

func TestIntegration_PlanCatalogKeepsConfiguredPriceWhileTermsMatch(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.priceCreates) != 0 || f.price != "price_pro_monthly" {
		t.Fatalf("configured price replaced: creates=%v price=%s", f.priceCreates, f.price)
	}
}

func TestIntegration_PlanCatalogCompletesPurchaseStartedBeforeCatalog(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_signup_choice SET request_payload=request_payload-'PlanTerms' WHERE team_id=$1`, f.team); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.status = "complete"
	f.paid = true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	var credit int64
	if err := testPool.QueryRow(t.Context(), `SELECT entitlement_amount_cents FROM billing_commercial_contract WHERE team_id=$1 AND status='active'`, f.team).Scan(&credit); err != nil || credit != 100000 {
		t.Fatalf("legacy purchase credit=%d err=%v", credit, err)
	}
}

func TestIntegration_PlanVersionsAreImmutableOncePublished(t *testing.T) {
	ctx := t.Context()
	published := currentPlanVersion(t, "enterprise")
	for _, stmt := range []string{
		`UPDATE billing_plan_version SET display_name='Changed' WHERE id=$1`,
		`UPDATE billing_plan_version SET state='draft',published_at=NULL WHERE id=$1`,
		`DELETE FROM billing_plan_version WHERE id=$1`,
		`UPDATE billing_plan_version SET state='retired',retired_at=now(),tagline='changed' WHERE id=$1`,
	} {
		if _, err := testPool.Exec(ctx, stmt, published); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("%s: err=%v", stmt, err)
		}
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO billing_plan_version(family,version,kind,state,display_name,display_only,published_at) VALUES('enterprise',999,'custom','published','Sneaky',true,now())`); err == nil {
		t.Fatal("inserted a published version without publication")
	}
	var draft uuid.UUID
	if err := testPool.QueryRow(ctx, `INSERT INTO billing_plan_version(family,version,kind,display_name,display_only) VALUES('enterprise',(SELECT MAX(version)+1 FROM billing_plan_version WHERE family='enterprise'),'custom','Enterprise draft',true) RETURNING id`).Scan(&draft); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE billing_plan_version SET tagline='edited' WHERE id=$1`, draft); err != nil {
		t.Fatalf("drafts are editable: %v", err)
	}
	if _, err := testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,NULL)`, draft); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publishPlanCopy(t, published, "") })
	var oldState string
	if err := testPool.QueryRow(ctx, `SELECT state FROM billing_plan_version WHERE id=$1`, published).Scan(&oldState); err != nil || oldState != "retired" {
		t.Fatalf("previous version state=%s err=%v", oldState, err)
	}
	if _, err := testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,NULL)`, draft); err == nil {
		t.Fatal("republished a published version")
	}
	for _, bad := range []string{
		`[{"start_months":0,"every_months":1,"amount_cents":0,"expires_after_months":1}]`,
		`[{"start_months":0,"every_months":0,"amount_cents":100,"expires_after_months":1}]`,
		`[{"start_months":0,"every_months":1,"amount_cents":100,"expires_after_months":1,"surprise":true}]`,
		`[{"start_months":0.5,"every_months":1,"amount_cents":100,"expires_after_months":1}]`,
		`{"start_months":0}`,
	} {
		if _, err := testPool.Exec(ctx, `INSERT INTO billing_plan_version(family,version,kind,display_name,monthly_fee_cents,max_sandboxes,credit_schedule) VALUES('pro',1000,'subscription','Bad',100,1,$1::jsonb)`, bad); err == nil {
			t.Fatalf("accepted invalid schedule %s", bad)
		}
	}
}

type publicPlansBody struct {
	PricingVersion string `json:"pricing_version"`
	Cards          []struct {
		Family      string `json:"family"`
		Kind        string `json:"kind"`
		Name        string `json:"name"`
		PriceLabel  string `json:"price_label"`
		DisplayOnly bool   `json:"display_only"`
		Monthly     *struct {
			OfferKey   string `json:"offer_key"`
			PriceCents int64  `json:"price_cents"`
			Available  bool   `json:"available"`
		} `json:"monthly"`
		Annual *struct {
			Available              bool  `json:"available"`
			PriceCents             int64 `json:"price_cents"`
			MonthlyEquivalentCents int64 `json:"monthly_equivalent_cents"`
		} `json:"annual"`
		CreditSummary      string `json:"credit_summary"`
		MonthlyCreditCents *int64 `json:"monthly_credit_cents"`
		Allowance          *struct {
			AmountCents int64  `json:"amount_cents"`
			AmountUSD   string `json:"amount_usd"`
			Period      string `json:"period"`
			OnExhausted string `json:"on_exhausted"`
			Summary     string `json:"summary"`
		} `json:"allowance"`
		Limits struct {
			MaxConcurrent *int32 `json:"max_concurrent"`
			MaxVCPU       *int32 `json:"max_vcpu"`
			MaxMemoryMiB  *int32 `json:"max_memory_mib"`
			MaxDiskMiB    *int32 `json:"max_disk_mib"`
		} `json:"limits"`
	} `json:"cards"`
	Plans []struct {
		Key string `json:"key"`
	} `json:"plans"`
}

func getPublicPlans(t *testing.T, r http.Handler) publicPlansBody {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/billing/plans/public", nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q body=%s", w.Code, w.Header().Get("Cache-Control"), w.Body)
	}
	var body publicPlansBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestIntegration_PublicBillingPlansWithTheSwitchOff(t *testing.T) {
	_, r, _ := newProFixture(t, "pro_monthly")
	body := getPublicPlans(t, r)
	if body.PricingVersion != "legacy" || len(body.Cards) != 2 || body.Cards[0].Family != "pro" || body.Cards[1].Family != "enterprise" {
		t.Fatalf("legacy cards=%+v", body)
	}
	pro := body.Cards[0]
	if pro.Monthly == nil || !pro.Monthly.Available || pro.Monthly.PriceCents != 120000 || pro.Annual == nil || pro.Annual.PriceCents != 1200000 || pro.Annual.MonthlyEquivalentCents != 100000 ||
		pro.MonthlyCreditCents == nil || *pro.MonthlyCreditCents != 100000 || pro.Limits.MaxConcurrent == nil || *pro.Limits.MaxConcurrent != 1000 {
		t.Fatalf("pro card=%+v", pro)
	}
	if e := body.Cards[1]; !e.DisplayOnly || e.Monthly != nil {
		t.Fatalf("enterprise card=%+v", e)
	}
}

func TestIntegration_BillingCatalogStaffAPI(t *testing.T) {
	r := newInternalRouter(t)
	// Catalog writes need the operator credential; reads and the internal token suffice for listing.
	do := func(method, path, actor, body string) *httptest.ResponseRecorder {
		if method == http.MethodGet {
			return doInternal(r, method, path, actor, body)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+operatorRBACToken)
		req.Header.Set("X-Actor-User-Id", actor)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	admin := seedPlatformAdminProfile(t).String()
	outsider := seedSuperserveEmailProfile(t).String()
	draftBody := `{"family":"enterprise","kind":"custom","public":true,"display_name":"Enterprise","tagline":"Talk to us","features":["SSO"],"sort_order":3,"display_only":true,"reason":"Refresh the Enterprise card copy"}`
	for _, req := range []struct{ method, path, body string }{
		{http.MethodGet, "/internal/billing/catalog", ""},
		{http.MethodPost, "/internal/billing/catalog/plans", draftBody},
		{http.MethodPost, "/internal/billing/pricing-version", `{"pricing_version":"v2","reason":"activate"}`},
	} {
		if w := do(req.method, req.path, outsider, req.body); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s by non-staff = %d %s", req.method, req.path, w.Code, w.Body)
		}
	}
	if w := doInternal(r, http.MethodPost, "/internal/billing/catalog/plans", admin, draftBody); w.Code != http.StatusUnauthorized {
		t.Fatalf("write with the internal token = %d %s", w.Code, w.Body)
	}
	previous := currentPlanVersion(t, "enterprise")
	for _, limits := range []string{`{"max_memory_mib":255}`, `{"max_disk_mib":1023}`} {
		body := strings.Replace(draftBody, `"display_only":true`, `"display_only":true,"limits":`+limits, 1)
		if w := do(http.MethodPost, "/internal/billing/catalog/plans", admin, body); w.Code != http.StatusBadRequest {
			t.Fatalf("unusable template limit accepted: %d %s", w.Code, w.Body)
		}
	}
	if w := do(http.MethodPost, "/internal/billing/catalog/plans", admin, strings.Replace(draftBody, `{"family"`, `{"id":"00000000-0000-0000-0000-000000000000","family"`, 1)); w.Code != http.StatusBadRequest {
		t.Fatalf("nil version id accepted: %d %s", w.Code, w.Body)
	}
	w := do(http.MethodPost, "/internal/billing/catalog/plans", admin, draftBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("create draft = %d %s", w.Code, w.Body)
	}
	var draft struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &draft)
	if w = do(http.MethodPut, "/internal/billing/catalog/plans/"+draft.ID, admin, strings.Replace(draftBody, "Talk to us", "Custom pricing", 1)); w.Code != 200 || !strings.Contains(w.Body.String(), "Custom pricing") {
		t.Fatalf("update draft = %d %s", w.Code, w.Body)
	}
	expected := w.Body.String()
	if stale := do(http.MethodPost, "/internal/billing/catalog/plans/"+draft.ID+"/publish", admin, `{"reason":"stale approval","expected":`+draftBody+`}`); stale.Code != http.StatusConflict {
		t.Fatalf("published changed draft from stale approval: %d %s", stale.Code, stale.Body)
	}
	if w = do(http.MethodPost, "/internal/billing/catalog/plans", admin, `{"family":"pro","kind":"subscription","display_name":"Pro","monthly_fee_cents":100,"limits":{"max_concurrent":1},"credit_schedule":[{"start_months":0,"every_months":0,"amount_cents":1,"expires_after_months":1}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid draft = %d %s", w.Code, w.Body)
	}
	if w = do(http.MethodPost, "/internal/billing/catalog/plans/"+draft.ID+"/publish", admin, `{"reason":" "}`); w.Code != http.StatusBadRequest {
		t.Fatalf("publish without a reason = %d %s", w.Code, w.Body)
	}
	if w = do(http.MethodPost, "/internal/billing/catalog/plans/"+draft.ID+"/publish", admin, `{"reason":"Approved card copy","expected":`+expected+`}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"published"`) {
		t.Fatalf("publish = %d %s", w.Code, w.Body)
	}
	t.Cleanup(func() { publishPlanCopy(t, previous, "") })
	if w = do(http.MethodPut, "/internal/billing/catalog/plans/"+draft.ID, admin, draftBody); w.Code != http.StatusConflict {
		t.Fatalf("edit published = %d %s", w.Code, w.Body)
	}
	if w = do(http.MethodDelete, "/internal/billing/catalog/plans/"+draft.ID, admin, `{"reason":"cleanup"}`); w.Code != http.StatusConflict {
		t.Fatalf("delete published = %d %s", w.Code, w.Body)
	}
	schedule := url.QueryEscape(`[{"start_months":0,"repeat":3,"every_months":1,"amount_cents":3000000,"expires_after_months":1},{"start_months":3,"repeat":9,"every_months":1,"amount_cents":100000,"expires_after_months":1}]`)
	if w = do(http.MethodGet, "/internal/billing/catalog/preview?credit_schedule="+schedule, admin, ""); w.Code != 200 {
		t.Fatalf("preview = %d %s", w.Code, w.Body)
	}
	var preview struct {
		Issues []struct {
			MonthOffset int32 `json:"month_offset"`
		} `json:"issues"`
		Summary string `json:"summary"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &preview)
	if len(preview.Issues) != 12 || preview.Summary != "3 × $30,000 every month, then 9 × $1,000 every month from month 4" {
		t.Fatalf("preview=%+v", preview)
	}
	var audit []string
	rows, err := testPool.Query(t.Context(), `SELECT action||':'||reason FROM billing_catalog_audit WHERE version_id=$1 AND actor_id=$2 ORDER BY created_at`, draft.ID, admin)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var entry string
		if err := rows.Scan(&entry); err != nil {
			t.Fatal(err)
		}
		audit = append(audit, entry)
	}
	if strings.Join(audit, "|") != "create_draft:Refresh the Enterprise card copy|update_draft:Refresh the Enterprise card copy|publish:Approved card copy" {
		t.Fatalf("audit=%v", audit)
	}
	if _, err := testPool.Exec(t.Context(), `DELETE FROM billing_catalog_audit WHERE version_id=$1`, draft.ID); err == nil {
		t.Fatal("audit rows were deletable")
	}
	if w = do(http.MethodGet, "/internal/billing/catalog", admin, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"pricing_version":"legacy"`) {
		t.Fatalf("catalog = %d %s", w.Code, w.Body)
	}
}

func TestIntegration_PlanCatalogDirectRetireStopsOlderBinariesSelling(t *testing.T) {
	previous := currentPlanVersion(t, "pro")
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_plan_version SET state='retired',retired_at=now() WHERE id=$1`, previous); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publishPlanCopy(t, previous, "") })
	var available bool
	if err := testPool.QueryRow(t.Context(), `SELECT bool_or(available) FROM billing_plan WHERE family='pro'`).Scan(&available); err != nil || available {
		t.Fatalf("retiring outside retire_billing_plan_version left pro available: %v %v", available, err)
	}
}

func TestIntegration_PlanCatalogConcurrentPublishAndRetireSerialize(t *testing.T) {
	ctx := t.Context()
	original := currentPlanVersion(t, "enterprise")
	t.Cleanup(func() { publishPlanCopy(t, original, "") })
	for i := 0; i < 10; i++ {
		current := currentPlanVersion(t, "enterprise")
		var draft uuid.UUID
		if err := testPool.QueryRow(ctx, `INSERT INTO billing_plan_version(family,version,kind,display_name,display_only)
			SELECT 'enterprise',MAX(version)+1,'custom','Enterprise',true FROM billing_plan_version WHERE family='enterprise' RETURNING id`).Scan(&draft); err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 2)
		go func() {
			_, err := testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,NULL)`, draft)
			errs <- err
		}()
		go func() {
			_, err := testPool.Exec(ctx, `SELECT retire_billing_plan_version($1,NULL)`, current)
			errs <- err
		}()
		for j := 0; j < 2; j++ {
			if err := <-errs; err != nil && !strings.Contains(err.Error(), "only the published version can be retired") {
				t.Fatalf("round %d: %v", i, err)
			}
		}
		var published int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM billing_plan_version WHERE family='enterprise' AND pricing_version='legacy' AND state='published'`).Scan(&published); err != nil || published > 1 {
			t.Fatalf("round %d: published=%d err=%v", i, published, err)
		}
		if published == 0 {
			publishPlanCopy(t, original, "")
		}
	}
}

func TestIntegration_PlanCatalogDoesNotSellUndeliveredMatching(t *testing.T) {
	setCatalogPlan(t, "pro", "matching_bps=5000,cap_cents=1000000")
	var available bool
	if err := testPool.QueryRow(t.Context(), `SELECT bool_or(available) FROM billing_plan WHERE family='pro'`).Scan(&available); err != nil || available {
		t.Fatalf("matching plan offered to older binaries: %v %v", available, err)
	}
	_, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody("pro_monthly"), 400, "invalid_offer")
}

func TestIntegration_PlanCatalogPendingCheckoutResumesAfterRetire(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	previous := currentPlanVersion(t, "pro")
	if _, err := testPool.Exec(t.Context(), `SELECT retire_billing_plan_version($1,NULL)`, previous); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publishPlanCopy(t, previous, "") })
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.priceCreates) != 0 || f.creates != 2 || f.keys[0] != f.keys[1] {
		t.Fatalf("resume changed the frozen request: creates=%d keys=%v prices=%v", f.creates, f.keys, f.priceCreates)
	}
}

func TestIntegration_PlanCatalogTransientPriceReadCreatesNothing(t *testing.T) {
	f, r, key := newProFixture(t, "pro_monthly")
	f.failBasePriceRead = true
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 503, "service_unavailable")
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.priceCreates) != 0 {
		t.Fatalf("transient read created prices: %v", f.priceCreates)
	}
}

func TestIntegration_PlanCatalogPublishesNewFamily(t *testing.T) {
	ctx := t.Context()
	family := "scale" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	family = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return 'a' + (r - '0')
		}
		return r
	}, family)
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `INSERT INTO billing_plan_version(family,version,kind,display_name,self_serve,monthly_fee_cents,credit_schedule,max_sandboxes)
		VALUES($1,1,'subscription','Scale',false,50000,$2::jsonb,200) RETURNING id`, family, monthlySchedule(40000)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,NULL)`, id); err != nil {
		t.Fatalf("publish new family: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(), `SELECT retire_billing_plan_version($1,NULL)`, id); err != nil {
			t.Error(err)
		}
	})
	var available bool
	var sandboxes int32
	if err := testPool.QueryRow(ctx, `SELECT p.available,l.max_sandboxes FROM billing_plan p JOIN plan_limits l USING(offer_key) WHERE p.offer_key=$1`, family+"_monthly").Scan(&available, &sandboxes); err != nil || available || sandboxes != 200 {
		t.Fatalf("new family offer available=%v sandboxes=%d err=%v", available, sandboxes, err)
	}
	// A customer-specific family is neither a public card nor sold through checkout.
	w := httptest.NewRecorder()
	newRouter(t).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/billing/plans/public", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), family) {
		t.Fatalf("non-public family listed: %d %s", w.Code, w.Body)
	}
}

func TestIntegration_BillingCatalogWritesAreIdempotentPerVersionID(t *testing.T) {
	r := newInternalRouter(t)
	admin := seedPlatformAdminProfile(t).String()
	operator := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+operatorRBACToken)
		req.Header.Set("X-Actor-User-Id", admin)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	previous := currentPlanVersion(t, "enterprise")
	var next int32
	if err := testPool.QueryRow(t.Context(), `SELECT MAX(version)+1 FROM billing_plan_version WHERE family='enterprise'`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	body := fmt.Sprintf(`{"id":"%s","version":%d,"family":"enterprise","kind":"custom","public":true,"display_name":"Enterprise","tagline":"Fan-out","sort_order":3,"display_only":true,"reason":"Sync every region"}`, id, next)
	for attempt := 0; attempt < 2; attempt++ {
		if w := operator(http.MethodPost, "/internal/billing/catalog/plans", body); (attempt == 0 && w.Code != http.StatusCreated) || (attempt == 1 && w.Code != http.StatusOK) || !strings.Contains(w.Body.String(), id.String()) {
			t.Fatalf("create attempt %d = %d %s", attempt, w.Code, w.Body)
		}
	}
	if w := operator(http.MethodPost, "/internal/billing/catalog/plans", strings.Replace(body, "Fan-out", "Different", 1)); w.Code != http.StatusConflict {
		t.Fatalf("same id, different terms = %d %s", w.Code, w.Body)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if w := operator(http.MethodPost, "/internal/billing/catalog/plans/"+id.String()+"/publish", `{"reason":"Sync every region"}`); w.Code != 200 {
			t.Fatalf("publish attempt %d = %d %s", attempt, w.Code, w.Body)
		}
	}
	t.Cleanup(func() { publishPlanCopy(t, previous, "") })
	for attempt := 0; attempt < 2; attempt++ {
		if w := operator(http.MethodPost, "/internal/billing/catalog/plans/"+id.String()+"/retire", `{"reason":"Sync every region"}`); w.Code != 200 {
			t.Fatalf("retire attempt %d = %d %s", attempt, w.Code, w.Body)
		}
	}
	if w := operator(http.MethodDelete, "/internal/billing/catalog/plans/"+uuid.NewString(), `{"reason":"Sync every region"}`); w.Code != http.StatusNoContent {
		t.Fatalf("delete of a missing draft = %d %s", w.Code, w.Body)
	}
	var actions string
	if err := testPool.QueryRow(t.Context(), `SELECT string_agg(action, ',' ORDER BY created_at) FROM billing_catalog_audit WHERE version_id=$1`, id).Scan(&actions); err != nil || actions != "create_draft,publish,retire" {
		t.Fatalf("audit actions=%q err=%v", actions, err)
	}
}

func TestIntegration_PlanCatalogNeverPublishesOverANewerVersion(t *testing.T) {
	ctx := t.Context()
	previous := currentPlanVersion(t, "enterprise")
	var older, newer uuid.UUID
	for _, id := range []*uuid.UUID{&older, &newer} {
		if err := testPool.QueryRow(ctx, `INSERT INTO billing_plan_version(family,version,kind,display_name,display_only)
			SELECT 'enterprise',MAX(version)+1,'custom','Enterprise',true FROM billing_plan_version WHERE family='enterprise' RETURNING id`).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,NULL)`, newer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publishPlanCopy(t, previous, "") })
	if _, err := testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,NULL)`, older); err == nil || !strings.Contains(err.Error(), "newer version") {
		t.Fatalf("older draft replaced the newer version: %v", err)
	}
	if current := currentPlanVersion(t, "enterprise"); current != newer {
		t.Fatalf("current=%s want %s", current, newer)
	}
	var seeded int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM billing_plan_version WHERE id=md5('billing-plan-version:'||pricing_version||':'||family||':'||version)::uuid`).Scan(&seeded); err != nil || seeded != 7 {
		t.Fatalf("seeded versions with region-independent ids=%d err=%v", seeded, err)
	}
}

// With the pricing switch off customers see exactly what they did before:
// a $5 trial, a $95 card bonus and Pro checkout on the configured Stripe
// prices.
func TestIntegration_PlanCatalogDefaultsMatchPreviousBehaviour(t *testing.T) {
	ctx := t.Context()
	userID := uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO profile (id, email) VALUES ($1, $2)`, userID, "defaults-"+uuid.NewString()[:8]+"@example.com"); err != nil {
		t.Fatal(err)
	}
	trialTeam, err := provisionTeamForUser(ctx, userID, "defaults-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatal(err)
	}
	var trial float64
	if err := testPool.QueryRow(ctx, `SELECT amount_usd::float8 FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'`, trialTeam).Scan(&trial); err != nil || trial != 5 {
		t.Fatalf("trial=%v err=%v", trial, err)
	}

	teamID, _, owner := seedTeamAndKeyWithRole(t, "team_owner")
	customerID, subscriptionID := "cus_"+teamID.String(), "sub_"+teamID.String()
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status) VALUES ($1,$2,$3,'incomplete')`, teamID, customerID, subscriptionID); err != nil {
		t.Fatal(err)
	}
	stripe := &fakeStripeClient{}
	created := time.Now().UTC().Truncate(time.Second)
	if w := sendStripeActivationWebhook(t, newBillingRouter(t, stripe), "evt_defaults_"+teamID.String(), teamID, owner, created); w.Code != http.StatusOK {
		t.Fatalf("activation: %d %s", w.Code, w.Body)
	}
	var ledger float64
	if err := testPool.QueryRow(ctx, `SELECT amount_usd::float8 FROM team_credit_grant WHERE team_id=$1 AND reason='stripe promotional credit'`, teamID).Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	if len(stripe.creditGrantCalls) != 1 || stripe.creditGrantCalls[0].AmountCents != 9500 || ledger != 95 {
		t.Fatalf("card bonus calls=%+v ledger=%v", stripe.creditGrantCalls, ledger)
	}

	for _, offer := range []string{"pro_monthly", "pro_annual"} {
		f, r, key := newProFixture(t, offer)
		assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
		f.mu.Lock()
		creates, price := len(f.priceCreates), f.price
		f.mu.Unlock()
		var base string
		if err := testPool.QueryRow(ctx, `SELECT base_price_id FROM billing_signup_choice WHERE team_id=$1`, f.team).Scan(&base); err != nil || base != "price_"+offer || price != "price_"+offer || creates != 0 {
			t.Fatalf("%s: base=%s price=%s creates=%d err=%v", offer, base, price, creates, err)
		}
	}
}

func TestIntegration_PlanCatalogContractsKeepTheLimitsTheyWereSold(t *testing.T) {
	offer := testFamily(t, 10000, 5000, 40)
	family := strings.TrimSuffix(offer, "_monthly")
	f, r, key := newProFixture(t, offer)
	sellFamily(f, offer)
	f.amount = 10000
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(f.offer), 200, f.session)
	publishPlanCopy(t, currentPlanVersion(t, family), "max_sandboxes=75,max_templates=3")
	f.mu.Lock()
	f.status = "complete"
	f.paid = true
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/pro-checkout/recover", `{}`, 200, "active")
	ctx := t.Context()
	var contract uuid.UUID
	var frozen, sandboxes int32
	if err := testPool.QueryRow(ctx, `SELECT c.id,l.max_sandboxes,t.max_sandboxes FROM billing_commercial_contract c JOIN billing_contract_limits l ON l.contract_id=c.id JOIN team t ON t.id=c.team_id
		WHERE c.team_id=$1 AND c.status='active'`, f.team).Scan(&contract, &frozen, &sandboxes); err != nil {
		t.Fatal(err)
	}
	if frozen != 40 || sandboxes != 40 {
		t.Fatalf("frozen=%d team=%d want the 40 sold at checkout", frozen, sandboxes)
	}
	if _, err := testPool.Exec(ctx, `SELECT apply_contract_limits($1)`, contract); err != nil {
		t.Fatal(err)
	}
	var templates int32
	if err := testPool.QueryRow(ctx, `SELECT t.max_sandboxes,l.max_templates FROM team t, team_effective_limits(t.id) l WHERE t.id=$1`, f.team).Scan(&sandboxes, &templates); err != nil || sandboxes != 40 || templates != 10 {
		t.Fatalf("reapplied limits sandboxes=%d templates=%d err=%v", sandboxes, templates, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE billing_contract_limits SET max_sandboxes=1 WHERE contract_id=$1`, contract); err == nil {
		t.Fatal("frozen limits were editable")
	}
}

func TestIntegration_PlanCatalogFirstVersionsNeedTheConfiguredPrice(t *testing.T) {
	ctx := t.Context()
	family := "first" + strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return 'a' + r - '0'
		}
		return r
	}, strings.ReplaceAll(uuid.NewString()[:8], "-", ""))
	var first uuid.UUID
	if err := testPool.QueryRow(ctx, `INSERT INTO billing_plan_version(family,version,kind,public,self_serve,display_name,monthly_fee_cents,credit_schedule,max_sandboxes)
		VALUES($1,1,'subscription',true,true,'First',120000,$2::jsonb,100) RETURNING id`, family, monthlySchedule(100000)).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `SELECT publish_billing_plan_version($1,NULL)`, first); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `SELECT retire_billing_plan_version(id,NULL) FROM billing_plan_version WHERE family=$1 AND state='published'`, family)
	})
	offer := family + "_monthly"
	f, r, key := newProFixture(t, offer)
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(offer), 400, "invalid_offer")
	// A configured price that no longer matches stops sales of the first
	// version rather than being replaced by a price of its own.
	sellFamily(f, offer)
	f.mu.Lock()
	f.amount = 99
	f.mu.Unlock()
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(offer), 503, "service_unavailable")
	f.mu.Lock()
	if len(f.priceCreates) != 0 {
		t.Fatalf("first version created a price: %v", f.priceCreates)
	}
	f.amount = 120000
	f.mu.Unlock()
	delete(f.handlers.Config.StripePlanPriceIDs, offer)
	publishPlanCopy(t, first, "")
	assertProResponse(t, r, key, "/stripe/checkout-session", proCheckoutBody(offer), 200, f.session)
}

func operatorRequest(r http.Handler, method, path, actor, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+operatorRBACToken)
	req.Header.Set("X-Actor-User-Id", actor)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestIntegration_PricingSwitchDoesNotReleasePublicCatalog(t *testing.T) {
	ctx := t.Context()
	r := newInternalRouter(t)
	admin := seedPlatformAdminProfile(t).String()
	outsider := seedSuperserveEmailProfile(t).String()
	if w := operatorRequest(r, http.MethodPost, "/internal/billing/pricing-version", outsider, `{"pricing_version":"v2","reason":"activate"}`); w.Code != http.StatusForbidden {
		t.Fatalf("non-staff flip = %d %s", w.Code, w.Body)
	}
	if w := doInternal(r, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"v2","reason":"activate"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("flip with the internal token = %d %s", w.Code, w.Body)
	}
	if w := operatorRequest(r, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"v2","reason":" "}`); w.Code != http.StatusBadRequest {
		t.Fatalf("flip without a reason = %d %s", w.Code, w.Body)
	}
	if w := doInternal(r, http.MethodGet, "/internal/billing/pricing-version", admin, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"pricing_version":"legacy"`) {
		t.Fatalf("read switch = %d %s", w.Code, w.Body)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if w := operatorRequest(r, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"v2","reason":"Launch pricing v2"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"pricing_version":"v2"`) {
			t.Fatalf("flip attempt %d = %d %s", attempt, w.Code, w.Body)
		}
	}
	t.Cleanup(func() {
		if w := operatorRequest(r, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"legacy","reason":"test cleanup"}`); w.Code != 200 {
			t.Errorf("restore switch = %d %s", w.Code, w.Body)
		}
	})
	var audits int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM billing_pricing_switch_audit WHERE actor_id=$1 AND to_version='v2' AND reason='Launch pricing v2'`, admin).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("switch audits=%d err=%v", audits, err)
	}

	body := getPublicPlans(t, r)
	if body.PricingVersion != "legacy" || len(body.Cards) != 2 || body.Cards[0].Family != "pro" || body.Cards[1].Family != "enterprise" {
		t.Fatalf("unreleased catalog=%+v", body)
	}
	for _, card := range body.Cards {
		if (card.Monthly != nil && card.Monthly.Available) || (card.Annual != nil && card.Annual.Available) {
			t.Fatalf("unreleased purchase available: %+v", card)
		}
	}
	if len(body.Plans) != 0 {
		t.Fatalf("unreleased offers=%+v", body.Plans)
	}
	var monthly int64
	var annualAvailable bool
	if err := testPool.QueryRow(ctx, `SELECT (SELECT charge_amount_cents FROM billing_plan WHERE offer_key='pro_monthly'),(SELECT available FROM billing_plan WHERE offer_key='pro_annual')`).Scan(&monthly, &annualAvailable); err != nil ||
		monthly != 25000 || annualAvailable {
		t.Fatalf("v2 offers monthly=%d annual available=%v err=%v", monthly, annualAvailable, err)
	}
	// Contracts without frozen limits activate on plan_limits, so the flip
	// keeps the limits legacy Pro was sold with.
	var proVCPU int32
	if err := testPool.QueryRow(ctx, `SELECT max_template_vcpu FROM plan_limits WHERE offer_key='pro_monthly'`).Scan(&proVCPU); err != nil || proVCPU == 8 {
		t.Fatalf("pro_monthly plan_limits vcpu after flip = %d err=%v", proVCPU, err)
	}
	if w := operatorRequest(r, http.MethodPost, "/internal/billing/pricing-version", admin, `{"pricing_version":"legacy","reason":"roll back"}`); w.Code != 200 {
		t.Fatalf("flip back = %d %s", w.Code, w.Body)
	}
	if err := testPool.QueryRow(ctx, `SELECT (SELECT charge_amount_cents FROM billing_plan WHERE offer_key='pro_monthly'),(SELECT available FROM billing_plan WHERE offer_key='pro_annual')`).Scan(&monthly, &annualAvailable); err != nil ||
		monthly != 120000 || !annualAvailable {
		t.Fatalf("legacy offers after rollback monthly=%d annual available=%v err=%v", monthly, annualAvailable, err)
	}
}

func TestIntegration_TeamEffectiveLimitsKeepTodaysValuesAndOverrides(t *testing.T) {
	ctx := t.Context()
	team, err := testQueries.CreateTeam(ctx, "limits-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatal(err)
	}
	var l [5]int32
	read := func() {
		t.Helper()
		if err := testPool.QueryRow(ctx, `SELECT max_concurrent,max_vcpu,max_memory_mib,max_disk_mib,max_templates FROM team_effective_limits($1)`, team.ID).Scan(&l[0], &l[1], &l[2], &l[3], &l[4]); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if l != [5]int32{20, 2, 2048, 8192, 10} {
		t.Fatalf("legacy limits=%v", l)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_templates=25, max_template_vcpu=4 WHERE id=$1`, team.ID); err != nil {
		t.Fatal(err)
	}
	read()
	if l != [5]int32{20, 4, 2048, 8192, 25} {
		t.Fatalf("overridden limits=%v", l)
	}
}

func TestIntegration_PublicBillingPlansListTodaysPurchasablePlans(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", internalRBACToken)
	cfg := &config.Config{
		Port:                    "0",
		VMDAddress:              "localhost:0",
		SystemTeamID:            testSystemTeamID.String(),
		StripePlanPriceIDs:      map[string]string{"starter_monthly": "price_starter_monthly", "starter_annual": "price_starter_annual"},
		StripeProMonthlyPriceID: "price_pro_monthly",
		StripeProAnnualPriceID:  "price_pro_annual",
	}
	h := api.NewHandlers(&stubVMD{}, db.New(testPool), cfg)
	h.Pool = testPool
	h.Stripe = api.NewStripeBillingClient(&config.Config{StripeSecretKey: "sk_test_example", StripeAPIVersion: "2026-07-29.dahlia"})
	w := do(api.SetupRouter(t.Context(), h, testPool), "GET", "/billing/plans/public", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("plans: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Plans []struct {
			Key                string `json:"key"`
			IntervalMonths     int32  `json:"interval_months"`
			PriceCents         int64  `json:"price_cents"`
			MonthlyCreditCents int64  `json:"monthly_credit_cents"`
		} `json:"plans"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// Starter stays unavailable, even where a price is configured, so only
	// the Pro offers checkout already sells are listed, at their current terms.
	var starter int
	if err := testPool.QueryRow(t.Context(), `SELECT (SELECT COUNT(*) FROM billing_plan WHERE family='starter') + (SELECT COUNT(*) FROM plan_limits WHERE offer_key LIKE 'starter%')`).Scan(&starter); err != nil || starter != 0 {
		t.Fatalf("migrated catalog has %d Starter offer rows, err=%v", starter, err)
	}
	got := fmt.Sprint(body.Plans)
	want := "[{pro_monthly 1 120000 100000} {pro_annual 12 1200000 100000}]"
	if got != want {
		t.Fatalf("plans = %s, want %s", got, want)
	}
}

func setPricingSwitch(t *testing.T, version string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_pricing_switch SET pricing_version=$1`, version); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := testPool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version='legacy'`); err != nil {
			t.Error(err)
		}
	})
}

func TestIntegration_PricingV2HasNoSignupPromotions(t *testing.T) {
	ctx := t.Context()
	setPricingSwitch(t, "v2")
	userID := uuid.New()
	if _, err := testPool.Exec(ctx, `INSERT INTO profile (id, email) VALUES ($1, $2)`, userID, "v2-"+uuid.NewString()[:8]+"@example.com"); err != nil {
		t.Fatal(err)
	}
	trialTeam, err := provisionTeamForUser(ctx, userID, "v2-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatal(err)
	}
	var grants int
	var reason string
	var denied bool
	if err := testPool.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit'),
		(SELECT reason FROM team_signup_promotion_outcome WHERE team_id=$1), EXISTS(SELECT 1 FROM team_signup_trial_denial WHERE team_id=$1)`, trialTeam).
		Scan(&grants, &reason, &denied); err != nil || grants != 0 || reason != "pricing_v2" || !denied {
		t.Fatalf("trial grants=%d reason=%s denied=%v err=%v", grants, reason, denied, err)
	}

	teamID, _, owner := seedTeamAndKeyWithRole(t, "team_owner")
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status) VALUES ($1,$2,$3,'incomplete')`,
		teamID, "cus_"+teamID.String(), "sub_"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	stripe := &fakeStripeClient{}
	router := newBillingRouter(t, stripe)
	created := time.Now().UTC().Truncate(time.Second)
	if w := sendStripeActivationWebhook(t, router, "evt_v2_"+teamID.String(), teamID, owner, created); w.Code != http.StatusOK {
		t.Fatalf("activation: %d %s", w.Code, w.Body)
	}
	var trialEnded, reserved bool
	if err := testPool.QueryRow(ctx, `SELECT trial_ended_at IS NOT NULL, stripe_activation_credit_reserved_at IS NOT NULL FROM team_billing_account WHERE team_id=$1`, teamID).
		Scan(&trialEnded, &reserved); err != nil || !trialEnded || reserved {
		t.Fatalf("account trial ended=%v reserved=%v err=%v", trialEnded, reserved, err)
	}
	if err := testPool.QueryRow(ctx, `SELECT reason FROM stripe_promotion_outcome WHERE team_id=$1`, teamID).Scan(&reason); err != nil || reason != "pricing_v2" {
		t.Fatalf("card bonus outcome=%s err=%v", reason, err)
	}

	if len(stripe.creditGrantCalls) != 0 {
		t.Fatalf("card bonus granted under v2: %+v", stripe.creditGrantCalls)
	}
}

func TestIntegration_PricingSwitchRollbackRestoresTheLegacyOfferRows(t *testing.T) {
	ctx := t.Context()
	snapshot := func() string {
		var rows string
		if err := testPool.QueryRow(ctx, `SELECT jsonb_build_object(
			'plans', (SELECT jsonb_agg(to_jsonb(p) ORDER BY offer_key) FROM billing_plan p),
			'limits', (SELECT jsonb_agg(to_jsonb(l) ORDER BY offer_key) FROM plan_limits l))::text`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	before := snapshot()
	setPricingSwitch(t, "v2")
	if during := snapshot(); during == before {
		t.Fatal("the v2 flip left the offer rows unchanged")
	}
	if _, err := testPool.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='legacy'`); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("offer rows after rollback differ:\nbefore %s\nafter  %s", before, after)
	}
	var monthly, annual int64
	var monthlyAvailable, annualAvailable bool
	if err := testPool.QueryRow(ctx, `SELECT m.charge_amount_cents, m.available, a.charge_amount_cents, a.available
		FROM billing_plan m, billing_plan a WHERE m.offer_key='pro_monthly' AND a.offer_key='pro_annual'`).
		Scan(&monthly, &monthlyAvailable, &annual, &annualAvailable); err != nil || monthly != 120000 || annual != 1200000 || !monthlyAvailable || !annualAvailable {
		t.Fatalf("legacy Pro after rollback monthly=%d/%v annual=%d/%v err=%v", monthly, monthlyAvailable, annual, annualAvailable, err)
	}
}

func TestIntegration_UnassignedFreeEntryWaitsForPricingAdoption(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprintf("replay=%t", replay), func(t *testing.T) {
			fixture, r, key := newProFixture(t, "pro_monthly")
			if replay {
				assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, 200, "committed")
			}
			setPricingSwitch(t, "v2")
			status, code := 409, "plan_conflict"
			if replay {
				status, code = 200, "committed"
			}
			assertProResponse(t, r, key, "/stripe/plan-choice", `{"offer":"free"}`, status, code)
			var choices int
			if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_signup_choice WHERE team_id=$1 AND offer_key='free' AND state='committed'`, fixture.team).Scan(&choices); err != nil {
				t.Fatal(err)
			}
			expected := 0
			if replay {
				expected = 1
			}
			if choices != expected {
				t.Fatalf("choice rows=%d want=%d", choices, expected)
			}

		})
	}
}

func TestIntegration_PricingEntryReaderUsesRestrictedRole(t *testing.T) {
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role NOLOGIN; END IF; END $$; GRANT USAGE ON SCHEMA public TO service_role; DROP FUNCTION billing_lock_pricing_public_state()`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../supabase/migrations/20261024131000_pricing_adoption_entry.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), string(migration)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SET LOCAL ROLE service_role`); err != nil {
		t.Fatal(err)
	}
	var model string
	var opened bool
	var epoch *uuid.UUID
	if err := tx.QueryRow(t.Context(), `SELECT * FROM billing_lock_pricing_public_state()`).Scan(&model, &opened, &epoch); err != nil || model != "legacy" || opened {
		t.Fatalf("restricted reader=%s/%t/%v: %v", model, opened, epoch, err)
	}
}
