package api

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type fundingCreditObservation struct {
	SpendableUSD string
	ValidUntil   time.Time
	Source       string
	Evidence     json.RawMessage
}

type fundingPeriodReserve struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	USD   string    `json:"reserved_usd"`
}

type fundingGrantBalance struct{ Ledger, Available int64 }

func fundingProviderGrantBalance(ctx context.Context, client *stripeHTTPClient, customer, id string) (fundingGrantBalance, error) {
	var result fundingGrantBalance
	type amount struct {
		Monetary *struct {
			Currency string `json:"currency"`
			Value    int64  `json:"value"`
		} `json:"monetary"`
	}
	var summary struct {
		Balances []struct {
			Ledger    amount `json:"ledger_balance"`
			Available amount `json:"available_balance"`
		} `json:"balances"`
	}
	if err := client.doForm(ctx, http.MethodGet, "/v1/billing/credit_balance_summary?"+url.Values{"customer": {customer}, "filter[type]": {"credit_grant"}, "filter[credit_grant]": {id}}.Encode(), nil, &summary, ""); err != nil {
		return result, err
	}
	if len(summary.Balances) != 1 || summary.Balances[0].Ledger.Monetary == nil || summary.Balances[0].Available.Monetary == nil {
		return result, errors.New("funding grant ledger/reservation evidence incomplete")
	}
	l, a := summary.Balances[0].Ledger.Monetary, summary.Balances[0].Available.Monetary
	if l.Currency != "usd" || a.Currency != "usd" || l.Value < 0 || a.Value < 0 || a.Value > l.Value {
		return result, errors.New("funding grant ledger/reservation evidence invalid")
	}
	return fundingGrantBalance{Ledger: l.Value, Available: a.Value}, nil
}

func fundingGrantCoversResources(g entitlementGrant, requiredPrices []string) bool {
	if g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value <= 0 {
		return false
	}
	if g.Applicability.Scope.PriceType == "metered" && len(g.Applicability.Scope.Prices) == 0 {
		return true
	}
	if g.Applicability.Scope.PriceType != "" || len(requiredPrices) == 0 {
		return false
	}
	prices := map[string]bool{}
	for _, p := range g.Applicability.Scope.Prices {
		prices[p.ID] = true
	}
	for _, price := range requiredPrices {
		if price == "" || !prices[price] {
			return false
		}
	}
	return true
}

// Purchase evidence survives both configuration rotations and an explicit Free
// transition. Never reinterpret an old scoped grant using today's price IDs.
func (h *Handlers) fundingCreditResourcePrices(ctx context.Context, team uuid.UUID, customer string) ([]string, error) {
	var payload []byte
	var storage bool
	var rounding string
	err := h.Pool.QueryRow(ctx, `WITH identity AS (
 SELECT COALESCE(NULLIF(a.stripe_subscription_id,''),(SELECT r.subscription_id FROM billing_plan_release r WHERE r.team_id=$1 AND r.customer_id=$2 AND r.subscription_id IS NOT NULL ORDER BY r.released_at DESC LIMIT 1)) subscription
 FROM team_billing_account a WHERE a.team_id=$1 AND a.stripe_customer_id=$2
), evidence AS (
 SELECT c.request_payload payload,1 priority FROM billing_signup_choice c,identity i WHERE c.team_id=$1 AND c.subscription_id=i.subscription AND c.offer_key IN ('pro_monthly','pro_annual')
 UNION ALL SELECT o.resource_terms,2 FROM identity i CROSS JOIN LATERAL (SELECT resource_terms FROM billing_sponsored_operation WHERE team_id=$1 AND customer_id=$2 AND subscription_id=i.subscription ORDER BY approved_at DESC,id DESC LIMIT 1) o
 UNION ALL SELECT o.resource_terms,2 FROM billing_yc_operation o,identity i WHERE o.team_id=$1 AND o.customer_id=$2 AND o.subscription_id=i.subscription
 UNION ALL SELECT r.previous_choice->'request_payload',3 FROM billing_plan_release r,identity i WHERE r.team_id=$1 AND r.customer_id=$2 AND r.subscription_id=i.subscription
)
SELECT e.payload,storage_billing_activated($1),COALESCE((SELECT a.adjustment_price_id FROM billing_invoice_account a,identity i WHERE a.team_id=$1 AND a.customer_id=$2 AND a.subscription_id=i.subscription),'')
FROM evidence e WHERE e.payload IS NOT NULL AND e.payload<>'null'::jsonb ORDER BY priority LIMIT 1`, team, customer).Scan(&payload, &storage, &rounding)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return h.fundingPAYGCreditResourcePrices(ctx, team, customer)
		}
		return nil, err
	}
	var params StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(payload, &params); err != nil {
		return nil, err
	}
	return fundingRequiredCreditPrices(params.ResourceTerms, storage, rounding)
}

func (h *Handlers) fundingPAYGCreditResourcePrices(ctx context.Context, team uuid.UUID, customer string) ([]string, error) {
	a, enrolled, err := h.invoiceAccount(ctx, team)
	if err != nil {
		return nil, err
	}
	if !enrolled || a.Customer != customer || a.Base.Price != "" {
		return nil, errors.New("current credit resource authority unavailable")
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return nil, errors.New("provider resource verification unavailable")
	}
	sub, err := client.invoiceSubscription(ctx, a.Subscription)
	if err != nil {
		return nil, err
	}
	if sub.Customer != customer {
		return nil, errors.New("provider credit resource customer mismatch")
	}
	var anchor time.Time
	var storage bool
	if err = h.Pool.QueryRow(ctx, `SELECT commercial_billing_anchor,storage_billing_activated($1) FROM team_billing_account WHERE team_id=$1 AND stripe_customer_id=$2 AND stripe_subscription_id=$3`, team, customer, sub.ID).Scan(&anchor, &storage); err != nil {
		return nil, err
	}
	if err = h.validateInvoiceResourceSubscription(ctx, team, a, client, sub, anchor, h.Pool); err != nil {
		return nil, err
	}
	var terms []StripeCheckoutResourceTerms
	for _, resource := range h.billingResourceStates(storage) {
		if resource.Billable {
			terms = append(terms, StripeCheckoutResourceTerms{ResourceKey: resource.ResourceKey, PriceID: resource.StripePriceID})
		}
	}
	return fundingRequiredCreditPrices(terms, storage, a.Price)
}

func fundingRequiredCreditPrices(terms []StripeCheckoutResourceTerms, storage bool, rounding string) ([]string, error) {
	resources := map[string]string{}
	for _, term := range terms {
		if term.ResourceKey != "vcpu" && term.ResourceKey != "memory_gib" && term.ResourceKey != "storage_gib" {
			return nil, errors.New("unknown frozen funding resource")
		}
		if term.PriceID == "" || resources[term.ResourceKey] != "" {
			return nil, errors.New("incomplete frozen funding resource")
		}
		resources[term.ResourceKey] = term.PriceID
	}
	if resources["vcpu"] == "" || resources["memory_gib"] == "" || storage && resources["storage_gib"] == "" {
		return nil, errors.New("frozen funding resource missing")
	}
	prices := []string{resources["vcpu"], resources["memory_gib"]}
	if storage {
		prices = append(prices, resources["storage_gib"])
	}
	if rounding != "" {
		prices = append(prices, rounding)
	}
	return prices, nil
}

// Credit balances are observations, never reservations. Publication must compare
// the funding generation read before this call; grant changes and period close
// invalidate that generation. This work belongs to the background reconciler.
func (h *Handlers) observeFundingCredit(ctx context.Context, team uuid.UUID, account db.TeamBillingAccount, at time.Time) (fundingCreditObservation, error) {
	if at.IsZero() || team != account.TeamID {
		return fundingCreditObservation{}, errors.New("invalid funding credit identity or observation time")
	}
	var err error
	// A customer alone is not activation. Once credits have moved to Stripe,
	// local grant rows cannot prove independent funds and must not be added.
	provider := derefString(account.StripeSubscriptionID) != "" || derefString(account.StripeActivationCreditGrantID) != "" || account.StripeActivationCreditGrantedAt.Valid
	var historicalProvider bool
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1) OR EXISTS(SELECT 1 FROM billing_invoice_close WHERE team_id=$1)`, team).Scan(&historicalProvider); err != nil {
		return fundingCreditObservation{}, err
	}
	provider = provider || historicalProvider
	result := fundingCreditObservation{SpendableUSD: "0.000000", ValidUntil: at.Add(time.Minute), Source: "local"}
	var available string
	var start time.Time
	var expiry pgtype.Timestamptz
	var providerEvidence any
	var verifyProvider func([]fundingPeriodReserve) error
	if provider {
		result.Source = "stripe"
		client, ok := h.Stripe.(*stripeHTTPClient)
		if !ok || derefString(account.StripeCustomerID) == "" {
			return result, errors.New("provider credit authority unavailable")
		}
		var cents int64
		cents, start, expiry, providerEvidence, verifyProvider, err = h.observeProviderFundingGrants(ctx, client, team, *account.StripeCustomerID, at)
		if err != nil {
			return result, err
		}
		available = big.NewRat(cents, 100).FloatString(6)
	}
	// Do not hold a database connection across provider requests.
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	if !provider {
		err = tx.QueryRow(ctx, `SELECT COALESCE(sum(remaining_usd),0)::text, COALESCE(min(created_at),$2),min(expires_at)
 FROM team_credit_grant WHERE team_id=$1 AND currency='USD' AND remaining_usd>0 AND created_at<=$2 AND (expires_at IS NULL OR expires_at>$2)`, team, at).Scan(&available, &start, &expiry)
		if err != nil {
			return result, err
		}
	}
	if expiry.Valid && expiry.Time.Before(result.ValidUntil) {
		result.ValidUntil = expiry.Time
	}
	amount, err := meterDecimal(available)
	if err != nil {
		return result, err
	}
	if amount.Sign() == 0 {
		result.Evidence = json.RawMessage(`{"balance":"zero"}`)
		return result, nil
	}
	var unsettled, snapshot string
	var rawCoverage []byte
	err = tx.QueryRow(ctx, fundingUnsettledCreditSQL, team, at, start, provider).Scan(&unsettled, &snapshot, &rawCoverage)
	if err != nil {
		return result, err
	}
	result.SpendableUSD, err = fundingNetSpendableUSD(available, unsettled)
	if err != nil {
		return result, err
	}
	if err = tx.Rollback(ctx); err != nil {
		return result, err
	}
	if verifyProvider != nil {
		var coverage []fundingPeriodReserve
		if err = json.Unmarshal(rawCoverage, &coverage); err != nil {
			return result, err
		}
		if err = verifyProvider(coverage); err != nil {
			return result, err
		}
	}
	result.Evidence, err = json.Marshal(map[string]any{"available_usd": available, "unsettled_usd": unsettled, "coverage": snapshot, "provider": providerEvidence, "observed_at": at})
	return result, err
}

func fundingNetSpendableUSD(available, unsettled string) (string, error) {
	a, err := meterDecimal(available)
	if err != nil {
		return "", err
	}
	u, err := meterDecimal(unsettled)
	if err != nil {
		return "", err
	}
	if a.Sign() < 0 || u.Sign() < 0 {
		return "", errors.New("negative funding credit accounting input")
	}
	net := new(big.Rat).Sub(a, u)
	if net.Sign() <= 0 {
		return "0.000000", nil
	}
	// Round availability down, including sub-micro-dollar live consumption.
	micros := new(big.Int).Quo(new(big.Int).Mul(net.Num(), big.NewInt(1000000)), net.Denom())
	return new(big.Rat).SetFrac(micros, big.NewInt(1000000)).FloatString(6), nil
}

// Closed periods have already debited the authoritative grant balance. The
// complement includes live usage and gaps where no billing-period row exists.
// Unknown corrections, missing prices and unbounded history cannot authorize
// usage. All sums stay numeric; rollups supply compute and exact billable
// storage uses the same activation intersection as invoice finalization.
const fundingUnsettledCreditSQL = `WITH periods AS MATERIALIZED (
 SELECT p.* FROM team_billing_period p WHERE team_id=$1 AND period_end>$3 AND period_start<$2
), bounds AS MATERIALIZED (
 SELECT LEAST($3,COALESCE(min(period_start) FILTER(WHERE finalized_at IS NULL),$3)) lo,$2::timestamptz hi FROM periods
), checks AS MATERIALIZED (
 SELECT hi-lo<=interval '400 days' AND (SELECT count(*) FROM periods)<=128
 AND NOT EXISTS(SELECT 1 FROM billing_export_correction c WHERE c.team_id=$1 AND c.period_end>lo)
 AND NOT EXISTS(SELECT 1 FROM periods p WHERE $4 AND p.finalized_at IS NOT NULL AND NOT EXISTS(
   SELECT 1 FROM billing_invoice_close j WHERE j.team_id=p.team_id AND j.period_start=p.period_start AND j.period_end=p.period_end AND j.state='released' AND billing_invoice_close_matches(j.team_id,j.period_start,j.period_end))) ok FROM bounds
), windows AS MATERIALIZED (
 SELECT lower(w) lo,upper(w) hi FROM bounds,checks,LATERAL unnest(tstzmultirange(tstzrange(lo,hi,'[)'))-
 COALESCE((SELECT range_agg(tstzrange(period_start,period_end,'[)')) FROM periods WHERE finalized_at IS NOT NULL),'{}'::tstzmultirange)) w WHERE checks.ok
), edges AS MATERIALIZED (
 SELECT lo edge FROM windows UNION SELECT hi FROM windows UNION SELECT period_start FROM periods UNION SELECT period_end FROM periods
), segments AS MATERIALIZED (
 SELECT edge lo,lead(edge) OVER(ORDER BY edge) hi FROM edges
), buckets AS MATERIALIZED (
 SELECT s.lo,s.hi FROM segments s WHERE s.hi>s.lo AND EXISTS(SELECT 1 FROM windows w WHERE s.lo>=w.lo AND s.hi<=w.hi)
), usage AS MATERIALIZED (
 SELECT u.bucket_start lo,u.bucket_end hi,u.vcpu_seconds cpu,u.memory_mib_seconds/1024 memory,
 billable_storage_mib_seconds($1,u.bucket_start,u.bucket_end)/1024 storage
 FROM billing_usage_from_rollups($1,(SELECT array_agg(lo ORDER BY lo) FROM buckets),(SELECT array_agg(hi ORDER BY lo) FROM buckets)) u
), cost AS (
 SELECT u.*,r.cpu_rate,r.memory_rate,r.storage_rate FROM usage u CROSS JOIN LATERAL (
 SELECT max(price_usd) FILTER(WHERE resource='vcpu') cpu_rate,max(price_usd) FILTER(WHERE resource='memory_gib') memory_rate,
 max(price_usd) FILTER(WHERE resource='storage_gib') storage_rate FROM (
 SELECT DISTINCT ON(resource) resource,price_usd FROM pricing_rate r JOIN pricing_plan pp ON pp.key=r.plan_key AND pp.active AND pp.currency='USD'
 WHERE r.plan_key=COALESCE((SELECT t.plan_key FROM team_pricing_plan t JOIN pricing_plan p ON p.key=t.plan_key AND p.active WHERE t.team_id=$1 AND t.effective_from<u.hi AND (t.effective_to IS NULL OR t.effective_to>=u.hi) ORDER BY t.effective_from DESC LIMIT 1),'payg')
 AND r.unit='second' AND r.effective_from<u.hi AND (r.effective_to IS NULL OR r.effective_to>=u.hi)
 ORDER BY resource,r.effective_from DESC,r.created_at DESC,r.id DESC) rates) r
)
SELECT CASE WHEN (SELECT ok FROM checks) AND NOT EXISTS(SELECT 1 FROM cost WHERE cpu_rate IS NULL OR memory_rate IS NULL OR (storage>0 AND storage_rate IS NULL) OR storage IS NULL)
 THEN CASE WHEN $4 THEN (COALESCE(sum(ceil(cpu*cpu_rate*100)+ceil(memory*memory_rate*100)+ceil(storage*COALESCE(storage_rate,0)*100)),0)/100)::text
 ELSE COALESCE(sum(cpu*cpu_rate+memory*memory_rate+storage*COALESCE(storage_rate,0)),0)::text END ELSE 'unknown' END,
 md5(COALESCE((SELECT jsonb_agg(to_jsonb(p) ORDER BY period_start)::text FROM periods p),'[]')),
 COALESCE(jsonb_agg(jsonb_build_object('start',lo,'end',hi,'reserved_usd',((ceil(cpu*cpu_rate*100)+ceil(memory*memory_rate*100)+ceil(storage*COALESCE(storage_rate,0)*100))/100)::text) ORDER BY lo),'[]'::jsonb) FROM cost`

func (h *Handlers) observeProviderFundingGrants(ctx context.Context, client *stripeHTTPClient, team uuid.UUID, customer string, at time.Time) (int64, time.Time, pgtype.Timestamptz, any, func([]fundingPeriodReserve) error, error) {
	var inventory struct {
		Data    []entitlementGrant `json:"data"`
		HasMore bool               `json:"has_more"`
	}
	var total int64
	start := at
	var expiry pgtype.Timestamptz
	fail := func(err error) (int64, time.Time, pgtype.Timestamptz, any, func([]fundingPeriodReserve) error, error) {
		return 0, at, expiry, nil, nil, err
	}
	if err := client.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+url.Values{"customer": {customer}, "limit": {"100"}}.Encode(), nil, &inventory, ""); err != nil {
		return fail(err)
	}
	if inventory.HasMore {
		return fail(errors.New("funding credit inventory exceeds observation bound"))
	}
	active := 0
	for _, grant := range inventory.Data {
		if grant.VoidedAt == 0 && grant.EffectiveAt <= at.Unix() && (grant.ExpiresAt == 0 || grant.ExpiresAt > at.Unix()) {
			active++
		}
	}
	// At most eight ledger reads plus sixteen stability reads per observation.
	// Expired historical grants do not consume this budget.
	if active > 8 {
		return fail(errors.New("active funding credit inventory exceeds observation bound"))
	}
	balances := map[string]int64{}
	providerBalances := map[string]fundingGrantBalance{}
	grants := map[string]entitlementGrant{}
	var requiredPrices []string
	for _, grant := range inventory.Data {
		if grant.ID == "" || grant.Customer != customer {
			return fail(errors.New("funding credit customer mismatch"))
		}
		if _, ok := grants[grant.ID]; ok {
			return fail(errors.New("duplicate funding credit grant"))
		}
		grants[grant.ID] = grant
		if grant.VoidedAt != 0 || grant.EffectiveAt > at.Unix() || grant.ExpiresAt != 0 && grant.ExpiresAt <= at.Unix() {
			continue
		}
		if grant.Applicability.Scope.PriceType != "metered" && requiredPrices == nil {
			var err error
			requiredPrices, err = h.fundingCreditResourcePrices(ctx, team, customer)
			if err != nil {
				return fail(err)
			}
		}
		if !fundingGrantCoversResources(grant, requiredPrices) {
			return fail(errors.New("funding credit applicability is unknown"))
		}
		providerBalance, err := fundingProviderGrantBalance(ctx, client, customer, grant.ID)
		if err != nil {
			return fail(err)
		}
		balance := providerBalance.Ledger
		if balance == 0 {
			continue
		}
		if balance > grant.Amount.Monetary.Value || total > int64(^uint64(0)>>1)-balance {
			return fail(errors.New("invalid funding credit ledger total"))
		}
		balances[grant.ID] = balance
		providerBalances[grant.ID] = providerBalance
		total += balance
		effective := grant.EffectiveAt
		if effective == 0 {
			effective = grant.Created
		}
		if effective <= 0 {
			return fail(errors.New("funding credit has no effective boundary"))
		}
		if time.Unix(effective, 0).Before(start) {
			start = time.Unix(effective, 0)
		}
		if grant.ExpiresAt > 0 && (!expiry.Valid || time.Unix(grant.ExpiresAt, 0).Before(expiry.Time)) {
			expiry = pgtype.Timestamptz{Valid: true, Time: time.Unix(grant.ExpiresAt, 0)}
		}
	}
	if total == 0 {
		return 0, start, expiry, balances, nil, nil
	}
	// Drafts may reserve grants for charges outside the measured sandbox ledger.
	// Creation can predate the grant, so inspect the entire draft inventory.
	var drafts struct {
		Data    []StripeInvoiceAmounts `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	if err := client.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"customer": {customer}, "status": {"draft"}, "limit": {"100"}}.Encode(), nil, &drafts, ""); err != nil {
		return fail(err)
	}
	if drafts.HasMore || len(drafts.Data) > 2 {
		return fail(errors.New("draft credit inventory exceeds observation bound"))
	}
	draftHashes := map[string]string{}
	for _, draft := range drafts.Data {
		if draft.ID == "" || draft.Customer != customer || draft.Status != "draft" || draft.BillingReason != "subscription_cycle" || draft.Lines.HasMore || len(draft.Lines.Data) > 5 || draftHashes[draft.ID] != "" {
			return fail(errors.New("draft credit reservations lack owned usage identity"))
		}
		draftHashes[draft.ID] = invoiceSettlementHash(draft)
	}
	var invoices struct {
		Data    []StripeInvoiceAmounts `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	if err := client.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"customer": {customer}, "limit": {"100"}, "created[gte]": {strconv.FormatInt(start.Unix(), 10)}}.Encode(), nil, &invoices, ""); err != nil {
		return fail(err)
	}
	if invoices.HasMore {
		return fail(errors.New("funding invoice inventory exceeds observation bound"))
	}
	for _, inv := range invoices.Data {
		if inv.Customer != customer || inv.ID == "" {
			return fail(errors.New("funding invoice identity mismatch"))
		}
		if inv.Status == "draft" {
			if draftHashes[inv.ID] != invoiceSettlementHash(inv) {
				return fail(errors.New("draft credit reservation changed during observation"))
			}
			continue
		}
		credits := false
		for _, credit := range inv.PretaxCredits {
			if credit.Type == "credit_balance_transaction" || credit.CreditBalanceTransaction != "" {
				credits = true
			}
		}
		if !credits {
			continue
		}
		var settled bool
		if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_invoice_close j JOIN team_billing_period p USING(team_id,period_start,period_end) WHERE j.team_id=$1 AND j.invoice_id=$2 AND j.state='released' AND p.finalized_at IS NOT NULL AND billing_invoice_close_matches(j.team_id,j.period_start,j.period_end))`, team, inv.ID).Scan(&settled); err != nil {
			return fail(err)
		}
		if !settled {
			return fail(errors.New("provider credit debit is not reconciled to local usage"))
		}
	}
	verify := func(coverage []fundingPeriodReserve) error {
		reserved := new(big.Int)
		for _, balance := range providerBalances {
			reserved.Add(reserved, big.NewInt(balance.Ledger-balance.Available))
		}
		attributed := new(big.Int)
		for _, draft := range drafts.Data {
			if err := h.validateFundingDraft(ctx, team, draft, coverage); err != nil {
				return err
			}
			for _, credit := range draft.PretaxCredits {
				if credit.Type == "credit_balance_transaction" || credit.CreditBalanceTransaction != "" {
					attributed.Add(attributed, big.NewInt(credit.Amount))
				}
			}
		}
		if reserved.Cmp(attributed) != 0 {
			return errors.New("grant reservations differ from attributed owned drafts")
		}
		for id, before := range balances {
			after, err := fundingProviderGrantBalance(ctx, client, customer, id)
			if err != nil {
				return err
			}
			if after.Ledger != before || after != providerBalances[id] {
				return errors.New("funding credit ledger changed during observation")
			}
			grant, err := client.retrieveEntitlementGrant(ctx, id)
			if err != nil {
				return err
			}
			a, _ := json.Marshal(grant)
			b, _ := json.Marshal(grants[id])
			if string(a) != string(b) {
				return errors.New("funding credit grant changed during observation")
			}
		}
		var current struct {
			Data    []StripeInvoiceAmounts `json:"data"`
			HasMore bool                   `json:"has_more"`
		}
		if err := client.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"customer": {customer}, "status": {"draft"}, "limit": {"100"}}.Encode(), nil, &current, ""); err != nil {
			return err
		}
		if current.HasMore || len(current.Data) != len(draftHashes) {
			return errors.New("draft credit inventory changed during observation")
		}
		for _, draft := range current.Data {
			if draft.Status != "draft" || draftHashes[draft.ID] != invoiceSettlementHash(draft) {
				return errors.New("draft credit reservation changed during observation")
			}
		}
		return nil
	}
	return total, start, expiry, balances, verify, nil
}

func (h *Handlers) validateFundingDraft(ctx context.Context, team uuid.UUID, inv StripeInvoiceAmounts, coverage []fundingPeriodReserve) error {
	var p billing.ExportPeriod
	p.TeamID = team
	var raw []byte
	err := h.Pool.QueryRow(ctx, `SELECT p.period_start,p.period_end,j.plan FROM billing_invoice_close j JOIN team_billing_period p USING(team_id,period_start,period_end)
 WHERE j.team_id=$1 AND j.invoice_id=$2 AND j.state IN ('prepared','adjusted','finalizing') AND p.finalized_at IS NULL
 AND j.plan->>'customer'=$3 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(j.plan->'resources') r WHERE r->'snapshot' IS DISTINCT FROM billing_meter_accounting_snapshot(j.team_id,j.period_start,j.period_end,r->>'resource'))`, team, inv.ID, inv.Customer).Scan(&p.Start, &p.End, &raw)
	if err != nil {
		return err
	}
	var plan billing.InvoiceClosePlan
	if err = json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	a, ok, err := h.invoiceAccountForPeriod(ctx, p)
	if err != nil {
		return err
	}
	if !ok || a.Customer != plan.Customer || a.Subscription != plan.Subscription {
		return errors.New("draft credit accounting identity changed")
	}
	return validateFundingDraftCoverage(inv, p, a, plan, coverage)
}

func validateFundingDraftCoverage(inv StripeInvoiceAmounts, p billing.ExportPeriod, a invoiceAccount, plan billing.InvoiceClosePlan, coverage []fundingPeriodReserve) error {
	if err := validateInvoiceDocument(inv, invoicePlanPeriod(p, plan), a, plan); err != nil {
		return err
	}
	amounts := map[string]int64{a.Price: max(plan.AdjustmentCents, 0)}
	for _, r := range plan.Resources {
		if r.ProviderCents < 0 {
			return errors.New("negative planned draft usage")
		}
		amounts[r.PriceID] = r.ProviderCents
	}
	gross := new(big.Int)
	lineCredits := new(big.Int)
	for _, line := range inv.Lines.Data {
		id := line.Pricing.PriceDetails.Price
		credits := new(big.Int)
		for _, credit := range line.PretaxCredits {
			if credit.Type == "credit_balance_transaction" || credit.CreditBalanceTransaction != "" {
				if credit.Amount < 0 {
					return errors.New("negative draft credit")
				}
				credits.Add(credits, big.NewInt(credit.Amount))
			}
		}
		if id == a.Base.Price && a.Base.Price != "" {
			if credits.Sign() != 0 {
				return errors.New("draft credit reserved for a licensed fee")
			}
			continue
		}
		if line.Amount != amounts[id] || credits.Cmp(big.NewInt(line.Amount)) > 0 {
			return errors.New("draft resource amount differs from accounted usage")
		}
		gross.Add(gross, big.NewInt(line.Amount))
		lineCredits.Add(lineCredits, credits)
	}
	aggregate := new(big.Int)
	for _, credit := range inv.PretaxCredits {
		if credit.Type == "credit_balance_transaction" || credit.CreditBalanceTransaction != "" {
			if credit.Amount < 0 {
				return errors.New("negative draft reservation")
			}
			aggregate.Add(aggregate, big.NewInt(credit.Amount))
		}
	}
	if aggregate.Cmp(lineCredits) != 0 {
		return errors.New("draft grant reservations lack line attribution")
	}
	reserved := new(big.Rat)
	coveredStart := p.Start
	for _, bucket := range coverage {
		if bucket.Start.Before(p.Start) || bucket.End.After(p.End) {
			continue
		}
		if !bucket.Start.Equal(coveredStart) {
			return errors.New("draft usage coverage is incomplete")
		}
		amount, err := meterDecimal(bucket.USD)
		if err != nil {
			return err
		}
		reserved.Add(reserved, amount)
		coveredStart = bucket.End
	}
	if !coveredStart.Equal(p.End) || reserved.Cmp(new(big.Rat).SetFrac(gross, big.NewInt(100))) < 0 {
		return errors.New("draft obligations exceed reserved outstanding usage")
	}
	return nil
}
