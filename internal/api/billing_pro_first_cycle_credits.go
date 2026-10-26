package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

// The recurring contract begins next month. Its paid predecessor operation,
// rather than a fabricated recurring payment, authorizes this first allowance.
func firstProCycleAuthority(ctx context.Context, reader db.DBTX, team uuid.UUID, a invoiceAccount) (proUpgrade, bool, error) {
	u, err := scanProUpgrade(reader.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3 AND request_payload->>'FirstPaidProCycle'='true' ORDER BY quoted_at DESC LIMIT 1`, team, a.Customer, a.Subscription))
	if errors.Is(err, pgx.ErrNoRows) {
		return u, false, nil
	}
	if err != nil {
		return u, true, err
	}
	if u.Contract == nil || (u.State != "credited" && u.State != "active" && u.State != "ended") || u.Grant == nil || len(u.Evidence) == 0 || !json.Valid(u.Evidence) {
		return u, true, errors.New("first Pro month payment or allowance is unresolved")
	}
	var p StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(u.Payload, &p); err != nil {
		return u, true, err
	}
	if _, err = u.creditExpiry(); err != nil {
		return u, true, err
	}
	var valid bool
	err = reader.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract c
 WHERE c.id=$1 AND c.team_id=$2 AND c.customer_id=$3 AND c.subscription_id=$4 AND c.base_price_id=$5
 AND c.charge_amount_cents=$6 AND c.charge_interval_months=1 AND c.entitlement_amount_cents=$7 AND c.entitlement_anchor=$8 AND c.starts_at=$9
 AND EXISTS(SELECT 1 FROM team_plan_assignment t WHERE t.team_id=c.team_id AND t.contract_id=c.id AND t.source='checkout' AND t.idempotency_key='checkout:'||c.id::text AND t.plan_version_id=$10))
 AND NOT EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE id=$11 AND payment_review_required)`, u.Contract, team, a.Customer, a.Subscription, p.BasePriceID, p.PlanTerms.Amount, p.PlanTerms.Credit, u.Anchor, u.End, p.PlanTerms.VersionID, u.ID).Scan(&valid)
	if err != nil {
		return u, true, err
	}
	if !valid {
		return u, true, errors.New("first Pro month contract or assignment differs from paid terms")
	}
	return u, true, nil
}

func validateFirstProCycleGrant(u proUpgrade, g entitlementGrant) error {
	expires, err := u.creditExpiry()
	if err != nil {
		return err
	}
	if g.ID != derefString(u.Grant) || g.Customer != u.Customer || g.Category != "paid" || g.Priority != 50 || g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value != u.bridgeCreditAmount() || g.ExpiresAt != expires || g.VoidedAt != 0 || (expires > 0 && g.EffectiveAt > u.End.Unix()) || g.Applicability.Scope.PriceType != "metered" || len(g.Applicability.Scope.Prices) != 0 || g.Metadata["pro_upgrade_id"] != u.ID.String() {
		return errors.New("first Pro month allowance is missing or differs from paid terms")
	}
	return nil
}

func verifyFirstProCycleGrant(ctx context.Context, u proUpgrade, client *stripeHTTPClient) (entitlementGrant, error) {
	g, err := client.retrieveEntitlementGrant(ctx, derefString(u.Grant))
	if err != nil {
		return g, err
	}
	return g, validateFirstProCycleGrant(u, g)
}

func (h *Handlers) verifyOwnedFirstProCycleGrant(ctx context.Context, g entitlementGrant) error {
	u, err := scanProUpgrade(h.Pool.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE customer_id=$1 AND (grant_id=$2 OR id::text=$3)`, g.Customer, g.ID, g.Metadata["pro_upgrade_id"]))
	if errors.Is(err, pgx.ErrNoRows) {
		if g.Metadata["pro_upgrade_id"] != "" {
			return errors.New("Pro upgrade allowance lacks frozen local authority")
		}
		return nil
	}
	if err != nil {
		return err
	}
	// Locally recognized unmarked upgrades retain their original non-expiring
	// bridge terms; the same frozen amount and grant identity still apply.
	return validateFirstProCycleGrant(u, g)
}

func (h *Handlers) preflightFirstProCycleCredits(ctx context.Context, team uuid.UUID, a invoiceAccount, client *stripeHTTPClient, reader db.DBTX) (bool, error) {
	u, found, err := firstProCycleAuthority(ctx, reader, team, a)
	if err != nil || !found {
		return found, err
	}
	if _, err = verifyFirstProCycleGrant(ctx, u, client); err != nil {
		return true, err
	}
	sub, err := client.invoiceSubscription(ctx, a.Subscription)
	if err != nil {
		return true, err
	}
	if sub.ID != a.Subscription || sub.Customer != a.Customer {
		return true, errors.New("first Pro month subscription identity differs")
	}
	if err = validateFirstProCycleProviderCalendar(u.ID, u.Anchor, sub); err != nil {
		return true, err
	}

	prices := []string{a.Price}
	for _, item := range sub.Items.Data {
		if item.Price.ID != a.Price && item.Price.ID != a.Base.Price {
			prices = append(prices, item.Price.ID)
		}
	}
	sort.Strings(prices)
	// Enrollment holds the account transaction. Use provider-only reads here;
	// durable inventory refresh and invoice isolation happen outside that lock.
	var page struct {
		Data    []entitlementGrant `json:"data"`
		HasMore bool               `json:"has_more"`
	}
	query := url.Values{"customer": {a.Customer}, "limit": {"100"}}
	if err = client.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+query.Encode(), nil, &page, ""); err != nil {
		return true, err
	}
	if page.HasMore || len(page.Data) > 100 {
		return true, errors.New("first Pro month credit preflight exceeds inventory bound")
	}
	seen := map[string]bool{}
	foundGrant := false
	for _, g := range page.Data {
		if g.ID == "" || g.Customer != a.Customer || seen[g.ID] {
			return true, errors.New("first Pro month credit inventory identity differs")
		}
		seen[g.ID] = true
		foundGrant = foundGrant || g.ID == derefString(u.Grant)
		at := h.nowUTC().Unix()
		if g.VoidedAt != 0 || g.EffectiveAt > at || (g.ExpiresAt != 0 && g.ExpiresAt <= at) {
			continue
		}
		balance, balanceErr := client.grantLedgerBalance(ctx, a.Customer, g.ID)
		if balanceErr != nil {
			return true, balanceErr
		}
		if balance == 0 {
			continue
		}
		if err = creditScope(g, a.Customer, at, prices); err != nil {
			return true, err
		}
	}
	if !foundGrant {
		return true, errors.New("first Pro month allowance is absent from provider inventory")
	}
	return true, nil
}

func (h *Handlers) prepareFirstProCycleCredits(ctx context.Context, p billing.ExportPeriod, a invoiceAccount, invoiceID string, plan *billing.InvoiceClosePlan, client *stripeHTTPClient) (bool, error) {
	u, found, err := firstProCycleAuthority(ctx, h.Pool, p.TeamID, a)
	if err != nil || !found {
		return found, err
	}
	if !p.Start.Before(u.End) {
		return false, nil
	}
	if !p.Start.Equal(u.Start) || !p.End.Equal(u.End) || plan.InvoiceEnd != u.End.Unix() {
		return true, errors.New("first Pro month invoice differs from the paid service period")
	}
	g, err := verifyFirstProCycleGrant(ctx, u, client)
	if err != nil {
		return true, err
	}
	if err = h.fundingCreditInventoryReady(ctx, *u.Contract, a.Customer, client); err != nil {
		return true, err
	}
	plan.CreditVersion = 1
	plan.CreditPrices = []string{a.Price}
	for _, r := range plan.Resources {
		plan.CreditPrices = append(plan.CreditPrices, r.PriceID)
	}
	sort.Strings(plan.CreditPrices)
	grants, err := h.eligibleInvoiceCredits(ctx, a.Customer, plan.InvoiceEnd, plan.CreditPrices, client)
	if err != nil {
		return true, err
	}
	balance, err := client.grantLedgerBalance(ctx, a.Customer, g.ID)
	if err != nil {
		return true, err
	}
	promised := balance == 0
	plan.CreditBeforeCents = 0
	for _, grant := range grants {
		promised = promised || (grant.ID == g.ID && grant.Before == balance)
		plan.CreditBeforeCents, err = checkedCreditSum(plan.CreditBeforeCents, grant.Before)
		if err != nil {
			return true, err
		}
	}
	if !promised {
		return true, errors.New("first Pro month allowance is absent from eligible invoice credits")
	}
	plan.CreditGrants = grants
	return true, client.rejectCompetingCreditInvoice(ctx, a.Customer, invoiceID, plan.InvoiceEnd)
}
