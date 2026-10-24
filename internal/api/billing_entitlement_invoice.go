package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"

	"golang.org/x/sync/errgroup"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing"
)

func creditScope(g entitlementGrant, customer string, end int64, prices []string) error {
	if g.ID == "" || g.Customer != customer || g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value <= 0 || g.VoidedAt != 0 || g.EffectiveAt > end || (g.ExpiresAt != 0 && g.ExpiresAt <= end) {
		return errors.New("grant is ineligible for invoice")
	}
	if g.Priority != 50 {
		return errors.New("credit priorities must agree so earliest expiry is consumed first")
	}
	if g.Applicability.Scope.PriceType == "metered" && len(g.Applicability.Scope.Prices) == 0 {
		return nil
	}
	actual := []string{}
	for _, p := range g.Applicability.Scope.Prices {
		actual = append(actual, p.ID)
	}
	sort.Strings(actual)
	want := append([]string(nil), prices...)
	sort.Strings(want)
	if g.Applicability.Scope.PriceType != "" || !reflect.DeepEqual(actual, want) {
		return errors.New("credit grant scope differs from invoice usage and rounding prices")
	}
	return nil
}

func (h *Handlers) prepareEntitlementCredits(ctx context.Context, p billing.ExportPeriod, a invoiceAccount, invoiceID string, plan *billing.InvoiceClosePlan, client *stripeHTTPClient) error {
	var contract uuid.UUID
	var state, grantID string
	var withheld bool
	var platformFailure, adoptedEmpty bool
	err := h.Pool.QueryRow(ctx, `SELECT c.id,COALESCE(e.state,''),COALESCE(e.stripe_credit_grant_id,''),COALESCE(e.issuance_source='adopted' AND e.adopted_available_balance_cents=0,false),EXISTS(SELECT 1 FROM billing_entitlement_withheld w WHERE w.contract_id=c.id AND w.period_start=$2 AND w.period_end=$3),EXISTS(SELECT 1 FROM billing_entitlement_withheld w WHERE w.contract_id=c.id AND w.period_start=$2 AND w.platform_failure_at IS NOT NULL)
 FROM billing_commercial_contract c LEFT JOIN billing_usage_entitlement e ON e.contract_id=c.id AND e.period_start=$2 AND e.period_end=$3
 WHERE c.team_id=$1 AND c.customer_id=$4 AND c.subscription_id=$5 AND c.starts_at<=$2 AND (c.ends_at IS NULL OR c.ends_at>=$3)`, p.TeamID, p.Start, p.End, a.Customer, a.Subscription).Scan(&contract, &state, &grantID, &adoptedEmpty, &withheld, &platformFailure)
	if err != nil {
		return err
	}
	var revoked bool
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_yc_operation WHERE contract_id=$1 AND revoked_at<$2) OR EXISTS(SELECT 1 FROM billing_sponsored_operation WHERE contract_id=$1 AND revoked_at<$2)`, contract, p.End).Scan(&revoked); err != nil {
		return err
	}
	if revoked && state != "uncertain" && state != "issued" {
		state = ""
		withheld = true
	}
	if state != "issued" && (state != "" || !withheld) {
		return errors.New("expected period allowance is unresolved; invoice collection requires recovery")
	}
	if state == "" && platformFailure {
		return errors.New("recorded platform issuance failure requires allowance remediation")
	}
	if state == "" && withheld && !revoked {
		if err = h.verifyEntitlementForfeiture(ctx, contract, p, a, client); err != nil {
			return err
		}
	}
	if err = h.creditInventoryReady(ctx, contract, a.Customer, client); err != nil {
		return err
	}
	plan.CreditVersion = 1
	plan.CreditPrices = []string{a.Price}
	for _, r := range plan.Resources {
		plan.CreditPrices = append(plan.CreditPrices, r.PriceID)
	}
	sort.Strings(plan.CreditPrices)
	grants, err := h.eligibleInvoiceCredits(ctx, a.Customer, plan.InvoiceEnd, plan.CreditPrices, client)
	if err != nil {
		return err
	}
	found := grantID == ""
	for _, g := range grants {
		if g.ID == grantID {
			found = true
		}
		plan.CreditBeforeCents, err = checkedCreditSum(plan.CreditBeforeCents, g.Before)
		if err != nil {
			return err
		}
	}
	if !found && adoptedEmpty {
		// Zero balance was verified and recorded at operator adoption; there is no
		// promised remaining credit to replace or silently charge for.
		grant, e := client.retrieveEntitlementGrant(ctx, grantID)
		if e != nil {
			return e
		}
		if e = creditScope(grant, a.Customer, plan.InvoiceEnd, plan.CreditPrices); e != nil {
			return e
		}
		balance, e := client.grantLedgerBalance(ctx, a.Customer, grantID)
		if e != nil {
			return e
		}
		found = balance == 0
	}
	if !found {
		return errors.New("issued period allowance is absent from eligible credit inventory")
	}
	plan.CreditGrants = grants
	return client.rejectCompetingCreditInvoice(ctx, a.Customer, invoiceID, plan.InvoiceEnd)
}

func (h *Handlers) eligibleInvoiceCredits(ctx context.Context, customer string, end int64, prices []string, client *stripeHTTPClient) ([]billing.InvoiceCreditGrant, error) {
	ledger, inventory, err := h.creditScanVersion(ctx, customer, client)
	if err != nil {
		return nil, err
	}
	_, err = h.Pool.Exec(ctx, `INSERT INTO billing_invoice_credit_scan(customer_id,invoice_end,ledger_head,inventory_head) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, customer, end, ledger, inventory)
	if err != nil {
		return nil, err
	}
	var after, savedLedger, savedInventory string
	var saved []byte
	if err = h.Pool.QueryRow(ctx, `SELECT cursor,credits,ledger_head,inventory_head FROM billing_invoice_credit_scan WHERE customer_id=$1 AND invoice_end=$2`, customer, end).Scan(&after, &saved, &savedLedger, &savedInventory); err != nil {
		return nil, err
	}
	if ledger != savedLedger || inventory != savedInventory {
		return nil, h.restartInvoiceCreditScan(ctx, customer, end, after, ledger, inventory)
	}
	var result []billing.InvoiceCreditGrant
	if err = json.Unmarshal(saved, &result); err != nil {
		return nil, err
	}
	rows, err := h.Pool.Query(ctx, `SELECT grant_id FROM billing_provider_credit WHERE customer_id=$1 AND effective_at<=$2 AND (expires_at=0 OR expires_at>$2) AND grant_id>$3 ORDER BY grant_id LIMIT 51`, customer, end, after)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	more := len(ids) > 50
	if more {
		ids = ids[:50]
	}
	page, err := h.refreshInvoiceCredits(ctx, customer, end, prices, ids, client)
	if err != nil {
		return nil, err
	}
	result = append(result, page...)
	if len(result) > 200 {
		return nil, errors.New("positive eligible credit set exceeds per-invoice work budget; operator reconciliation required")
	}
	if more {
		raw, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		tag, err := h.Pool.Exec(ctx, `UPDATE billing_invoice_credit_scan SET cursor=$3,credits=$4 WHERE customer_id=$1 AND invoice_end=$2 AND cursor=$5`, customer, end, ids[len(ids)-1], raw, after)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() != 1 {
			return nil, errors.New("credit scan changed concurrently")
		}
		return nil, errCreditInventoryPending
	}
	// Earlier pages may be minutes old. Refresh all positive candidates together
	// before returning evidence that can authorize invoice finalization.
	if after != "" {
		positiveIDs := make([]string, len(result))
		for i, g := range result {
			positiveIDs[i] = g.ID
		}
		result, err = h.refreshInvoiceCredits(ctx, customer, end, prices, positiveIDs, client)
		if err != nil {
			return nil, err
		}
	}
	finalLedger, finalInventory, err := h.creditScanVersion(ctx, customer, client)
	if err != nil {
		return nil, err
	}
	if finalLedger != ledger || finalInventory != inventory {
		return nil, h.restartInvoiceCreditScan(ctx, customer, end, after, finalLedger, finalInventory)
	}
	tag, err := h.Pool.Exec(ctx, `DELETE FROM billing_invoice_credit_scan WHERE customer_id=$1 AND invoice_end=$2 AND cursor=$3`, customer, end, after)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, errors.New("credit scan changed concurrently")
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.ExpiresAt == b.ExpiresAt {
			return a.ID < b.ID
		}
		if a.ExpiresAt == 0 {
			return false
		}
		if b.ExpiresAt == 0 {
			return true
		}
		return a.ExpiresAt < b.ExpiresAt
	})
	return result, nil
}

func (c *stripeHTTPClient) rejectCompetingCreditInvoice(ctx context.Context, customer, id string, end int64) error {
	var page struct {
		Data    []StripeInvoiceAmounts `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	q := url.Values{"customer": {customer}, "status": {"draft"}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+q.Encode(), nil, &page, ""); err != nil {
		return err
	}
	if page.HasMore {
		return errors.New("too many concurrent draft invoices to establish credit isolation")
	}
	for _, inv := range page.Data {
		if inv.Customer != customer || inv.ID == "" {
			return errors.New("draft invoice inventory identity mismatch")
		}
		if inv.ID != id && inv.PeriodEnd <= end {
			return errors.New("another draft invoice can consume the closing period credits")
		}
	}
	return nil
}

func (h *Handlers) invoicePlanCredits(ctx context.Context, p billing.ExportPeriod, a invoiceAccount, plan billing.InvoiceClosePlan, inv *StripeInvoiceAmounts, client *stripeHTTPClient) (int64, error) {
	if plan.CreditVersion == 0 {
		return client.invoiceCreditLedger(ctx, a.Customer, invoicePlanPeriod(p, plan).End.Unix())
	}
	if plan.CreditVersion != 1 {
		return 0, errors.New("unsupported invoice credit plan")
	}
	if inv == nil {
		var invoiceID string
		if err := h.Pool.QueryRow(ctx, `SELECT invoice_id FROM billing_invoice_close WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&invoiceID); err != nil {
			return 0, err
		}
		if err := client.rejectCompetingCreditInvoice(ctx, a.Customer, invoiceID, plan.InvoiceEnd); err != nil {
			return 0, err
		}
		contract, err := h.invoiceCreditInventoryContract(ctx, p.TeamID, a)
		if err != nil {
			return 0, err
		}
		if err := h.syncCreditInventory(ctx, contract, a.Customer, client); err != nil {
			return 0, err
		}
		current, err := h.eligibleInvoiceCredits(ctx, a.Customer, plan.InvoiceEnd, plan.CreditPrices, client)
		if err != nil {
			return 0, err
		}
		if !sameInvoiceCreditGrants(current, plan.CreditGrants) {
			return 0, errors.New("eligible credits changed before invoice finalization")
		}
		return plan.CreditBeforeCents, nil
	}
	return client.verifyInvoiceCreditTransactions(ctx, *inv, plan)
}

type invoiceCreditTransaction struct {
	ID    string `json:"id"`
	Grant string `json:"credit_grant"`
	Type  string `json:"type"`
	Debit *struct {
		Type   string `json:"type"`
		Amount struct {
			Type     string `json:"type"`
			Monetary struct {
				Currency string `json:"currency"`
				Value    int64  `json:"value"`
			} `json:"monetary"`
		} `json:"amount"`
		Applied struct {
			Invoice string `json:"invoice"`
			Line    string `json:"invoice_line_item"`
		} `json:"credits_applied"`
	} `json:"debit"`
}

func (c *stripeHTTPClient) verifyInvoiceCreditTransactions(ctx context.Context, inv StripeInvoiceAmounts, plan billing.InvoiceClosePlan) (int64, error) {
	if inv.Lines.HasMore {
		return 0, errors.New("incomplete invoice credit lines")
	}
	grants := map[string]billing.InvoiceCreditGrant{}
	for _, g := range plan.CreditGrants {
		grants[g.ID] = g
	}
	applied := map[string]int64{}
	seen := map[string]int64{}
	lines := map[string]string{}
	for _, line := range inv.Lines.Data {
		for _, credit := range line.PretaxCredits {
			if credit.Type == "credit_balance_transaction" {
				if _, ok := seen[credit.CreditBalanceTransaction]; ok {
					return 0, errors.New("duplicate line credit transaction")
				}
				if credit.Amount <= 0 || credit.CreditBalanceTransaction == "" || line.Pricing.PriceDetails == nil {
					return 0, errors.New("invalid line credit")
				}
				allowed := false
				for _, price := range plan.CreditPrices {
					allowed = allowed || price == line.Pricing.PriceDetails.Price
				}
				if !allowed {
					return 0, errors.New("credit applied outside metered price scope")
				}
				seen[credit.CreditBalanceTransaction] = credit.Amount
				lines[credit.CreditBalanceTransaction] = line.ID
			}
		}
	}
	totalIDs := map[string]bool{}
	type expectedTransaction struct {
		ID     string
		Amount int64
	}
	var expectedTransactions []expectedTransaction
	for _, credit := range inv.PretaxCredits {
		if credit.Type != "credit_balance_transaction" {
			continue
		}
		if totalIDs[credit.CreditBalanceTransaction] || seen[credit.CreditBalanceTransaction] != credit.Amount || credit.Amount <= 0 {
			return 0, errors.New("invoice and line credit transactions disagree")
		}
		totalIDs[credit.CreditBalanceTransaction] = true
		expectedTransactions = append(expectedTransactions, expectedTransaction{credit.CreditBalanceTransaction, credit.Amount})
	}
	transactions := make([]invoiceCreditTransaction, len(expectedTransactions))
	fetch, work := errgroup.WithContext(ctx)
	fetch.SetLimit(8)
	for i, credit := range expectedTransactions {
		fetch.Go(func() error {
			tr := &transactions[i]
			if err := c.doForm(work, http.MethodGet, "/v1/billing/credit_balance_transactions/"+url.PathEscape(credit.ID), nil, tr, ""); err != nil {
				return err
			}
			d := tr.Debit
			if tr.ID != credit.ID || tr.Type != "debit" || d == nil || d.Type != "credits_applied" || d.Amount.Type != "monetary" || d.Amount.Monetary.Currency != "usd" || d.Amount.Monetary.Value != credit.Amount || d.Applied.Invoice != inv.ID || d.Applied.Line != lines[tr.ID] || grants[tr.Grant].ID == "" {
				return errors.New("credit transaction does not prove this invoice's grant application")
			}
			return nil
		})
	}
	if err := fetch.Wait(); err != nil {
		return 0, err
	}
	for _, tr := range transactions {
		sum, err := checkedCreditSum(applied[tr.Grant], tr.Debit.Amount.Monetary.Value)
		if err != nil {
			return 0, err
		}
		applied[tr.Grant] = sum
	}

	if len(totalIDs) != len(seen) {
		return 0, errors.New("line credit missing from invoice totals")
	}
	balances := make([]int64, len(plan.CreditGrants))
	fetch, work = errgroup.WithContext(ctx)
	fetch.SetLimit(8)
	for i, saved := range plan.CreditGrants {
		fetch.Go(func() error {
			grant, err := c.retrieveEntitlementGrant(work, saved.ID)
			if err != nil {
				return err
			}
			if err = creditScope(grant, plan.Customer, plan.InvoiceEnd, plan.CreditPrices); err != nil {
				return err
			}
			var original entitlementGrant
			if err = json.Unmarshal(saved.Evidence, &original); err != nil {
				return err
			}
			if !reflect.DeepEqual(grant, original) {
				return errors.New("grant changed during invoice settlement")
			}
			balance, err := c.grantLedgerBalance(work, plan.Customer, saved.ID)
			if err != nil {
				return err
			}
			if applied[saved.ID] > saved.Before || balance != saved.Before-applied[saved.ID] {
				return errors.New("grant ledger differs from invoice transactions")
			}
			balances[i] = balance
			return nil
		})
	}
	if err := fetch.Wait(); err != nil {
		return 0, err
	}
	remaining := int64(0)
	usage := plan.ExpectedCents
	// Validate earliest expiry by groups; ties may be applied in any provider order.
	for i := 0; i < len(plan.CreditGrants); {
		expiry := plan.CreditGrants[i].ExpiresAt
		groupBefore, groupApplied := int64(0), int64(0)
		for i < len(plan.CreditGrants) && plan.CreditGrants[i].ExpiresAt == expiry {
			saved := plan.CreditGrants[i]
			balance := balances[i]
			i++
			var err error
			remaining, err = checkedCreditSum(remaining, balance)
			if err != nil {
				return 0, err
			}
			groupBefore, err = checkedCreditSum(groupBefore, saved.Before)
			if err != nil {
				return 0, err
			}
			groupApplied, err = checkedCreditSum(groupApplied, applied[saved.ID])
			if err != nil {
				return 0, err
			}
		}
		expected := min(usage, groupBefore)
		if groupApplied != expected {
			return 0, fmt.Errorf("invoice did not apply earliest-expiring eligible credit: expected %d, applied %d", expected, groupApplied)
		}
		usage -= expected
	}
	return remaining, nil
}

// A debt first created after eligibility began cannot excuse an earlier missed grant.
func entitlementDebtSpansPeriod(inv StripeInvoiceAmounts, start, end int64) bool {
	payable := inv.StatusTransitions.FinalizedAt
	if payable <= 0 {
		return false
	}
	// Allow the normal held renewal to become payable just after the boundary.
	// Longer delays are platform incidents requiring explicit remediation.
	deadline := start
	if inv.BillingReason == "subscription_cycle" && inv.PeriodEnd == start {
		deadline += 300
	}
	if payable > deadline || payable >= end {
		return false
	}
	return inv.Status == "open" || inv.Status == "uncollectible" || (inv.Status == "paid" && inv.StatusTransitions.PaidAt >= end)
}
func (h *Handlers) verifyOwnedEntitlementGrant(ctx context.Context, g entitlementGrant) error {
	var raw []byte
	err := h.Pool.QueryRow(ctx, `SELECT e.issuance_evidence FROM billing_usage_entitlement e JOIN billing_commercial_contract c ON c.id=e.contract_id WHERE e.stripe_credit_grant_id=$1 AND c.customer_id=$2 AND e.state='issued'
 UNION ALL SELECT issuance_evidence FROM billing_matching_credit WHERE stripe_credit_grant_id=$1 AND customer_id=$2 AND state='issued'`, g.ID, g.Customer).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		if g.Metadata["entitlement_id"] != "" || g.Metadata["matching_credit_id"] != "" {
			return errors.New("unrecognized entitlement grant")
		}
		return nil
	}
	if err != nil {
		return err
	}
	var expected entitlementGrant
	if err = json.Unmarshal(raw, &expected); err != nil {
		return err
	}
	if !reflect.DeepEqual(g, expected) {
		return errors.New("owned grant changed from immutable issuance evidence")
	}
	return nil
}

func sameInvoiceCreditGrants(a, b []billing.InvoiceCreditGrant) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Before != b[i].Before || a[i].ExpiresAt != b[i].ExpiresAt {
			return false
		}
		var ga, gb entitlementGrant
		if json.Unmarshal(a[i].Evidence, &ga) != nil || json.Unmarshal(b[i].Evidence, &gb) != nil || !reflect.DeepEqual(ga, gb) {
			return false
		}
	}
	return true
}

// Preserve each blocking invoice: a newer bill must not erase older nonpayment.
func (h *Handlers) verifyEntitlementForfeiture(ctx context.Context, contract uuid.UUID, p billing.ExportPeriod, a invoiceAccount, client *stripeHTTPClient) error {
	rows, err := h.Pool.Query(ctx, `SELECT invoice_id FROM billing_entitlement_debt WHERE contract_id=$1 AND period_start=$2 ORDER BY observed_at,invoice_id LIMIT 201`, contract, p.Start)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(ids) > 200 {
		return errors.New("period debt evidence exceeds work budget; operator recovery required")
	}
	// Oldest observed debt usually proves the entire interval in one request.
	for _, id := range ids {
		inv, err := client.RetrieveBillingInvoice(ctx, id)
		if err != nil {
			return err
		}
		if inv.ID != id || inv.Customer != a.Customer {
			return errors.New("withheld entitlement debt ownership changed")
		}
		if inv.BillingReason == "subscription_cycle" && inv.PeriodEnd == p.Start.Unix() && (inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != a.Subscription) {
			continue
		}
		if entitlementDebtSpansPeriod(inv, p.Start.Unix(), p.End.Unix()) {
			return nil
		}
	}
	return h.discoverEntitlementForfeiture(ctx, contract, p, a, client)
}

// A scheduled cycle invoice cannot precede its service interval. There is no
// upper creation cutoff: provider delays must remain discoverable after recovery.
func (h *Handlers) billingCycleInvoice(ctx context.Context, a invoiceAccount, start, end int64, c *stripeHTTPClient) (StripeInvoiceAmounts, error) {
	empty := StripeInvoiceAmounts{}
	_, err := h.Pool.Exec(ctx, `INSERT INTO billing_invoice_discovery(customer_id,subscription_id,period_start,period_end) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, a.Customer, a.Subscription, start, end)
	if err != nil {
		return empty, err
	}
	var after, match string
	err = h.Pool.QueryRow(ctx, `SELECT cursor,match_id FROM billing_invoice_discovery WHERE customer_id=$1 AND subscription_id=$2 AND period_start=$3 AND period_end=$4`, a.Customer, a.Subscription, start, end).Scan(&after, &match)
	if err != nil {
		return empty, err
	}
	if after == "" {
		match = ""
	}
	var list struct {
		Data    []StripeInvoiceAmounts `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	q := url.Values{"subscription": {a.Subscription}, "limit": {"100"}, "created[gte]": {strconv.FormatInt(start, 10)}}
	if after != "" {
		q.Set("starting_after", after)
	}
	if err = c.doForm(ctx, http.MethodGet, "/v1/invoices?"+q.Encode(), nil, &list, ""); err != nil {
		return empty, err
	}
	for _, inv := range list.Data {
		if inv.ID == "" || inv.Customer != a.Customer {
			return empty, errors.New("invoice inventory ownership mismatch")
		}
		if inv.BillingReason == "subscription_cycle" && inv.Status != "void" && inv.PeriodStart == start && inv.PeriodEnd == end {
			if match != "" && match != inv.ID {
				return empty, errors.New("multiple cycle invoices for period")
			}
			match = inv.ID
		}
	}
	next := ""
	if list.HasMore {
		if len(list.Data) == 0 {
			return empty, errors.New("incomplete invoice inventory page")
		}
		next = list.Data[len(list.Data)-1].ID
		if next == after {
			return empty, errors.New("invoice discovery cursor did not advance")
		}
	}
	tag, err := h.Pool.Exec(ctx, `UPDATE billing_invoice_discovery SET cursor=$5,match_id=$6 WHERE customer_id=$1 AND subscription_id=$2 AND period_start=$3 AND period_end=$4 AND cursor=$7`, a.Customer, a.Subscription, start, end, next, match, after)
	if err != nil {
		return empty, err
	}
	if tag.RowsAffected() != 1 {
		return empty, errors.New("invoice discovery changed concurrently")
	}
	if list.HasMore {
		return empty, errors.New("invoice discovery continuing from saved cursor")
	}
	if match == "" {
		return empty, errors.New("waiting for the scheduled renewal invoice")
	}
	inv, err := c.RetrieveBillingInvoice(ctx, match)
	if err != nil {
		return inv, err
	}
	if inv.Customer != a.Customer || inv.ID != match || inv.Currency != "usd" || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != a.Subscription || inv.PeriodStart != start || inv.PeriodEnd != end || inv.Status == "void" || inv.BillingReason != "subscription_cycle" {
		return inv, errors.New("invoice association changed")
	}
	return inv, nil
}

func (h *Handlers) refreshInvoiceCredits(ctx context.Context, customer string, end int64, prices, ids []string, client *stripeHTTPClient) ([]billing.InvoiceCreditGrant, error) {
	slots := make([]*billing.InvoiceCreditGrant, len(ids))
	group, work := errgroup.WithContext(ctx)
	group.SetLimit(8)
	for i, id := range ids {
		group.Go(func() error {
			g, e := client.retrieveEntitlementGrant(work, id)
			if e != nil {
				return e
			}
			if g.Customer != customer {
				return errors.New("credit grant customer changed")
			}
			if g.VoidedAt != 0 || g.EffectiveAt > end || (g.ExpiresAt != 0 && g.ExpiresAt <= end) {
				return nil
			}
			if e = h.verifyOwnedEntitlementGrant(work, g); e != nil {
				return e
			}
			balance, e := client.grantLedgerBalance(work, customer, id)
			if e != nil {
				return e
			}
			if balance == 0 {
				return nil
			}
			if e = creditScope(g, customer, end, prices); e != nil {
				return e
			}
			raw, e := json.Marshal(g)
			if e != nil {
				return e
			}
			slots[i] = &billing.InvoiceCreditGrant{ID: id, Before: balance, ExpiresAt: g.ExpiresAt, Evidence: raw}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	result := []billing.InvoiceCreditGrant{}
	for _, g := range slots {
		if g != nil {
			result = append(result, *g)
		}
	}
	return result, nil
}

// A bounded existence check is enough to block issuance, but not to attribute a
// whole missed period. Search older invoices when saved observations lack proof.
func (h *Handlers) discoverEntitlementForfeiture(ctx context.Context, contract uuid.UUID, p billing.ExportPeriod, a invoiceAccount, client *stripeHTTPClient) error {
	var after string
	if err := h.Pool.QueryRow(ctx, `SELECT COALESCE(evidence->>'forfeiture_cursor','') FROM billing_entitlement_withheld WHERE contract_id=$1 AND period_start=$2`, contract, p.Start).Scan(&after); err != nil {
		return err
	}
	q := url.Values{"customer": {a.Customer}, "limit": {"50"}, "created[lte]": {strconv.FormatInt(p.Start.Unix()+300, 10)}}
	if after != "" {
		q.Set("starting_after", after)
	}
	var page struct {
		Data    []StripeInvoiceAmounts `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	if err := client.doForm(ctx, http.MethodGet, "/v1/invoices?"+q.Encode(), nil, &page, ""); err != nil {
		return err
	}
	invoices := make([]StripeInvoiceAmounts, len(page.Data))
	fetch, work := errgroup.WithContext(ctx)
	fetch.SetLimit(8)
	for i, candidate := range page.Data {
		fetch.Go(func() error {
			if candidate.ID == "" || candidate.Customer != a.Customer {
				return errors.New("historical debt inventory ownership mismatch")
			}
			inv, err := client.RetrieveBillingInvoice(work, candidate.ID)
			if err != nil {
				return err
			}
			if inv.ID != candidate.ID || inv.Customer != a.Customer {
				return errors.New("historical debt ownership mismatch")
			}
			invoices[i] = inv
			return nil
		})
	}
	if err := fetch.Wait(); err != nil {
		return err
	}
	for _, inv := range invoices {
		if inv.BillingReason == "subscription_cycle" && inv.PeriodEnd == p.Start.Unix() && (inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != a.Subscription) {
			continue
		}
		if entitlementDebtSpansPeriod(inv, p.Start.Unix(), p.End.Unix()) {
			_, err := h.Pool.Exec(ctx, `INSERT INTO billing_entitlement_debt(contract_id,period_start,invoice_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, contract, p.Start, inv.ID)
			return err
		}
	}
	next := ""
	if page.HasMore {
		if len(page.Data) == 0 {
			return errors.New("incomplete historical debt page")
		}
		next = page.Data[len(page.Data)-1].ID
		if next == after {
			return errors.New("historical debt cursor did not advance")
		}
	}
	tag, err := h.Pool.Exec(ctx, `UPDATE billing_entitlement_withheld SET evidence=jsonb_set(evidence,'{forfeiture_cursor}',to_jsonb($3::text)) WHERE contract_id=$1 AND period_start=$2 AND COALESCE(evidence->>'forfeiture_cursor','')=$4`, contract, p.Start, next, after)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("historical debt discovery changed concurrently")
	}
	if page.HasMore {
		return errCreditInventoryPending
	}
	return errors.New("missing allowance lacks full-period nonpayment evidence; operator recovery required")
}

// Stripe's reverse-chronological list heads fence ledger and inventory changes,
// including reinstated zero balances and new grants behind the local page cursor.
func (h *Handlers) creditScanVersion(ctx context.Context, customer string, client *stripeHTTPClient) (string, string, error) {
	heads := make([]string, 2)
	for i, path := range []string{"credit_balance_transactions", "credit_grants"} {
		var page struct {
			Data *[]struct {
				ID string `json:"id"`
			} `json:"data"`
			HasMore bool `json:"has_more"`
		}
		q := url.Values{"customer": {customer}, "limit": {"1"}}
		if err := client.doForm(ctx, http.MethodGet, "/v1/billing/"+path+"?"+q.Encode(), nil, &page, ""); err != nil {
			return "", "", err
		}
		if page.Data == nil || len(*page.Data) > 1 || (page.HasMore && len(*page.Data) == 0) {
			return "", "", errors.New("incomplete credit scan version")
		}
		if len(*page.Data) == 1 {
			heads[i] = (*page.Data)[0].ID
			if heads[i] == "" {
				return "", "", errors.New("empty credit scan version identity")
			}
		}
	}
	var indexed bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_entitlement_work w JOIN billing_commercial_contract c ON c.id=w.contract_id WHERE c.customer_id=$1 AND w.inventory_cursor IS NULL AND w.inventory_checked_at IS NOT NULL AND COALESCE(w.inventory_head,'')=$2)`, customer, heads[1]).Scan(&indexed); err != nil {
		return "", "", err
	}
	if !indexed {
		return "", "", errCreditInventoryPending
	}
	return heads[0], heads[1], nil
}
func (h *Handlers) restartInvoiceCreditScan(ctx context.Context, customer string, end int64, after, ledger, inventory string) error {
	tag, err := h.Pool.Exec(ctx, `UPDATE billing_invoice_credit_scan SET cursor='',credits='[]',ledger_head=$4,inventory_head=$5 WHERE customer_id=$1 AND invoice_end=$2 AND cursor=$3`, customer, end, after, ledger, inventory)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("credit scan changed concurrently")
	}
	return errCreditInventoryPending
}
