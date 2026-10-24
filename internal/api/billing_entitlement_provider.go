package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errCreditInventoryPending = errors.New("credit inventory pagination pending")

type entitlementGrant struct {
	ID          string `json:"id"`
	Customer    string `json:"customer"`
	Category    string `json:"category"`
	Created     int64  `json:"created"`
	EffectiveAt int64  `json:"effective_at"`
	ExpiresAt   int64  `json:"expires_at"`
	VoidedAt    int64  `json:"voided_at"`
	Priority    int64  `json:"priority"`
	Amount      struct {
		Type     string `json:"type"`
		Monetary struct {
			Currency string `json:"currency"`
			Value    int64  `json:"value"`
		} `json:"monetary"`
	} `json:"amount"`
	Applicability struct {
		Scope struct {
			PriceType string `json:"price_type,omitempty"`
			Prices    []struct {
				ID string `json:"id"`
			} `json:"prices,omitempty"`
		} `json:"scope"`
	} `json:"applicability_config"`
	Metadata map[string]string `json:"metadata"`
}

func (c *stripeHTTPClient) retrieveEntitlementGrant(ctx context.Context, id string) (entitlementGrant, error) {
	var g entitlementGrant
	err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants/"+url.PathEscape(id), nil, &g, "")
	if err == nil && g.ID != id {
		err = errors.New("credit grant identity changed")
	}
	return g, err
}

func (c *stripeHTTPClient) createCreditGrant(ctx context.Context, form url.Values, key string) (entitlementGrant, error) {
	var g entitlementGrant
	if err := c.doForm(ctx, http.MethodPost, "/v1/billing/credit_grants", form, &g, key); err != nil {
		return g, err
	}
	if g.ID == "" || g.Customer != form.Get("customer") {
		return g, errors.New("created grant identity differs from request")
	}
	if g.VoidedAt != 0 {
		return g, errors.New("created grant was voided; operator recovery required")
	}
	return g, nil
}

// The form is derived exclusively from the saved request, including omission of
// effective_at. Replays never substitute a new timestamp or idempotency key.
func entitlementGrantForm(raw []byte, expected []map[string]string) (url.Values, error) {
	var g entitlementGrant
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if g.Customer == "" || g.Category != "promotional" || g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value <= 0 || g.ExpiresAt <= 0 || (len(expected) < 3 || len(expected) > 4 || len(g.Applicability.Scope.Prices) != len(expected) || g.Applicability.Scope.PriceType != "") || g.Metadata["entitlement_id"] == "" {
		return nil, errors.New("incomplete saved entitlement request")
	}
	scope := map[string]bool{}
	for _, p := range expected {
		if p["id"] == "" || scope[p["id"]] {
			return nil, errors.New("invalid approved credit price scope")
		}
		scope[p["id"]] = true
	}
	for _, p := range g.Applicability.Scope.Prices {
		if !scope[p.ID] {
			return nil, errors.New("saved entitlement scope differs from approved resource and rounding prices")
		}
		delete(scope, p.ID)
	}
	v := url.Values{"customer": {g.Customer}, "category": {g.Category}, "amount[type]": {"monetary"}, "amount[monetary][currency]": {"usd"}, "amount[monetary][value]": {strconv.FormatInt(g.Amount.Monetary.Value, 10)}, "expires_at": {strconv.FormatInt(g.ExpiresAt, 10)}}
	if _, ok := fields["priority"]; ok {
		v.Set("priority", strconv.FormatInt(g.Priority, 10))
	}
	if _, ok := fields["effective_at"]; ok {
		v.Set("effective_at", strconv.FormatInt(g.EffectiveAt, 10))
	}
	for i, p := range g.Applicability.Scope.Prices {
		v.Set(fmt.Sprintf("applicability_config[scope][prices][%d][id]", i), p.ID)
	}
	for k, val := range g.Metadata {
		v.Set("metadata["+k+"]", val)
	}
	return v, nil
}

func (c *stripeHTTPClient) grantLedgerBalance(ctx context.Context, customer, id string) (int64, error) {
	var b struct {
		Balances []struct {
			Ledger struct {
				Monetary *struct {
					Currency string `json:"currency"`
					Value    int64  `json:"value"`
				} `json:"monetary"`
			} `json:"ledger_balance"`
		} `json:"balances"`
	}
	q := url.Values{"customer": {customer}, "filter[type]": {"credit_grant"}, "filter[credit_grant]": {id}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_balance_summary?"+q.Encode(), nil, &b, ""); err != nil {
		return 0, err
	}
	if len(b.Balances) != 1 || b.Balances[0].Ledger.Monetary == nil {
		return 0, errors.New("incomplete grant ledger")
	}
	m := b.Balances[0].Ledger.Monetary
	if m.Currency != "usd" || m.Value < 0 {
		return 0, errors.New("invalid grant ledger")
	}
	return m.Value, nil
}

// One page per invocation. Stripe list pagination is newest first; reaching the
// previously completed head finishes an incremental discovery pass. Existing
// candidate objects are retrieved again before they can authorize settlement.
func (h *Handlers) syncCreditInventory(ctx context.Context, contract uuid.UUID, customer string, client *stripeHTTPClient) error {
	var head, cursor, newHead *string
	if err := h.Pool.QueryRow(ctx, `SELECT inventory_head,inventory_cursor,inventory_new_head FROM billing_entitlement_work WHERE contract_id=$1`, contract).Scan(&head, &cursor, &newHead); err != nil {
		return err
	}
	q := url.Values{"customer": {customer}, "limit": {"50"}}
	if cursor != nil {
		q.Set("starting_after", *cursor)
	}
	var page struct {
		Data    []entitlementGrant `json:"data"`
		HasMore bool               `json:"has_more"`
	}
	if err := client.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+q.Encode(), nil, &page, ""); err != nil {
		return err
	}
	if page.HasMore && len(page.Data) == 0 {
		return errors.New("empty incomplete credit inventory")
	}
	done := !page.HasMore
	if cursor == nil && len(page.Data) > 0 {
		v := page.Data[0].ID
		newHead = &v
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var actualHead, actualCursor *string
	if err = tx.QueryRow(ctx, `SELECT inventory_head,inventory_cursor FROM billing_entitlement_work WHERE contract_id=$1 FOR UPDATE`, contract).Scan(&actualHead, &actualCursor); err != nil {
		return err
	}
	if derefString(head) != derefString(actualHead) || derefString(cursor) != derefString(actualCursor) {
		return errCreditInventoryPending
	}
	seen := map[string]bool{}
	for _, g := range page.Data {
		if g.ID == "" || g.Customer != customer || seen[g.ID] || (cursor != nil && g.ID == *cursor) {
			return errors.New("credit inventory identity mismatch")
		}
		seen[g.ID] = true
		if head != nil && g.ID == *head {
			done = true
			break
		}
		raw, e := json.Marshal(g)
		if e != nil {
			return e
		}
		_, err = tx.Exec(ctx, `INSERT INTO billing_provider_credit(customer_id,grant_id,evidence,effective_at,expires_at,entitlement_id) VALUES($1,$2,$3,$4,$5,NULLIF($6,'')) ON CONFLICT(customer_id,grant_id) DO UPDATE SET evidence=EXCLUDED.evidence,effective_at=EXCLUDED.effective_at,expires_at=EXCLUDED.expires_at,entitlement_id=EXCLUDED.entitlement_id,observed_at=clock_timestamp()`, customer, g.ID, raw, g.EffectiveAt, g.ExpiresAt, g.Metadata["entitlement_id"])
		if err != nil {
			return err
		}
	}
	if done {
		_, err = tx.Exec(ctx, `UPDATE billing_entitlement_work SET inventory_head=COALESCE($2,inventory_head),inventory_cursor=NULL,inventory_new_head=NULL,inventory_checked_at=clock_timestamp() WHERE contract_id=$1`, contract, newHead)
	} else {
		_, err = tx.Exec(ctx, `UPDATE billing_entitlement_work SET inventory_cursor=$2,inventory_new_head=$3 WHERE contract_id=$1`, contract, page.Data[len(page.Data)-1].ID, newHead)
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if !done {
		return errCreditInventoryPending
	}
	return nil
}

// Existence queries have no lifetime-history cost: any open or uncollectible
// invoice blocks issuance. Zero-dollar settlement must have reached paid.
func (c *stripeHTTPClient) entitlementDebt(ctx context.Context, customer string) (string, error) {
	for _, status := range []string{"open", "uncollectible"} {
		var page struct {
			Data    []struct{ ID, Customer, Status string } `json:"data"`
			HasMore bool                                    `json:"has_more"`
		}
		q := url.Values{"customer": {customer}, "status": {status}, "limit": {"1"}}
		if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+q.Encode(), nil, &page, ""); err != nil {
			return "", err
		}
		if len(page.Data) == 0 && page.HasMore {
			return "", errors.New("incomplete debt observation")
		}
		if len(page.Data) > 0 {
			inv := page.Data[0]
			if inv.ID == "" || inv.Customer != customer || inv.Status != status {
				return "", errors.New("debt invoice ownership mismatch")
			}
			return inv.ID, nil
		}
	}
	return "", nil
}

func checkedCreditSum(total, value int64) (int64, error) {
	if value < 0 || total < 0 || value > math.MaxInt64-total {
		return 0, errors.New("invalid credit total")
	}
	return total + value, nil
}

func (h *Handlers) creditInventoryReady(ctx context.Context, contract uuid.UUID, customer string, client *stripeHTTPClient) error {
	var checked *time.Time
	var cursor *string
	err := h.Pool.QueryRow(ctx, `SELECT inventory_checked_at,inventory_cursor FROM billing_entitlement_work WHERE contract_id=$1`, contract).Scan(&checked, &cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("credit inventory work is missing")
	}
	if err != nil {
		return err
	}
	if cursor != nil || checked == nil || time.Since(*checked) > 30*time.Second {
		return h.syncCreditInventory(ctx, contract, customer, client)
	}
	return nil
}
