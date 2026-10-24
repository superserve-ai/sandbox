package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Purchased credit is the customer's money: it never expires and covers all
// metered usage, so it carries over unchanged to any later plan.
func prepaidCreditRequest(id uuid.UUID, customer string, amount int64, source string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"customer": customer, "category": "paid", "name": "Prepaid credit",
		"amount":               map[string]any{"type": "monetary", "monetary": map[string]any{"currency": "usd", "value": amount}},
		"priority":             50,
		"applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}},
		"metadata":             map[string]string{"prepaid_purchase_id": id.String(), "source": source},
	})
}

func prepaidGrantForm(raw []byte) (url.Values, error) {
	var g entitlementGrant
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var name string
	if err := json.Unmarshal(fields["name"], &name); err != nil {
		return nil, err
	}
	if g.Customer == "" || g.Category != "paid" || g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value <= 0 || g.Priority != 50 || g.ExpiresAt != 0 || g.EffectiveAt != 0 || g.Applicability.Scope.PriceType != "metered" || len(g.Applicability.Scope.Prices) != 0 || g.Metadata["prepaid_purchase_id"] == "" || g.Metadata["source"] == "" || len(g.Metadata) != 2 || name == "" {
		return nil, errors.New("incomplete saved prepaid credit request")
	}
	return url.Values{
		"customer": {g.Customer}, "category": {"paid"}, "name": {name},
		"amount[type]": {"monetary"}, "amount[monetary][currency]": {"usd"}, "amount[monetary][value]": {strconv.FormatInt(g.Amount.Monetary.Value, 10)},
		"priority": {"50"}, "applicability_config[scope][price_type]": {"metered"},
		"metadata[prepaid_purchase_id]": {g.Metadata["prepaid_purchase_id"]}, "metadata[source]": {g.Metadata["source"]},
	}, nil
}

// issuePrepaidCredit turns a verified payment into exactly one grant. It runs
// inside the invoice closer's fence for the same reason matching credit does.
func (h *Handlers) issuePrepaidCredit(ctx context.Context, client *stripeHTTPClient, id uuid.UUID) error {
	var team uuid.UUID
	var customer, source, key, paymentState, creditState string
	var amount int64
	if err := h.Pool.QueryRow(ctx, `SELECT team_id,customer_id,source,amount_cents,credit_idempotency_key,payment_state,credit_state FROM billing_prepaid_purchase WHERE id=$1`, id).
		Scan(&team, &customer, &source, &amount, &key, &paymentState, &creditState); err != nil {
		return err
	}
	if paymentState != "succeeded" || creditState == "issued" {
		return nil
	}
	if creditState == "none" {
		request, err := prepaidCreditRequest(id, customer, amount, source)
		if err != nil {
			return err
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET credit_state='pending',credit_request=$2 WHERE id=$1 AND credit_state='none'`, id, request); err != nil {
			return err
		}
	}
	release, err := h.holdCreditIssuanceFence(ctx, team)
	if err != nil {
		return err
	}
	defer release()
	var payload []byte
	var first *time.Time
	err = h.Pool.QueryRow(ctx, `UPDATE billing_prepaid_purchase SET credit_state='uncertain',credit_first_attempt_at=COALESCE(credit_first_attempt_at,clock_timestamp())
 WHERE id=$1 AND credit_state IN ('pending','uncertain') RETURNING credit_request,credit_first_attempt_at`, id).Scan(&payload, &first)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if first == nil || time.Since(*first) >= 23*time.Hour {
		grant, found, err := client.findCreditGrantByMetadata(ctx, customer, "prepaid_purchase_id", id.String())
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("prepaid credit outcome unknown after the replay window; operator recovery required")
		}
		return h.confirmPrepaidCredit(ctx, id, grant)
	}
	form, err := prepaidGrantForm(payload)
	if err != nil {
		return err
	}
	grant, err := client.createCreditGrant(ctx, form, key)
	if err != nil {
		return err
	}
	return h.confirmPrepaidCredit(ctx, id, grant)
}

func (h *Handlers) confirmPrepaidCredit(ctx context.Context, id uuid.UUID, grant entitlementGrant) error {
	if grant.VoidedAt != 0 {
		return errors.New("prepaid credit grant was voided; operator recovery required")
	}
	raw, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET credit_state='issued',stripe_credit_grant_id=$2,credit_evidence=$3,credited_at=clock_timestamp() WHERE id=$1 AND credit_state='uncertain'`, id, grant.ID, raw); err != nil {
		return err
	}
	_, err = h.Pool.Exec(ctx, `UPDATE billing_funding_account f SET next_check_at=LEAST(f.next_check_at,clock_timestamp()) FROM billing_prepaid_purchase p WHERE p.id=$1 AND f.team_id=p.team_id AND f.observe`, id)
	return err
}

// Teams without a commercial contract have no indexed grant inventory, so an
// ambiguous outcome is settled by reading the customer's grants directly.
func (c *stripeHTTPClient) findCreditGrantByMetadata(ctx context.Context, customer, key, value string) (entitlementGrant, bool, error) {
	var found []entitlementGrant
	cursor := ""
	for page := 0; page < 20; page++ {
		q := url.Values{"customer": {customer}, "limit": {"100"}}
		if cursor != "" {
			q.Set("starting_after", cursor)
		}
		var list struct {
			Data    []entitlementGrant `json:"data"`
			HasMore bool               `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+q.Encode(), nil, &list, ""); err != nil {
			return entitlementGrant{}, false, err
		}
		for _, g := range list.Data {
			if g.Customer != customer {
				return entitlementGrant{}, false, errors.New("credit grant inventory ownership mismatch")
			}
			if g.Metadata[key] == value {
				found = append(found, g)
			}
		}
		if !list.HasMore {
			if len(found) > 1 {
				return entitlementGrant{}, false, errors.New("multiple grants carry one purchase identity; operator recovery required")
			}
			if len(found) == 1 {
				return found[0], true, nil
			}
			return entitlementGrant{}, false, nil
		}
		if len(list.Data) == 0 {
			return entitlementGrant{}, false, errors.New("empty incomplete credit grant page")
		}
		cursor = list.Data[len(list.Data)-1].ID
	}
	return entitlementGrant{}, false, errors.New("credit grant inventory exceeds the discovery bound")
}
