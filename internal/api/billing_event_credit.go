package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

// recordEventCredit queues an event's extra usage credit when a checkout used
// one of its promotion codes. Stripe refuses an expired code at checkout, so a
// completed checkout carrying one is eligible however late it is processed. A
// team gets one credit per event.
func recordEventCredit(ctx context.Context, tx pgx.Tx, team, contract uuid.UUID, customer, promotionCode string) error {
	if promotionCode == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO billing_event_credit(contract_id,team_id,customer_id,promotion_code,label,credit_cents)
 SELECT $1,$2,$3,p.promotion_code,p.label,p.credit_cents FROM billing_event_promotion p WHERE p.promotion_code=$4
 ON CONFLICT DO NOTHING`, contract, team, customer, promotionCode)
	return err
}

// The grant matches scripts/billing/event_credit.py, including its key, so a
// manual run for the same team and label cannot add a second credit.
func eventGrantForm(team uuid.UUID, customer, label string, cents int64) url.Values {
	return url.Values{
		"customer": {customer}, "category": {"promotional"}, "name": {"Event credit"},
		"amount[type]": {"monetary"}, "amount[monetary][currency]": {"usd"}, "amount[monetary][value]": {strconv.FormatInt(cents, 10)},
		"priority": {"50"}, "applicability_config[scope][price_type]": {"metered"},
		"metadata[event_label]": {label}, "metadata[team_id]": {team.String()},
	}
}

func eventGrantKey(team uuid.UUID, label string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, `[%q, %q]`, team.String(), label))
	return "event-credit-" + hex.EncodeToString(sum[:])
}

func (h *Handlers) issueDueEventCredits(ctx context.Context, client *stripeHTTPClient) error {
	rows, err := h.Pool.Query(ctx, `SELECT contract_id FROM billing_event_credit WHERE state<>'issued' AND next_attempt_at<=clock_timestamp() ORDER BY next_attempt_at LIMIT 20`)
	if err != nil {
		return err
	}
	var due []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		due = append(due, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	var errs []error
	for _, id := range due {
		issueErr := h.issueEventCredit(ctx, client, id)
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		switch {
		case issueErr == nil:
			_, err = h.Pool.Exec(ack, `UPDATE billing_event_credit SET failures=0,last_error=NULL WHERE contract_id=$1`, id)
		case errors.Is(issueErr, errCreditIssuanceDeferred):
			_, err = h.Pool.Exec(ack, `UPDATE billing_event_credit SET last_error=$2,next_attempt_at=clock_timestamp()+interval '30 seconds' WHERE contract_id=$1`, id, issueErr.Error())
			issueErr = nil
		default:
			log.Error().Err(issueErr).Str("contract_id", id.String()).Msg("event credit issuance failed")
			_, err = h.Pool.Exec(ack, `UPDATE billing_event_credit SET failures=least(failures+1,10000),last_error=$2,
 next_attempt_at=clock_timestamp()+make_interval(secs=>least(300,10*power(2,least(failures,5)))::double precision) WHERE contract_id=$1`, id, issueErr.Error())
		}
		cancel()
		errs = append(errs, issueErr, err)
	}
	return errors.Join(errs...)
}

func (h *Handlers) issueEventCredit(ctx context.Context, client *stripeHTTPClient, contract uuid.UUID) error {
	var team uuid.UUID
	var customer, label string
	var cents int64
	if err := h.Pool.QueryRow(ctx, `SELECT team_id,customer_id,label,credit_cents FROM billing_event_credit WHERE contract_id=$1 AND state<>'issued'`, contract).Scan(&team, &customer, &label, &cents); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	release, err := h.holdCreditIssuanceFence(ctx, team)
	if err != nil {
		return err
	}
	defer release()
	// An earlier attempt, or a manual event_credit.py run whose idempotency key
	// Stripe has since forgotten, may already have granted this credit.
	grants, err := client.customerCreditGrants(ctx, customer)
	if err != nil {
		return err
	}
	grant, err := existingEventGrant(grants, team, label, cents)
	if err != nil || grant != "" {
		if grant != "" {
			_, err = h.Pool.Exec(ctx, `UPDATE billing_event_credit SET state='issued',stripe_credit_grant_id=$2,issued_at=clock_timestamp(),first_attempt_at=COALESCE(first_attempt_at,clock_timestamp()) WHERE contract_id=$1 AND state<>'issued'`, contract, grant)
		}
		return err
	}
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_event_credit SET state='uncertain',first_attempt_at=COALESCE(first_attempt_at,clock_timestamp()) WHERE contract_id=$1 AND state<>'issued'`, contract); err != nil {
		return err
	}
	created, err := client.createCreditGrant(ctx, eventGrantForm(team, customer, label, cents), eventGrantKey(team, label))
	if err != nil {
		return err
	}
	_, err = h.Pool.Exec(ctx, `UPDATE billing_event_credit SET state='issued',stripe_credit_grant_id=$2,issued_at=clock_timestamp() WHERE contract_id=$1 AND state='uncertain'`, contract, created.ID)
	return err
}

// customerCreditGrants lists every credit grant on a customer, bounded like
// the event credit script's inspection.
func (c *stripeHTTPClient) customerCreditGrants(ctx context.Context, customer string) ([]entitlementGrant, error) {
	var all []entitlementGrant
	after := ""
	for range 10 {
		q := url.Values{"customer": {customer}, "limit": {"100"}}
		if after != "" {
			q.Set("starting_after", after)
		}
		var page struct {
			Data    []entitlementGrant `json:"data"`
			HasMore bool               `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+q.Encode(), nil, &page, ""); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		if !page.HasMore {
			return all, nil
		}
		if len(page.Data) == 0 {
			return nil, errors.New("empty incomplete credit grant page")
		}
		after = page.Data[len(page.Data)-1].ID
	}
	return nil, errors.New("customer credit grants exceed the inspection bound")
}

// existingEventGrant returns the team's grant for this event, if any. A grant
// that was voided or differs from the event's terms needs an operator rather
// than a second grant.
func existingEventGrant(grants []entitlementGrant, team uuid.UUID, label string, cents int64) (string, error) {
	var found []entitlementGrant
	for _, g := range grants {
		if g.Metadata["event_label"] == label && g.Metadata["team_id"] == team.String() {
			found = append(found, g)
		}
	}
	if len(found) == 0 {
		return "", nil
	}
	g := found[0]
	if len(found) > 1 || g.VoidedAt != 0 || g.ExpiresAt != 0 || g.Category != "promotional" || g.Priority != 50 ||
		g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value != cents ||
		g.Applicability.Scope.PriceType != "metered" || len(g.Applicability.Scope.Prices) != 0 {
		return "", fmt.Errorf("event credit %s already has a grant that differs from its terms; operator review required", label)
	}
	return g.ID, nil
}
