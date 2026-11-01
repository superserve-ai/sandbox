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
	tag, err := tx.Exec(ctx, `INSERT INTO billing_event_credit(contract_id,team_id,customer_id,promotion_code,label,credit_cents)
 SELECT $1,$2,$3,p.promotion_code,p.label,p.credit_cents FROM billing_event_promotion p WHERE p.promotion_code=$4
 ON CONFLICT DO NOTHING`, contract, team, customer, promotionCode)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	var prior string
	err = tx.QueryRow(ctx, `SELECT c.customer_id FROM billing_event_credit c JOIN billing_event_promotion p ON p.label=c.label
 WHERE p.promotion_code=$1 AND c.team_id=$2 AND c.customer_id<>$3`, promotionCode, team, customer).Scan(&prior)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err == nil {
		log.Error().Str("team_id", team.String()).Str("contract_id", contract.String()).Str("prior_customer", prior).Str("customer", customer).
			Msg("event credit already queued on another customer; operator review required")
	}
	return err
}

// eventCheckout reports whether a checkout an event code made free may skip
// the saved card: the event credit funds usage, and a renewal without a card
// is unpaid like any other. Only a prepaid plan stops at its credit, and only
// without Auto Reload, which charges the card; otherwise a card is needed.
func eventCheckout(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, session StripeRetrievedCheckoutSession, params StripeCreateCheckoutSessionParams, team uuid.UUID, customer string) (bool, error) {
	if params.PlanTerms == nil || params.PlanTerms.FundingPolicy != fundingPolicyPrepaid {
		return false, nil
	}
	if params.Topoff != nil {
		if topoff, err := session.topoffChosen(); err != nil || topoff {
			return false, nil
		}
	}
	code := session.promotionCode()
	if code == "" || session.AmountTotal != 0 {
		return false, nil
	}
	// A team whose credit for this event sits on another customer gets no new
	// credit here, so its checkout needs a card like any other free one.
	var listed bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_event_promotion WHERE promotion_code=$1)
 AND NOT EXISTS(SELECT 1 FROM billing_event_credit c JOIN billing_event_promotion p ON p.label=c.label
  WHERE p.promotion_code=$1 AND c.team_id=$2 AND c.customer_id<>$3)`, code, team, customer).Scan(&listed)
	return listed, err
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
	var customer, label, state string
	var cents int64
	var first *time.Time
	if err := h.Pool.QueryRow(ctx, `SELECT team_id,customer_id,label,credit_cents,state,first_attempt_at FROM billing_event_credit WHERE contract_id=$1 AND state<>'issued'`, contract).Scan(&team, &customer, &label, &cents, &state, &first); err != nil {
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
	grants, err := h.teamCreditGrants(ctx, client, team, customer)
	if err != nil {
		return err
	}
	grant, err := existingEventGrant(grants, team, customer, label, cents, h.nowUTC().Unix())
	if err != nil || grant != "" {
		if grant != "" {
			_, err = h.Pool.Exec(ctx, `UPDATE billing_event_credit SET state='issued',stripe_credit_grant_id=$2,issued_at=clock_timestamp(),first_attempt_at=COALESCE(first_attempt_at,clock_timestamp()) WHERE contract_id=$1 AND state<>'issued'`, contract, grant)
		}
		return err
	}
	// Stripe forgets the idempotency key after a day, so a replay past then
	// could grant twice.
	if state == "uncertain" && first != nil && h.nowUTC().Sub(*first) >= 23*time.Hour {
		return fmt.Errorf("event credit %s has an unconfirmed grant past its replay window; operator review required", label)
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

// teamCreditGrants lists the grants on every customer the team has had, known
// locally or tagged with the team in Stripe, as event_credit.py inspects them.
func (h *Handlers) teamCreditGrants(ctx context.Context, client *stripeHTTPClient, team uuid.UUID, customer string) ([]entitlementGrant, error) {
	customers := map[string]bool{customer: true}
	rows, err := h.Pool.Query(ctx, `SELECT stripe_customer_id FROM team_billing_account WHERE team_id=$1 AND stripe_customer_id IS NOT NULL
 UNION SELECT customer_id FROM billing_commercial_contract WHERE team_id=$1`, team)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		customers[id] = true
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	tagged, err := client.teamCustomers(ctx, team)
	if err != nil {
		return nil, err
	}
	for _, id := range tagged {
		customers[id] = true
	}
	var all []entitlementGrant
	for id := range customers {
		grants, err := client.customerCreditGrants(ctx, id)
		if err != nil {
			return nil, err
		}
		all = append(all, grants...)
	}
	return all, nil
}

func (c *stripeHTTPClient) teamCustomers(ctx context.Context, team uuid.UUID) ([]string, error) {
	var ids []string
	page := ""
	for range 20 {
		q := url.Values{"query": {fmt.Sprintf("metadata['team_id']:'%s'", team)}, "limit": {"100"}}
		if page != "" {
			q.Set("page", page)
		}
		var result struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			HasMore  bool   `json:"has_more"`
			NextPage string `json:"next_page"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/customers/search?"+q.Encode(), nil, &result, ""); err != nil {
			return nil, err
		}
		for _, d := range result.Data {
			ids = append(ids, d.ID)
		}
		if !result.HasMore {
			return ids, nil
		}
		if result.NextPage == "" {
			return nil, errors.New("customer search page is incomplete")
		}
		page = result.NextPage
	}
	return nil, errors.New("customers for the team exceed the inspection bound")
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

// otherCreditKind reports metadata that marks a grant as belonging to another
// credit flow, as event_credit.py's reserved keys and restore marker do.
func otherCreditKind(metadata map[string]string) bool {
	for _, key := range []string{"entitlement_id", "matching_credit_id", "prepaid_purchase_id", "pro_upgrade_id", "activation_identity", "trial_forfeit_restore"} {
		if _, ok := metadata[key]; ok {
			return true
		}
	}
	return false
}

// existingEventGrant returns the team's grant for this event, if any. A grant
// that was voided, differs from the event's terms, or sits on another customer
// (which cannot fund this one's invoices) needs an operator, not a second grant.
func existingEventGrant(grants []entitlementGrant, team uuid.UUID, customer, label string, cents, now int64) (string, error) {
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
	if len(found) > 1 || g.Customer != customer || g.VoidedAt != 0 || g.EffectiveAt > now || otherCreditKind(g.Metadata) || g.ExpiresAt != 0 || g.Category != "promotional" || g.Priority != 50 ||
		g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value != cents ||
		g.Applicability.Scope.PriceType != "metered" || len(g.Applicability.Scope.Prices) != 0 {
		return "", fmt.Errorf("event credit %s already has a grant that differs from its terms; operator review required", label)
	}
	return g.ID, nil
}
