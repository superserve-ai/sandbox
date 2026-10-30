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
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

var errCreditIssuanceDeferred = errors.New("credit issuance deferred")

type matchingTerms struct {
	MatchingBps int32
	CapCents    int64
}

type matchingRule struct {
	ContractID        uuid.UUID
	TeamID            uuid.UUID
	Terms             matchingTerms
	PriorMatchedCents int64
	EffectiveFrom     time.Time
	Source            string
	Actor             *uuid.UUID
	Reason            *string
}

// insertContractMatchingRule freezes matching terms onto a contract. A caller
// creating a contract from plan terms that include matching must call it in
// the same transaction; staff call it to attach a rule to an existing deal.
func insertContractMatchingRule(ctx context.Context, q db.DBTX, r matchingRule) error {
	_, err := q.Exec(ctx, `INSERT INTO billing_contract_matching_rule(contract_id,team_id,matching_bps,cap_cents,prior_matched_cents,effective_from,source,created_by,reason)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, r.ContractID, r.TeamID, r.Terms.MatchingBps, r.Terms.CapCents, r.PriorMatchedCents, r.EffectiveFrom, r.Source, r.Actor, r.Reason)
	return err
}

type matchingUsage struct {
	UsageCents, CreditCents, DiscountCents, UnpaidCents int64
	SkipReason                                          string
}

type matchingPayment struct {
	AmountPaid    int64 `json:"amount_paid"`
	PaidOutOfBand bool  `json:"paid_out_of_band"`
}

// A positive customer balance is debt, including invoices marked paid below
// Stripe's minimum charge. Attribution to a later cash payment needs separate
// reconciliation; it cannot consume matching eligibility at invoice close.
var errMatchingCashReconciliation = errors.New("matching cash attribution requires reconciliation: customer debit balance")

// Only usage-priced lines are matchable: the plan fee and anything else on the
// invoice fall outside the frozen close plan's credit prices. Every applied
// credit grant is subtracted, including earlier matching credit. Cash is
// attributed to the fee first, so usage the customer did not pay is unmatched.
func matchingInvoiceUsage(inv StripeInvoiceAmounts, paid matchingPayment, prices []string) (matchingUsage, error) {
	var u matchingUsage
	if len(prices) == 0 {
		u.SkipReason = "close plan does not identify usage prices"
		return u, nil
	}
	if paid.PaidOutOfBand || paid.AmountPaid < 0 {
		u.SkipReason = "invoice was not paid by the customer through Stripe"
		return u, nil
	}
	if inv.Lines.HasMore || len(inv.Taxes) != 0 || inv.AmountShipping != 0 || inv.PrePaymentCreditNotes != 0 || inv.PostPaymentCreditNotes != 0 {
		u.SkipReason = "invoice carries tax, shipping, credit notes or incomplete lines"
		return u, nil
	}
	usage := map[string]bool{}
	for _, p := range prices {
		usage[p] = true
	}
	var err error
	other := int64(0)
	for _, line := range inv.Lines.Data {
		if line.Pricing.PriceDetails == nil || !usage[line.Pricing.PriceDetails.Price] {
			other += line.Amount
			for _, credit := range line.PretaxCredits {
				other -= credit.Amount
			}
			continue
		}
		if line.Currency != "usd" || line.Amount < 0 {
			u.SkipReason = "usage line has unsupported currency or amount"
			return u, nil
		}
		if u.UsageCents, err = checkedCreditSum(u.UsageCents, line.Amount); err != nil {
			return u, err
		}
		for _, credit := range line.PretaxCredits {
			switch credit.Type {
			case "credit_balance_transaction":
				u.CreditCents, err = checkedCreditSum(u.CreditCents, credit.Amount)
			case "discount":
				u.DiscountCents, err = checkedCreditSum(u.DiscountCents, credit.Amount)
			default:
				u.SkipReason = "usage line has an unsupported pretax credit"
				return u, nil
			}
			if err != nil {
				return u, err
			}
		}
	}
	net := u.UsageCents - u.CreditCents - u.DiscountCents
	u.UnpaidCents = max(net-max(paid.AmountPaid-max(other, 0), 0), 0)
	return u, nil
}

func (h *Handlers) startMatchingCredits(ctx context.Context, client *stripeHTTPClient) {
	go func() {
		for ctx.Err() == nil {
			if h.Config != nil && h.Config.BillingUsageEntitlementsEnabled {
				started := time.Now()
				err := h.matchingCreditTick(ctx, client)
				currentBillingRecorder().RecordBillingWork(ctx, "matching_credit", err != nil, time.Since(started), 1)
				if err != nil {
					log.Warn().Err(err).Msg("matching credit reconciliation failed")
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
		}
	}()
}

func (h *Handlers) matchingCreditTick(ctx context.Context, client *stripeHTTPClient) error {
	return runBillingPhases(ctx, time.Minute,
		func(ctx context.Context) error { return h.recordPaidMatchingInvoices(ctx, client) },
		func(ctx context.Context) error { return h.issueDueMatchingCredits(ctx, client) },
		func(ctx context.Context) error { return h.reviewMatchedInvoices(ctx, client) },
	)
}

type matchingCandidate struct {
	Team, Contract    uuid.UUID
	Invoice, Customer string
	Hash              string
	Start, End        time.Time
	Prices            []string
}

// Collection is the durable record of payment: invoice.paid webhooks wake it
// and its poller recovers missed events, so a paid collection is the trigger.
func (h *Handlers) recordPaidMatchingInvoices(ctx context.Context, client *stripeHTTPClient) error {
	rows, err := h.Pool.Query(ctx, `SELECT r.team_id,r.contract_id,j.invoice_id,c.customer_id,k.settlement_hash,j.period_start,j.period_end,
 CASE WHEN jsonb_typeof(j.plan->'credit_prices')='array' AND NOT jsonb_path_exists(j.plan,'strict $.credit_prices[*] ? (@.type() != "string")') THEN ARRAY(SELECT jsonb_array_elements_text(j.plan->'credit_prices')) ELSE '{}'::text[] END
 FROM billing_contract_matching_rule r
 JOIN billing_commercial_contract c ON c.id=r.contract_id
 JOIN billing_invoice_close j ON j.team_id=r.team_id AND j.state='released' AND j.period_start>=r.effective_from
  AND j.period_start>=c.starts_at AND (c.ends_at IS NULL OR j.period_start<c.ends_at) AND (r.revoked_at IS NULL OR j.period_start<r.revoked_at)
  AND j.plan->>'customer'=c.customer_id AND j.plan->>'subscription'=c.subscription_id
  AND NOT EXISTS(SELECT 1 FROM billing_commercial_contract n WHERE n.subscription_id=c.subscription_id AND n.id<>c.id AND n.starts_at>c.starts_at AND n.starts_at<=j.period_start)
 JOIN billing_invoice_collection k ON k.invoice_id=j.invoice_id AND k.state='paid'
 LEFT JOIN billing_matching_invoice_inspection i ON i.invoice_id=j.invoice_id
 WHERE NOT EXISTS(SELECT 1 FROM billing_matching_credit m WHERE m.invoice_id=j.invoice_id)
 AND (i.invoice_id IS NULL OR i.next_attempt_at<=clock_timestamp())
 ORDER BY COALESCE(i.next_attempt_at,'-infinity'::timestamptz),j.period_start,j.invoice_id LIMIT 20`)
	if err != nil {
		return err
	}
	var candidates []matchingCandidate
	for rows.Next() {
		var m matchingCandidate
		if err = rows.Scan(&m.Team, &m.Contract, &m.Invoice, &m.Customer, &m.Hash, &m.Start, &m.End, &m.Prices); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, m)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	var errs []error
	for _, m := range candidates {
		var claimed string
		err := h.Pool.QueryRow(ctx, `INSERT INTO billing_matching_invoice_inspection(invoice_id) VALUES($1)
 ON CONFLICT(invoice_id) DO UPDATE SET failures=least(billing_matching_invoice_inspection.failures+1,10000),
 next_attempt_at=clock_timestamp()+make_interval(secs=>least(3600,300*power(2,least(billing_matching_invoice_inspection.failures,4)))::double precision),
 last_error=CASE WHEN billing_matching_invoice_inspection.last_error=$2 THEN $2 ELSE NULL END
 WHERE billing_matching_invoice_inspection.next_attempt_at<=clock_timestamp() RETURNING invoice_id`, m.Invoice, errMatchingCashReconciliation.Error()).Scan(&claimed)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		workErr := h.recordMatchingInvoice(ctx, client, m)
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		var message *string
		if workErr != nil {
			value := workErr.Error()
			message = &value
		}
		_, err = h.Pool.Exec(ack, `UPDATE billing_matching_invoice_inspection SET last_error=$2 WHERE invoice_id=$1`, m.Invoice, message)
		cancel()
		errs = append(errs, workErr, err)
	}
	return errors.Join(errs...)
}

func (h *Handlers) recordMatchingInvoice(ctx context.Context, client *stripeHTTPClient, m matchingCandidate) error {
	var held bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_matching_invoice_inspection WHERE invoice_id=$1 AND last_error=$2)`, m.Invoice, errMatchingCashReconciliation.Error()).Scan(&held); err != nil {
		return err
	}
	if held {
		return errMatchingCashReconciliation
	}
	inv, err := client.RetrieveBillingInvoice(ctx, m.Invoice)
	if err != nil {
		return err
	}
	if inv.ID != m.Invoice || inv.Customer != m.Customer {
		return fmt.Errorf("matching invoice %s ownership changed", m.Invoice)
	}
	var paid matchingPayment
	if err = client.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(m.Invoice), nil, &paid, ""); err != nil {
		return err
	}
	if inv.StartingBalance > 0 || inv.EndingBalance != nil && *inv.EndingBalance > 0 {
		// Keep the durable inspection open. A zero-value immutable matching row
		// would permanently discard the original usage's later cash eligibility.
		if _, err := h.Pool.Exec(ctx, `INSERT INTO billing_matching_invoice_inspection(invoice_id,next_attempt_at,last_error)
 VALUES($1,'infinity',$2) ON CONFLICT(invoice_id) DO UPDATE SET next_attempt_at='infinity',last_error=EXCLUDED.last_error`, m.Invoice, errMatchingCashReconciliation.Error()); err != nil {
			return err
		}
		return errMatchingCashReconciliation
	}
	var flagEvidence []byte
	u, err := matchingInvoiceUsage(inv, paid, m.Prices)
	if err != nil {
		return err
	}
	if inv.Status != "paid" || inv.AmountRemaining == nil || *inv.AmountRemaining != 0 {
		u.SkipReason = "invoice is not fully paid despite its paid collection record"
	}
	if u.SkipReason == "" && invoiceSettlementHash(inv) != m.Hash {
		u.SkipReason = "invoice changed after its verified settlement"
	}
	if u.SkipReason == "" {
		reversal, raw, err := client.matchedInvoiceReversal(ctx, m.Invoice, m.Customer)
		if err != nil {
			return err
		}
		u.SkipReason, flagEvidence = reversal, raw
	}
	evidence, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	if flagEvidence == nil {
		flagEvidence = evidence
	}
	var reason *string
	if u.SkipReason != "" {
		reason = &u.SkipReason
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO billing_matching_credit(team_id,contract_id,invoice_id,customer_id,period_start,period_end,usage_cents,credit_applied_cents,discount_cents,unpaid_cents,matchable_cents,amount_cents,skip_reason,invoice_evidence,state,idempotency_key)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,0,$11,$12,'skipped','') ON CONFLICT(invoice_id) DO NOTHING RETURNING id`,
		m.Team, m.Contract, m.Invoice, m.Customer, m.Start, m.End, u.UsageCents, u.CreditCents, u.DiscountCents, u.UnpaidCents, reason, evidence).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if reason != nil {
		if _, err = tx.Exec(ctx, `UPDATE billing_matching_credit SET flagged_at=clock_timestamp(),flag_reason=$2,flag_evidence=$3 WHERE id=$1`, id, *reason, flagEvidence); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (h *Handlers) issueDueMatchingCredits(ctx context.Context, client *stripeHTTPClient) error {
	rows, err := h.Pool.Query(ctx, `SELECT id FROM billing_matching_credit WHERE state IN ('pending','uncertain') AND next_attempt_at<=clock_timestamp()
 AND (state='uncertain' OR flagged_at IS NULL OR acknowledged_at IS NOT NULL) ORDER BY next_attempt_at,id LIMIT 20`)
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
		issueErr := h.issueMatchingCredit(ctx, client, id)
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		var err error
		switch {
		case issueErr == nil:
			_, err = h.Pool.Exec(ack, `UPDATE billing_matching_credit SET failures=0,last_error=NULL WHERE id=$1`, id)
		case errors.Is(issueErr, errCreditIssuanceDeferred) || errors.Is(issueErr, errCreditInventoryPending):
			_, err = h.Pool.Exec(ack, `UPDATE billing_matching_credit SET last_error=$2,
 next_attempt_at=clock_timestamp()+CASE WHEN $3 AND created_at<clock_timestamp()-interval '1 day' THEN interval '1 hour' ELSE interval '30 seconds' END WHERE id=$1`, id, issueErr.Error(), errors.Is(issueErr, errCreditIssuanceDeferred))
			issueErr = nil
		default:
			log.Error().Err(issueErr).Str("matching_credit_id", id.String()).Msg("matching credit issuance failed; inspect before replaying")
			_, err = h.Pool.Exec(ack, `UPDATE billing_matching_credit SET failures=least(failures+1,10000),last_error=$2,
 next_attempt_at=clock_timestamp()+make_interval(secs=>least(300,10*power(2,least(failures,5)))::double precision) WHERE id=$1`, id, issueErr.Error())
		}
		cancel()
		errs = append(errs, issueErr, err)
	}
	return errors.Join(errs...)
}

func (h *Handlers) issueMatchingCredit(ctx context.Context, client *stripeHTTPClient, id uuid.UUID) error {
	var team, contract uuid.UUID
	var customer, key, invoice, current string
	var acknowledged, flagged bool
	var attempted *time.Time
	if err := h.Pool.QueryRow(ctx, `SELECT team_id,contract_id,customer_id,idempotency_key,invoice_id,state,acknowledged_at IS NOT NULL,flagged_at IS NOT NULL,first_attempt_at FROM billing_matching_credit WHERE id=$1`, id).Scan(&team, &contract, &customer, &key, &invoice, &current, &acknowledged, &flagged, &attempted); err != nil {
		return err
	}
	release, err := h.holdCreditIssuanceFence(ctx, team)
	if err != nil {
		return err
	}
	defer release()
	if current == "uncertain" {
		found, err := h.recoverMatchingCredit(ctx, client, id, contract, customer)
		if err != nil || found {
			return err
		}
		if attempted == nil || time.Since(*attempted) >= 23*time.Hour {
			return errors.New("matching credit outcome unknown after the replay window; operator recovery required")
		}
		if flagged && !acknowledged {
			return fmt.Errorf("%w: uncertain matching credit is held for provider recovery", errCreditIssuanceDeferred)
		}
	}
	if (current == "pending" || current == "uncertain") && !acknowledged {
		reason, evidence, err := client.matchedInvoiceReversal(ctx, invoice, customer)
		if err != nil {
			return err
		}
		if reason != "" {
			log.Warn().Str("matching_credit_id", id.String()).Str("invoice_id", invoice).Str("reason", reason).Msg("matched invoice was reversed before issuance; staff review required")
			_, err = h.Pool.Exec(ctx, `UPDATE billing_matching_credit SET flagged_at=clock_timestamp(),flag_reason=$2,flag_evidence=$3 WHERE id=$1 AND state IN ('pending','uncertain') AND flagged_at IS NULL`, id, reason, evidence)
			if err == nil && current == "uncertain" {
				return fmt.Errorf("%w: reversed uncertain matching credit requires provider recovery", errCreditIssuanceDeferred)
			}
			return err
		}
	}
	var state string
	var payload []byte
	var first *time.Time
	err = h.Pool.QueryRow(ctx, `UPDATE billing_matching_credit SET state='uncertain',first_attempt_at=COALESCE(first_attempt_at,clock_timestamp())
 WHERE id=$1 AND state IN ('pending','uncertain') AND (flagged_at IS NULL OR acknowledged_at IS NOT NULL) RETURNING state,request_payload,first_attempt_at`, id).Scan(&state, &payload, &first)
	if errors.Is(err, pgx.ErrNoRows) {
		if current == "pending" || current == "uncertain" {
			return fmt.Errorf("%w: matching credit dispatch is held", errCreditIssuanceDeferred)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if first == nil || time.Since(*first) >= 23*time.Hour {
		return h.discoverMatchingCredit(ctx, client, id, contract, customer)
	}
	form, err := matchingGrantForm(payload)
	if err != nil {
		return err
	}
	grant, err := client.createCreditGrant(ctx, form, key)
	if err != nil {
		return err
	}
	return h.confirmMatchingCredit(ctx, id, grant)
}

func (h *Handlers) confirmMatchingCredit(ctx context.Context, id uuid.UUID, grant entitlementGrant) error {
	raw, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	_, err = h.Pool.Exec(ctx, `UPDATE billing_matching_credit SET state='issued',stripe_credit_grant_id=$2,issuance_evidence=$3,issued_at=clock_timestamp(),review_checked_at=NULL WHERE id=$1 AND state='uncertain'`, id, grant.ID, raw)
	return err
}

// Past Stripe's idempotency window a replay could create a second grant, so
// only the provider inventory can settle the outcome.
func (h *Handlers) discoverMatchingCredit(ctx context.Context, client *stripeHTTPClient, id, contract uuid.UUID, customer string) error {
	found, err := h.recoverMatchingCredit(ctx, client, id, contract, customer)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("matching credit outcome unknown after the replay window; operator recovery required")
	}
	return nil
}

func (h *Handlers) recoverMatchingCredit(ctx context.Context, client *stripeHTTPClient, id, contract uuid.UUID, customer string) (bool, error) {
	if err := h.syncCreditInventory(ctx, contract, customer, client); err != nil {
		return false, err
	}
	rows, err := h.Pool.Query(ctx, `SELECT grant_id FROM billing_provider_credit WHERE customer_id=$1 AND evidence->'metadata'->>'matching_credit_id'=$2 LIMIT 2`, customer, id.String())
	if err != nil {
		return false, err
	}
	var ids []string
	for rows.Next() {
		var grant string
		if err = rows.Scan(&grant); err != nil {
			rows.Close()
			return false, err
		}
		ids = append(ids, grant)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return false, err
	}
	if len(ids) == 0 {
		return false, nil
	}
	if len(ids) != 1 {
		return false, fmt.Errorf("matching credit outcome unknown after the replay window (%d provider grants); operator recovery required", len(ids))
	}
	grant, err := client.retrieveEntitlementGrant(ctx, ids[0])
	if err != nil {
		return false, err
	}
	if grant.VoidedAt != 0 {
		return false, errors.New("recovered matching grant was voided; operator recovery required")
	}
	return true, h.confirmMatchingCredit(ctx, id, grant)
}

// The form is derived exclusively from the frozen request so every replay
// sends identical parameters under the same idempotency key.
func matchingGrantForm(raw []byte) (url.Values, error) {
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
	if g.Customer == "" || g.Category != "promotional" || g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value <= 0 || g.Priority != 50 || g.ExpiresAt != 0 || g.EffectiveAt != 0 || g.Applicability.Scope.PriceType != "metered" || len(g.Applicability.Scope.Prices) != 0 || g.Metadata["matching_credit_id"] == "" || g.Metadata["invoice_id"] == "" || len(g.Metadata) != 2 || name == "" {
		return nil, errors.New("incomplete saved matching credit request")
	}
	return url.Values{
		"customer": {g.Customer}, "category": {g.Category}, "name": {name},
		"amount[type]": {"monetary"}, "amount[monetary][currency]": {"usd"}, "amount[monetary][value]": {strconv.FormatInt(g.Amount.Monetary.Value, 10)},
		"priority": {"50"}, "applicability_config[scope][price_type]": {"metered"},
		"metadata[matching_credit_id]": {g.Metadata["matching_credit_id"]}, "metadata[invoice_id]": {g.Metadata["invoice_id"]},
	}, nil
}

// Refunds and credit notes after a match are surfaced for staff; matched
// credit is never clawed back automatically.
func (h *Handlers) reviewMatchedInvoices(ctx context.Context, client *stripeHTTPClient) error {
	rows, err := h.Pool.Query(ctx, `SELECT id,invoice_id,customer_id,state='issued' AND issued_at<now()-interval '120 days' FROM billing_matching_credit
 WHERE amount_cents>0 AND flagged_at IS NULL AND review_checked_at IS DISTINCT FROM 'infinity'::timestamptz
  AND COALESCE(review_checked_at,'-infinity'::timestamptz)<now()-interval '1 day'
 ORDER BY COALESCE(review_checked_at,'-infinity'::timestamptz) LIMIT 10`)
	if err != nil {
		return err
	}
	type matched struct {
		ID                uuid.UUID
		Invoice, Customer string
		Expired           bool
	}
	var due []matched
	for rows.Next() {
		var m matched
		if err = rows.Scan(&m.ID, &m.Invoice, &m.Customer, &m.Expired); err != nil {
			rows.Close()
			return err
		}
		due = append(due, m)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	var errs []error
	for _, m := range due {
		reason, evidence, err := client.matchedInvoiceReversal(ctx, m.Invoice, m.Customer)
		if err != nil {
			errs = append(errs, err)
			_, err = h.Pool.Exec(ctx, `UPDATE billing_matching_credit SET review_checked_at=clock_timestamp()-interval '23 hours' WHERE id=$1`, m.ID)
		} else if reason != "" {
			log.Warn().Str("matching_credit_id", m.ID.String()).Str("invoice_id", m.Invoice).Str("reason", reason).Msg("matched invoice was reversed; staff review required")
			_, err = h.Pool.Exec(ctx, `UPDATE billing_matching_credit SET review_checked_at=clock_timestamp(),flagged_at=clock_timestamp(),flag_reason=$2,flag_evidence=$3 WHERE id=$1 AND flagged_at IS NULL`, m.ID, reason, evidence)
		} else if m.Expired {
			_, err = h.Pool.Exec(ctx, `UPDATE billing_matching_credit SET review_checked_at='infinity' WHERE id=$1`, m.ID)
		} else {
			_, err = h.Pool.Exec(ctx, `UPDATE billing_matching_credit SET review_checked_at=clock_timestamp() WHERE id=$1`, m.ID)
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (c *stripeHTTPClient) matchedInvoiceReversal(ctx context.Context, id, customer string) (string, []byte, error) {
	inv, err := c.RetrieveBillingInvoice(ctx, id)
	if err != nil {
		return "", nil, err
	}
	if inv.ID != id || inv.Customer != customer {
		return "", nil, errors.New("matched invoice ownership changed")
	}
	if inv.Status != "paid" || inv.PrePaymentCreditNotes != 0 || inv.PostPaymentCreditNotes != 0 {
		raw, _ := json.Marshal(inv)
		return "credit note issued or payment reversed on matched invoice", raw, nil
	}
	if inv.AmountPaid == nil || *inv.AmountPaid < 0 {
		return "", nil, errors.New("matched invoice lacks supported cash-paid evidence")
	}
	var payments struct {
		Data []struct {
			Invoice    string `json:"invoice"`
			AmountPaid int64  `json:"amount_paid"`
			Payment    struct {
				Type   string `json:"type"`
				Intent string `json:"payment_intent"`
			} `json:"payment"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	}
	q := url.Values{"invoice": {id}, "status": {"paid"}, "limit": {"100"}}
	if err = c.doForm(ctx, http.MethodGet, "/v1/invoice_payments?"+q.Encode(), nil, &payments, ""); err != nil {
		return "", nil, err
	}
	if payments.HasMore {
		return "", nil, errors.New("matched invoice payments exceed the supported bound")
	}
	if payments.Data == nil {
		return "", nil, errors.New("matched invoice lacks paid-payment evidence")
	}
	var verifiedCash int64
	seenIntents := map[string]bool{}
	for _, p := range payments.Data {
		if p.Invoice != id || p.Payment.Type != "payment_intent" || p.Payment.Intent == "" {
			return "", nil, errors.New("matched invoice has unsupported paid-payment evidence")
		}
		if p.AmountPaid <= 0 || p.AmountPaid > *inv.AmountPaid-verifiedCash || seenIntents[p.Payment.Intent] {
			return "", nil, errors.New("matched invoice payments do not account for its cash-paid amount")
		}
		seenIntents[p.Payment.Intent] = true
		var intent struct {
			ID           string `json:"id"`
			LatestCharge string `json:"latest_charge"`
		}
		if err = c.doForm(ctx, http.MethodGet, "/v1/payment_intents/"+url.PathEscape(p.Payment.Intent), nil, &intent, ""); err != nil {
			return "", nil, err
		}
		if intent.ID != p.Payment.Intent {
			return "", nil, errors.New("matched invoice payment intent identity changed")
		}
		raw, err := c.verifyProCharge(ctx, intent.LatestCharge, p.Payment.Intent, customer, p.AmountPaid)
		var review *proPaymentReviewError
		if errors.As(err, &review) {
			return "payment on matched invoice was refunded or disputed", raw, nil
		}
		if err != nil {
			return "", nil, err
		}
		verifiedCash += p.AmountPaid
	}
	if verifiedCash != *inv.AmountPaid {
		return "", nil, errors.New("matched invoice payments do not account for its cash-paid amount")
	}
	return "", nil, nil
}

// Matching and purchased credit are owned by their ledgers; no other flow may adopt them.
func (h *Handlers) withoutLedgerOwnedGrants(ctx context.Context, grants []billing.InvoiceCreditGrant) ([]billing.InvoiceCreditGrant, error) {
	ids := make([]string, len(grants))
	for i, g := range grants {
		ids[i] = g.ID
	}
	rows, err := h.Pool.Query(ctx, `SELECT stripe_credit_grant_id FROM billing_matching_credit WHERE stripe_credit_grant_id=ANY($1)
 UNION ALL SELECT stripe_credit_grant_id FROM billing_prepaid_purchase WHERE stripe_credit_grant_id=ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	owned := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		owned[id] = true
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	kept := []billing.InvoiceCreditGrant{}
	for _, g := range grants {
		if !owned[g.ID] {
			kept = append(kept, g)
		}
	}
	return kept, nil
}

// Issuance shares the invoice closer's per-team lock and waits until every
// ended period is released: a close freezes or recomputes the eligible credit
// set for its period, so a grant appearing before release could wedge it. A
// grant issued while no period awaits closing simply funds the next invoice.
func (h *Handlers) holdCreditIssuanceFence(ctx context.Context, team uuid.UUID) (func(), error) {
	lock, err := h.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	release := func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = lock.Rollback(cleanup)
	}
	var locked, closing bool
	if err = lock.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "invoice:"+team.String()).Scan(&locked); err != nil {
		release()
		return nil, err
	}
	if !locked {
		release()
		return nil, errCreditIssuanceDeferred
	}
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_period p JOIN billing_invoice_account a USING(team_id)
 WHERE p.team_id=$1 AND p.period_end<=clock_timestamp() AND p.period_end>a.enrolled_at
  AND NOT EXISTS(SELECT 1 FROM billing_invoice_close j WHERE (j.team_id,j.period_start,j.period_end)=(p.team_id,p.period_start,p.period_end) AND j.state='released'))`, team).Scan(&closing); err != nil {
		release()
		return nil, err
	}
	if closing {
		release()
		return nil, fmt.Errorf("%w: an ended billing period is not yet released", errCreditIssuanceDeferred)
	}
	return release, nil
}
