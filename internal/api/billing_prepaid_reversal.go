package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
)

// Paid purchases are swept for refunds and disputes for 120 days after
// payment. Refund and dispute webhooks request a recheck at any age, and a
// purchase with a dispute still open keeps being rechecked until it closes.
const prepaidReversalWindow = "120 days"

var errPrepaidNoPaymentReference = errors.New("paid purchase has no payment reference")

// Disputes in these states have neither been won nor lost yet. Inquiries
// (warning_*) withdraw no funds and are reported apart from them.
var prepaidOpenDisputeStates = []string{"warning_needs_response", "warning_under_review", "needs_response", "under_review"}

var prepaidWithdrawnDisputeStates = []string{"needs_response", "under_review"}

type prepaidChargeState struct {
	ID             string `json:"id"`
	Customer       string `json:"customer"`
	Amount         int64  `json:"amount"`
	AmountRefunded int64  `json:"amount_refunded"`
	Disputed       bool   `json:"disputed"`
}

type prepaidDispute struct {
	ID      string `json:"id"`
	Charge  string `json:"charge"`
	Amount  int64  `json:"amount"`
	Status  string `json:"status"`
	Created int64  `json:"created"`
}

type prepaidIntentCharge struct {
	ID           string `json:"id"`
	Customer     string `json:"customer"`
	LatestCharge string `json:"latest_charge"`
}

type prepaidReversalObservation struct {
	Refunded      int64
	DisputeStatus *string
	Disputed      int64
	Evidence      []byte
}

// A row is claimed by pushing its retry time an hour ahead before any provider
// call, so instances never inspect the same purchase together and a failing
// row waits an hour instead of holding the head of the queue. Candidates come
// from three bounded sets: purchases an event asked about, purchases paid in
// the last 120 days, and purchases whose dispute is still open.
func (h *Handlers) reviewPrepaidReversals(ctx context.Context, client *stripeHTTPClient) error {
	rows, err := h.Pool.Query(ctx, `WITH candidates AS (
  (SELECT id FROM billing_prepaid_purchase WHERE reversal_check_requested_at IS NOT NULL
    AND COALESCE(reversal_retry_after,'-infinity'::timestamptz)<=clock_timestamp() ORDER BY reversal_check_requested_at LIMIT 50)
  UNION
  (SELECT id FROM billing_prepaid_purchase WHERE payment_state='succeeded' AND paid_at>clock_timestamp()-$1::interval
    AND COALESCE(reversal_checked_at,'-infinity'::timestamptz)<clock_timestamp()-interval '1 day'
    AND COALESCE(reversal_retry_after,'-infinity'::timestamptz)<=clock_timestamp()
   ORDER BY COALESCE(reversal_checked_at,'-infinity'::timestamptz) LIMIT 50)
  UNION
  (SELECT r.purchase_id FROM billing_prepaid_reversal r JOIN billing_prepaid_purchase p ON p.id=r.purchase_id
   WHERE r.dispute_status=ANY($2) AND COALESCE(p.reversal_checked_at,'-infinity'::timestamptz)<clock_timestamp()-interval '1 day'
    AND COALESCE(p.reversal_retry_after,'-infinity'::timestamptz)<=clock_timestamp() LIMIT 50)),
 due AS (SELECT p.id FROM billing_prepaid_purchase p JOIN candidates c ON c.id=p.id
  WHERE p.payment_state='succeeded' AND COALESCE(p.reversal_retry_after,'-infinity'::timestamptz)<=clock_timestamp()
  ORDER BY p.reversal_check_requested_at NULLS LAST,COALESCE(p.reversal_checked_at,'-infinity'::timestamptz),p.id
  LIMIT 10 FOR UPDATE OF p SKIP LOCKED)
 UPDATE billing_prepaid_purchase p SET reversal_retry_after=clock_timestamp()+interval '1 hour' FROM due WHERE p.id=due.id
 RETURNING p.id,p.team_id,p.customer_id,p.amount_cents,p.payment_intent_id,p.invoice_id,p.reversal_check_requested_at`, prepaidReversalWindow, prepaidOpenDisputeStates)
	if err != nil {
		return err
	}
	type paid struct {
		ID, Team        uuid.UUID
		Customer        string
		Amount          int64
		Intent, Invoice *string
		Requested       *time.Time
	}
	due, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (paid, error) {
		var p paid
		err := row.Scan(&p.ID, &p.Team, &p.Customer, &p.Amount, &p.Intent, &p.Invoice, &p.Requested)
		return p, err
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range due {
		observed, intents, err := client.prepaidPaymentReversal(ctx, p.Customer, p.Amount, p.Intent, p.Invoice)
		if errors.Is(err, errPrepaidNoPaymentReference) {
			log.Error().Str("prepaid_purchase_id", p.ID.String()).Msg("paid prepaid purchase has no payment reference; reversals cannot be checked")
			err = nil
		}
		if err == nil && p.Invoice != nil && len(intents) > 0 {
			_, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET reversal_payment_intents=ARRAY(SELECT DISTINCT unnest(reversal_payment_intents||$2::text[]) ORDER BY 1) WHERE id=$1`, p.ID, intents)
		}
		if err == nil && observed != nil {
			err = h.recordPrepaidReversal(ctx, p.ID, p.Team, p.Amount, *observed)
		}
		if err != nil {
			log.Error().Err(err).Str("prepaid_purchase_id", p.ID.String()).Msg("prepaid reversal check failed; retrying in an hour")
			errs = append(errs, err)
			continue
		}
		_, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET reversal_checked_at=clock_timestamp(),reversal_retry_after=NULL,
 reversal_check_requested_at=CASE WHEN reversal_check_requested_at IS NOT DISTINCT FROM $2 THEN NULL ELSE reversal_check_requested_at END WHERE id=$1`, p.ID, p.Requested)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// prepaidPaymentReversal reads the charges behind a purchase: its payment
// intent, or the payments of its first invoice. A credit note that refunds a
// charge also raises that charge's refunded amount, so for a first invoice the
// larger of the two is the amount returned rather than their sum. Refunds and
// disputes stay apart because only a refund is money known to be returned.
func (c *stripeHTTPClient) prepaidPaymentReversal(ctx context.Context, customer string, amount int64, intent, invoice *string) (*prepaidReversalObservation, []string, error) {
	var intents []string
	var creditNotes int64
	switch {
	case intent != nil:
		intents = []string{*intent}
	case invoice != nil:
		inv, err := c.RetrieveBillingInvoice(ctx, *invoice)
		if err != nil {
			return nil, nil, err
		}
		if inv.Customer != customer {
			return nil, nil, errors.New("purchase invoice ownership changed")
		}
		creditNotes = inv.PostPaymentCreditNotes
		if intents, err = c.invoicePaymentIntents(ctx, *invoice); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, errPrepaidNoPaymentReference
	}
	var refunded, disputed int64
	var status *string
	var charges []prepaidChargeState
	var disputes []prepaidDispute
	for _, id := range intents {
		var pi prepaidIntentCharge
		if err := c.doForm(ctx, http.MethodGet, "/v1/payment_intents/"+url.PathEscape(id), nil, &pi, ""); err != nil {
			return nil, nil, err
		}
		if pi.ID != id || pi.Customer != customer || pi.LatestCharge == "" {
			return nil, nil, errors.New("purchase payment intent ownership or charge changed")
		}
		var charge prepaidChargeState
		if err := c.doForm(ctx, http.MethodGet, "/v1/charges/"+url.PathEscape(pi.LatestCharge), nil, &charge, ""); err != nil {
			return nil, nil, err
		}
		if charge.ID != pi.LatestCharge || charge.Customer != customer {
			return nil, nil, errors.New("purchase charge ownership changed")
		}
		charges = append(charges, charge)
		refunded += charge.AmountRefunded
		if !charge.Disputed {
			continue
		}
		var list struct {
			Data    []prepaidDispute `json:"data"`
			HasMore bool             `json:"has_more"`
		}
		q := url.Values{"charge": {charge.ID}, "limit": {"10"}}
		if err := c.doForm(ctx, http.MethodGet, "/v1/disputes?"+q.Encode(), nil, &list, ""); err != nil {
			return nil, nil, err
		}
		if list.HasMore || len(list.Data) == 0 {
			return nil, nil, errors.New("purchase dispute evidence is incomplete")
		}
		latest := list.Data[0]
		for _, d := range list.Data {
			if d.Charge != charge.ID {
				return nil, nil, errors.New("purchase dispute ownership changed")
			}
			if d.Created > latest.Created {
				latest = d
			}
		}
		disputes = append(disputes, list.Data...)
		s := latest.Status
		status = &s
		disputed += latest.Amount
	}
	refunded = max(refunded, creditNotes)
	if refunded == 0 && status == nil {
		return nil, intents, nil
	}
	evidence, _ := json.Marshal(map[string]any{"charges": charges, "disputes": disputes, "post_payment_credit_notes": creditNotes})
	return &prepaidReversalObservation{Refunded: min(refunded, amount), DisputeStatus: status, Disputed: min(disputed, amount-min(refunded, amount)), Evidence: evidence}, intents, nil
}

// Each change the provider reports is appended as a new observation version,
// which reopens the purchase for a staff decision. Nothing about the credit or
// the team's settings changes here.
func (h *Handlers) recordPrepaidReversal(ctx context.Context, id, team uuid.UUID, amount int64, o prepaidReversalObservation) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var refunded, disputed int64
	var status *string
	var version int32
	err = tx.QueryRow(ctx, `SELECT refunded_cents,dispute_status,disputed_cents,version FROM billing_prepaid_reversal WHERE purchase_id=$1 FOR UPDATE`, id).Scan(&refunded, &status, &disputed, &version)
	refundedNow := max(refunded, o.Refunded)
	o.Disputed = min(o.Disputed, amount-refundedNow)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		version = 1
		_, err = tx.Exec(ctx, `INSERT INTO billing_prepaid_reversal(purchase_id,team_id,refunded_cents,dispute_status,disputed_cents) VALUES($1,$2,$3,$4,$5)`, id, team, refundedNow, o.DisputeStatus, o.Disputed)
	case err != nil:
		return err
	case refunded == refundedNow && disputed == o.Disputed && derefString(status) == derefString(o.DisputeStatus):
		return nil
	default:
		version++
		_, err = tx.Exec(ctx, `UPDATE billing_prepaid_reversal SET refunded_cents=$2,dispute_status=$3,disputed_cents=$4,version=$5 WHERE purchase_id=$1`, id, refundedNow, o.DisputeStatus, o.Disputed, version)
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_prepaid_reversal_event(purchase_id,version,refunded_cents,dispute_status,disputed_cents,evidence) VALUES($1,$2,$3,$4,$5,$6)`,
		id, version, refundedNow, o.DisputeStatus, o.Disputed, o.Evidence); err != nil {
		return err
	}
	log.Warn().Str("prepaid_purchase_id", id.String()).Int32("version", version).Int64("refunded_cents", refundedNow).Str("dispute_status", derefString(o.DisputeStatus)).
		Bool("dispute_open", o.DisputeStatus != nil && slices.Contains(prepaidOpenDisputeStates, *o.DisputeStatus)).Msg("prepaid purchase payment reversal observed; staff review required")
	return tx.Commit(ctx)
}

// Revocation follows only a staff decision on the latest observation and voids
// only what the grant still holds; spent credit and the issued grant's history
// are kept. A decision a newer observation superseded is never executed.
// Decisions are claimed with a retry time, so ones that cannot proceed yet
// (credit still in flight, fence held, provider errors) never block the rest.
func (h *Handlers) revokeReversedPrepaidCredit(ctx context.Context, client *stripeHTTPClient) error {
	rows, err := h.Pool.Query(ctx, `WITH due AS (
 SELECT d.id FROM billing_prepaid_reversal_decision d JOIN billing_prepaid_reversal r ON r.purchase_id=d.purchase_id
 WHERE d.decision='revoke' AND d.revoked_at IS NULL AND (r.version=d.version OR d.revoke_attempted_at IS NOT NULL) AND COALESCE(d.revoke_retry_after,'-infinity'::timestamptz)<=clock_timestamp()
 ORDER BY d.decided_at LIMIT 10 FOR UPDATE OF d SKIP LOCKED)
 UPDATE billing_prepaid_reversal_decision d SET revoke_retry_after=clock_timestamp()+interval '10 minutes' FROM due WHERE d.id=due.id
 RETURNING d.id,d.purchase_id,d.version,d.decided_at<clock_timestamp()-interval '1 day'`)
	if err != nil {
		return err
	}
	type revoke struct {
		Decision int64
		ID       uuid.UUID
		Version  int32
		Overdue  bool
	}
	due, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (revoke, error) {
		var r revoke
		err := row.Scan(&r.Decision, &r.ID, &r.Version, &r.Overdue)
		return r, err
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range due {
		if r.Overdue {
			log.Error().Str("prepaid_purchase_id", r.ID.String()).Msg("staff revocation of reversed prepaid credit has waited over a day")
		}
		errs = append(errs, h.revokePrepaidGrant(ctx, client, r.Decision, r.ID, r.Version))
	}
	return errors.Join(errs...)
}

func (h *Handlers) revokePrepaidGrant(ctx context.Context, client *stripeHTTPClient, decision int64, id uuid.UUID, version int32) error {
	var team uuid.UUID
	var customer, creditState string
	var grant *string
	var voided bool
	if err := h.Pool.QueryRow(ctx, `SELECT team_id,customer_id,credit_state,stripe_credit_grant_id,credit_voided_at IS NOT NULL FROM billing_prepaid_purchase WHERE id=$1`, id).
		Scan(&team, &customer, &creditState, &grant, &voided); err != nil {
		return err
	}
	if creditState == "uncertain" || (creditState == "issued" && grant == nil) {
		return nil
	}
	release, err := h.holdCreditIssuanceFence(ctx, team)
	if errors.Is(err, errCreditIssuanceDeferred) {
		return nil
	}
	if err != nil {
		return err
	}
	defer release()
	var current entitlementGrant
	if creditState == "issued" && !voided {
		if current, err = client.retrieveEntitlementGrant(ctx, *grant); err != nil {
			return err
		}
		if current.Customer != customer || current.Metadata["prepaid_purchase_id"] != id.String() {
			return errors.New("credit grant is not bound to this purchase; operator recovery required")
		}
	}
	for {
		done, err := h.revokePrepaidGrantStep(ctx, client, decision, id, version, team, customer, creditState, grant, voided, current)
		if err != nil || done {
			return err
		}
	}
}

// One locked step of a revocation. The attempt is committed before the void,
// and the void runs while the reversal row is locked at the decided version, so
// a newer observation can never land between the check and the void. An
// attempted revocation is always settled: once the grant is confirmed live,
// every other attempt on the purchase is closed without voiding, so the one
// unsettled attempt left is the one any void belongs to, and it is audited at
// the amount Stripe's ledger shows voided.
func (h *Handlers) revokePrepaidGrantStep(ctx context.Context, client *stripeHTTPClient, decision int64, id uuid.UUID, version int32, team uuid.UUID, customer, creditState string, grant *string, voided bool, current entitlementGrant) (bool, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return true, err
	}
	defer tx.Rollback(ctx)
	var latest int32
	var attempted, settled, nowVoided bool
	var nowState string
	if err = tx.QueryRow(ctx, `SELECT r.version,d.revoke_attempted_at IS NOT NULL,d.revoked_at IS NOT NULL OR d.revoke_retry_after IS NOT DISTINCT FROM 'infinity' FROM billing_prepaid_reversal r JOIN billing_prepaid_reversal_decision d ON d.purchase_id=r.purchase_id AND d.id=$2
 WHERE r.purchase_id=$1 FOR UPDATE OF r,d`, id, decision).Scan(&latest, &attempted, &settled); err != nil {
		return true, err
	}
	if settled {
		return true, tx.Commit(ctx)
	}
	if err = tx.QueryRow(ctx, `SELECT credit_state,credit_voided_at IS NOT NULL FROM billing_prepaid_purchase WHERE id=$1 FOR UPDATE`, id).Scan(&nowState, &nowVoided); err != nil {
		return true, err
	}
	if nowState != creditState || nowVoided != voided {
		return true, tx.Commit(ctx)
	}
	superseded := latest != version
	live := creditState == "issued" && !voided
	if superseded && (!attempted || (live && current.VoidedAt == 0)) {
		if attempted {
			if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_reversal_decision SET revoke_retry_after='infinity' WHERE id=$1`, decision); err != nil {
				return true, err
			}
		}
		return true, tx.Commit(ctx)
	}
	if live && current.VoidedAt == 0 {
		if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_reversal_decision SET revoke_retry_after='infinity' WHERE purchase_id=$1 AND id<>$2 AND decision='revoke' AND revoke_attempted_at IS NOT NULL AND revoked_at IS NULL`, id, decision); err != nil {
			return true, err
		}
		if !attempted {
			if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_reversal_decision SET revoke_attempted_at=clock_timestamp() WHERE id=$1`, decision); err != nil {
				return true, err
			}
			return false, tx.Commit(ctx)
		}
		var g entitlementGrant
		if err = client.doForm(ctx, http.MethodPost, "/v1/billing/credit_grants/"+url.PathEscape(*grant)+"/void", url.Values{}, &g, "prepaid-credit-revoke:v1:"+id.String()); err != nil {
			return true, err
		}
		if g.ID != *grant || g.VoidedAt == 0 {
			return true, errors.New("credit grant revocation was not confirmed")
		}
	}
	amount, target := int64(0), decision
	if live {
		if amount, err = client.grantVoidedAmount(ctx, customer, *grant); err != nil {
			return true, err
		}
		var oldest *int64
		if err = tx.QueryRow(ctx, `SELECT (SELECT id FROM billing_prepaid_reversal_decision WHERE purchase_id=$1 AND decision='revoke' AND revoke_attempted_at IS NOT NULL
   AND revoked_at IS NULL AND revoke_retry_after IS DISTINCT FROM 'infinity' ORDER BY revoke_attempted_at,id LIMIT 1 FOR UPDATE)`, id).Scan(&oldest); err != nil {
			return true, err
		}
		if oldest != nil {
			target = *oldest
		}
	}
	if creditState == "issued" {
		if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_purchase SET credit_voided_at=clock_timestamp() WHERE id=$1 AND credit_voided_at IS NULL`, id); err != nil {
			return true, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_reversal_decision SET revoked_at=clock_timestamp(),revoked_cents=CASE WHEN id=$2 THEN $3 ELSE 0 END WHERE id IN ($1,$2) AND revoked_at IS NULL`, decision, target, amount); err != nil {
		return true, err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_funding_account SET next_check_at=LEAST(next_check_at,clock_timestamp()) WHERE team_id=$1 AND observe`, team); err != nil {
		return true, err
	}
	log.Warn().Str("prepaid_purchase_id", id.String()).Int64("revoked_cents", amount).Msg("revoked unspent credit of a reversed prepaid purchase by staff decision")
	return true, tx.Commit(ctx)
}

func (c *stripeHTTPClient) grantVoidedAmount(ctx context.Context, customer, grant string) (int64, error) {
	var total int64
	after := ""
	for {
		var page struct {
			Data []struct {
				ID    string `json:"id"`
				Type  string `json:"type"`
				Grant string `json:"credit_grant"`
				Debit *struct {
					Type   string `json:"type"`
					Amount struct {
						Monetary *struct {
							Currency string `json:"currency"`
							Value    int64  `json:"value"`
						} `json:"monetary"`
					} `json:"amount"`
				} `json:"debit"`
			} `json:"data"`
			HasMore bool `json:"has_more"`
		}
		q := url.Values{"customer": {customer}, "credit_grant": {grant}, "limit": {"100"}}
		if after != "" {
			q.Set("starting_after", after)
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_balance_transactions?"+q.Encode(), nil, &page, ""); err != nil {
			return 0, err
		}
		for _, tr := range page.Data {
			if tr.Grant != grant {
				return 0, errors.New("credit ledger returned another grant's transaction")
			}
			if tr.Type != "debit" || tr.Debit == nil || tr.Debit.Type != "credits_voided" {
				continue
			}
			m := tr.Debit.Amount.Monetary
			if m == nil || m.Currency != "usd" || m.Value < 0 {
				return 0, errors.New("invalid voided credit amount")
			}
			total += m.Value
		}
		if !page.HasMore || len(page.Data) == 0 {
			return total, nil
		}
		after = page.Data[len(page.Data)-1].ID
	}
}

// A purchase reversed before its credit was issued is never credited by the
// worker, whatever staff decide: keeping it records the decision, and any
// credit for it is a separate, explicitly authorised staff grant.
func (h *Handlers) prepaidCreditWithheld(ctx context.Context, id uuid.UUID) (bool, error) {
	var withheld bool
	err := h.Pool.QueryRow(ctx, `SELECT billing_prepaid_credit_withheld(p) FROM billing_prepaid_purchase p WHERE id=$1`, id).Scan(&withheld)
	return withheld, err
}

// A refund, dispute or credit note event asks for the purchases it may concern
// to be rechecked now, whatever their age; the check itself reads the
// provider. Disputes carry no customer, so they are matched by payment intent;
// first purchases paid by invoice are matched through their customer.
func requestPrepaidReversalCheck(ctx context.Context, q db.DBTX, customer, intent string) error {
	if customer == "" && intent == "" {
		return nil
	}
	_, err := q.Exec(ctx, `UPDATE billing_prepaid_purchase SET reversal_check_requested_at=clock_timestamp()
 WHERE payment_state='succeeded' AND ((NULLIF($2,'') IS NOT NULL AND (payment_intent_id=$2 OR (invoice_id IS NOT NULL AND reversal_payment_intents @> ARRAY[$2::text])))
  OR (NULLIF($1,'') IS NOT NULL AND customer_id=$1 AND invoice_id IS NOT NULL))`, customer, intent)
	return err
}

func (c *stripeHTTPClient) invoicePaymentIntents(ctx context.Context, invoice string) ([]string, error) {
	var payments struct {
		Data []struct {
			Invoice string `json:"invoice"`
			Payment struct {
				Type   string `json:"type"`
				Intent string `json:"payment_intent"`
			} `json:"payment"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	}
	q := url.Values{"invoice": {invoice}, "status": {"paid"}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoice_payments?"+q.Encode(), nil, &payments, ""); err != nil {
		return nil, err
	}
	if payments.HasMore {
		return nil, errors.New("purchase invoice payments exceed the supported bound")
	}
	var intents []string
	for _, p := range payments.Data {
		if p.Invoice == invoice && p.Payment.Type == "payment_intent" && p.Payment.Intent != "" {
			intents = append(intents, p.Payment.Intent)
		}
	}
	return intents, nil
}
