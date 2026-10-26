package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
)

type invoiceCollection struct {
	Invoice, Customer, Subscription, Hash, Key, State string
	LiveMode, Authorized                              bool
	FirstAttempt                                      *time.Time
	Token                                             uuid.UUID
}

// Compare the saved final settlement, not the current credit ledger: later
// periods may already have consumed credits while this payment is outstanding.
func invoiceSettlementHash(inv StripeInvoiceAmounts) string {
	inv.Status = ""
	inv.AutoAdvance = false
	inv.StatusTransitions.PaidAt = 0
	inv.AmountRemaining = nil
	inv.AmountPaid = nil
	inv.Lines.Data = append([]StripeInvoiceAmountLine(nil), inv.Lines.Data...)
	sort.Slice(inv.Lines.Data, func(i, j int) bool { return inv.Lines.Data[i].ID < inv.Lines.Data[j].ID })
	raw, _ := json.Marshal(inv)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (h *Handlers) enqueueInvoiceCollection(ctx context.Context, p billing.ExportPeriod, inv StripeInvoiceAmounts, authorized bool) error {
	if inv.Parent.SubscriptionDetails == nil {
		return fmt.Errorf("collection invoice has no subscription")
	}
	cashAllowed, err := h.invoiceResidualCashAllowed(ctx, inv.ID, inv.Customer, inv.Parent.SubscriptionDetails.Subscription)
	if err != nil {
		return err
	}
	authorized = authorized && inv.CollectionMethod == "charge_automatically" && cashAllowed
	state := "pending"
	if !authorized {
		state = "review_required"
	}
	if inv.Status == "paid" && inv.AmountRemaining != nil && *inv.AmountRemaining == 0 {
		state = "paid"
	}
	tag, err := h.Pool.Exec(ctx, `WITH released AS (
        UPDATE billing_invoice_close c SET state='released',last_error=NULL,updated_at=clock_timestamp()
        FROM team_billing_period p WHERE c.team_id=$1 AND c.period_start=$2 AND c.period_end=$3
          AND (p.team_id,p.period_start,p.period_end)=(c.team_id,c.period_start,c.period_end)
          AND c.invoice_id=$4 AND c.state='verified' AND p.finalized_at IS NOT NULL
          AND billing_invoice_close_matches(c.team_id,c.period_start,c.period_end)
        RETURNING c.invoice_id)
        INSERT INTO billing_invoice_collection(invoice_id,customer_id,subscription_id,livemode,settlement_hash,idempotency_key,payment_authorized,state)
        SELECT invoice_id,$5,$6,$7,$8,$9,$10,$11 FROM released`, p.TeamID, p.Start, p.End, inv.ID, inv.Customer,
		inv.Parent.SubscriptionDetails.Subscription, inv.LiveMode, invoiceSettlementHash(inv), "billing-invoice-pay:v1:"+inv.ID, authorized, state)
	if err == nil && tag.RowsAffected() != 1 {
		return fmt.Errorf("invoice collection handoff lost accounting authority")
	}
	return err
}

func (h *Handlers) startBillingInvoiceCollectionService(ctx context.Context) {
	go func() {
		timer := time.NewTimer(time.Duration(1+rand.IntN(10)) * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			for i := 0; i < 4 && ctx.Err() == nil; i++ {
				worked, err := h.invoiceCollectionTick(ctx)
				if err != nil {
					log.Warn().Err(err).Msg("billing invoice collection reconciliation failed")
				}
				if !worked {
					break
				}
			}
			timer.Reset(5*time.Second + time.Duration(rand.IntN(1000))*time.Millisecond)
		}
	}()
}

func (h *Handlers) claimInvoiceCollection(ctx context.Context) (invoiceCollection, error) {
	var job invoiceCollection
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return job, err
	}
	defer tx.Rollback(ctx)
	var locked bool
	// A short scheduling lock caps fleet-wide work without holding a connection
	// or transaction across Stripe calls.
	err = tx.QueryRow(ctx, `SELECT id FROM billing_invoice_collection_scheduler FOR UPDATE SKIP LOCKED`).Scan(&locked)
	if err != nil {
		return job, err
	}
	var active int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM billing_invoice_collection WHERE lease_until>clock_timestamp()`).Scan(&active); err != nil {
		return job, err
	}
	if active >= 4 {
		return job, pgx.ErrNoRows
	}
	job.Token = uuid.New()
	err = tx.QueryRow(ctx, `WITH candidate AS (
        SELECT invoice_id FROM billing_invoice_collection
        WHERE state NOT IN ('paid','void') AND next_attempt_at<=clock_timestamp()
          AND (lease_until IS NULL OR lease_until<=clock_timestamp())
        ORDER BY next_attempt_at,invoice_id LIMIT 1 FOR UPDATE SKIP LOCKED)
        UPDATE billing_invoice_collection j SET lease_token=$1,lease_until=clock_timestamp()+interval '2 minutes'
        FROM candidate c WHERE j.invoice_id=c.invoice_id
        RETURNING j.invoice_id,j.customer_id,j.subscription_id,j.livemode,j.settlement_hash,j.idempotency_key,j.payment_authorized,j.state,j.first_attempt_at`, job.Token).
		Scan(&job.Invoice, &job.Customer, &job.Subscription, &job.LiveMode, &job.Hash, &job.Key, &job.Authorized, &job.State, &job.FirstAttempt)
	if err != nil {
		return job, err
	}
	return job, tx.Commit(ctx)
}

func (h *Handlers) invoiceCollectionTick(ctx context.Context) (bool, error) {
	if os.Getenv("BILLING_AUTOMATIC_CLOSE_DISABLED") == "true" {
		return false, nil
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if h.Pool == nil || !ok {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	started := time.Now()
	job, err := h.claimInvoiceCollection(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	state, reason := h.collectInvoice(ctx, client, &job)
	delay := time.Minute
	if state == "requires_action" || state == "requires_payment_method" || state == "review_required" || state == "uncollectible" {
		delay = time.Hour
	}
	ack, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer stop()
	tag, err := h.Pool.Exec(ack, `UPDATE billing_invoice_collection SET state=$3,last_error=NULLIF($4,''),
        next_attempt_at=clock_timestamp()+$5::interval,lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp()
        WHERE invoice_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp()`, job.Invoice, job.Token, state, reason, delay.String())
	if err == nil && tag.RowsAffected() != 1 {
		err = fmt.Errorf("invoice collection lease lost")
	}
	if state != job.State {
		log.Info().Str("invoice_id", job.Invoice).Str("collection_state", state).Str("reason", reason).Msg("billing invoice collection state changed")
	}
	currentBillingRecorder().RecordBillingWork(ack, "invoice_collection", err != nil || reason != "", time.Since(started), 1)
	return true, err
}

func (h *Handlers) collectInvoice(ctx context.Context, c *stripeHTTPClient, job *invoiceCollection) (string, string) {
	inv, err := c.RetrieveBillingInvoice(ctx, job.Invoice)
	if err != nil {
		return job.State, "invoice retrieval unavailable"
	}
	if inv.Customer != job.Customer || inv.LiveMode != job.LiveMode || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != job.Subscription || invoiceSettlementHash(inv) != job.Hash {
		return "review_required", "invoice differs from verified settlement"
	}
	if inv.Status == "paid" && inv.AmountRemaining != nil && *inv.AmountRemaining == 0 {
		return "paid", ""
	}
	if inv.Status == "void" || inv.Status == "uncollectible" {
		return inv.Status, "invoice closed without payment"
	}
	if inv.CollectionMethod != "charge_automatically" || inv.Status != "open" || inv.AutoAdvance || inv.AmountRemaining == nil || *inv.AmountRemaining != inv.AmountDue || inv.AmountDue <= 0 {
		return "review_required", "invoice is not held open with the verified amount due"
	}
	cashAllowed, err := h.invoiceResidualCashAllowed(ctx, job.Invoice, job.Customer, job.Subscription)
	if err != nil {
		return "review_required", "historical invoice cash authority unavailable"
	}
	if !cashAllowed {
		return "review_required", "historical prepaid or ambiguous period requires review"
	}
	state, err := c.invoicePaymentState(ctx, inv)
	if err != nil {
		return job.State, "invoice payment evidence unavailable"
	}
	if state != "ready" {
		return state, ""
	}
	// Action-required and declined attempts never acquire a new automatic attempt.
	// Polling/webhooks can still observe a payment completed outside this worker.
	if !job.Authorized || (job.State != "pending" && job.State != "unknown") {
		return "review_required", "automatic payment requires review"
	}
	if job.FirstAttempt != nil && time.Since(*job.FirstAttempt) >= 23*time.Hour {
		return "review_required", "payment idempotency recovery window expired"
	}
	sub, err := c.invoiceSubscription(ctx, job.Subscription)
	if err != nil {
		return job.State, "subscription retrieval unavailable"
	}
	if err = h.verifyFirstProCycleProviderCalendar(ctx, h.Pool, sub); err != nil {
		return "review_required", "first Pro month subscription calendar requires review"
	}

	if sub.CollectionMethod != "charge_automatically" || sub.Customer != job.Customer || sub.LiveMode != job.LiveMode || (sub.Status != "canceled" && (sub.PauseCollection == nil || sub.PauseCollection.Behavior != "keep_as_draft" || sub.PauseCollection.ResumesAt != 0)) {
		return "review_required", "subscription collection method or hold changed"
	}
	// Persist intent before any network side effect. An expired worker cannot
	// initiate a new call; an uncertain call is replayed only with the same key.
	err = h.Pool.QueryRow(ctx, `UPDATE billing_invoice_collection SET first_attempt_at=COALESCE(first_attempt_at,clock_timestamp()),state='unknown'
        WHERE invoice_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp() AND (first_attempt_at IS NULL OR first_attempt_at>clock_timestamp()-interval '23 hours') RETURNING first_attempt_at`, job.Invoice, job.Token).Scan(&job.FirstAttempt)
	if err != nil {
		return "unknown", "payment intent could not be recorded"
	}
	err = c.doForm(ctx, http.MethodPost, "/v1/invoices/"+url.PathEscape(job.Invoice)+"/pay", url.Values{"off_session": {"true"}}, nil, job.Key)
	// Neither an HTTP success nor a payment_intent success proves a paid invoice:
	// retrieve the invoice and its payment evidence on the next pass.
	if err != nil {
		var se *stripeRequestError
		if errors.As(err, &se) && se.Status >= 400 && se.Status < 500 && se.Status != 409 && se.Status != 429 {
			return "review_required", fmt.Sprintf("payment request returned HTTP %d; reconcile before further action", se.Status)
		}
		return "unknown", "payment response uncertain; reconcile before replay"
	}
	return "unknown", ""
}

func (c *stripeHTTPClient) invoicePaymentState(ctx context.Context, inv StripeInvoiceAmounts) (string, error) {
	var list struct {
		HasMore bool `json:"has_more"`
		Data    []struct {
			Invoice  string `json:"invoice"`
			Currency string `json:"currency"`
			LiveMode bool   `json:"livemode"`
			Status   string `json:"status"`
			Payment  struct {
				Type   string `json:"type"`
				Intent *struct {
					ID        string `json:"id"`
					Customer  string `json:"customer"`
					Currency  string `json:"currency"`
					LiveMode  bool   `json:"livemode"`
					Status    string `json:"status"`
					LastError *struct {
						Code string `json:"code"`
					} `json:"last_payment_error"`
				} `json:"payment_intent"`
			} `json:"payment"`
		} `json:"data"`
	}
	query := url.Values{"invoice": {inv.ID}, "limit": {"100"}, "expand[]": {"data.payment.payment_intent"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoice_payments?"+query.Encode(), nil, &list, ""); err != nil {
		return "", err
	}
	if list.HasMore {
		return "review_required", nil
	}
	state := "ready"
	active := 0
	for _, p := range list.Data {
		if p.Invoice != inv.ID || p.Currency != inv.Currency || p.LiveMode != inv.LiveMode {
			return "review_required", nil
		}
		if p.Status == "canceled" {
			continue
		}
		active++
		if active > 1 {
			return "review_required", nil
		}
		pi := p.Payment.Intent
		if p.Payment.Type != "payment_intent" || pi == nil || pi.ID == "" || pi.Customer != inv.Customer || pi.Currency != inv.Currency || pi.LiveMode != inv.LiveMode {
			return "review_required", nil
		}
		if p.Status == "paid" {
			state = "processing"
			continue
		}
		if p.Status != "open" {
			return "review_required", nil
		}
		switch pi.Status {
		case "processing", "succeeded":
			state = "processing"
		case "requires_action":
			state = "requires_action"
		case "requires_payment_method":
			// Finalization can leave the intent without a method. Invoice /pay
			// resolves Billing defaults; only an actual failure parks the job.
			// An uncertain earlier call still reuses its saved key and window.
			if pi.LastError != nil {
				state = "requires_payment_method"
			}
		case "requires_confirmation":
			if pi.LastError != nil {
				return "review_required", nil
			}
		default:
			return "review_required", nil
		}
	}
	return state, nil
}

// An auto-recharge setting authorizes its saved top-up, never arbitrary invoice
// cash. Resolve once from the closed period and retain that immutable decision.
func (h *Handlers) invoiceResidualCashAllowed(ctx context.Context, invoice, customer, subscription string) (bool, error) {
	var allowed bool
	err := h.Pool.QueryRow(ctx, `SELECT a.policy='residual_allowed' AND a.customer_id=$2 AND a.subscription_id=$3
 FROM resolve_invoice_cash_authority($1) a`, invoice, customer, subscription).Scan(&allowed)
	return allowed, err
}
