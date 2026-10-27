package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
)

const prepaidAutoRechargeDailyCap = 10

type prepaidPaymentIntent struct {
	ID             string            `json:"id"`
	Status         string            `json:"status"`
	Amount         int64             `json:"amount"`
	AmountReceived int64             `json:"amount_received"`
	Currency       string            `json:"currency"`
	Customer       string            `json:"customer"`
	PaymentMethod  string            `json:"payment_method"`
	Created        int64             `json:"created"`
	Metadata       map[string]string `json:"metadata"`
	LastError      *struct {
		Code        string `json:"code"`
		DeclineCode string `json:"decline_code"`
		Message     string `json:"message"`
	} `json:"last_payment_error"`
}

type prepaidPaymentRequest struct {
	Customer      string `json:"customer"`
	PaymentMethod string `json:"payment_method"`
	AmountCents   int64  `json:"amount_cents"`
}

func (h *Handlers) startPrepaidCredits(ctx context.Context, client *stripeHTTPClient) {
	go func() {
		for ctx.Err() == nil {
			started := time.Now()
			err := h.prepaidTick(ctx, client)
			currentBillingRecorder().RecordBillingWork(ctx, "prepaid_credit", err != nil, time.Since(started), 1)
			if err != nil {
				log.Warn().Err(err).Msg("prepaid credit reconciliation failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}()
}

func (h *Handlers) prepaidTick(ctx context.Context, client *stripeHTTPClient) error {
	return runBillingPhases(ctx, time.Minute,
		h.recordAutoRecharges,
		func(ctx context.Context) error { return h.settleDuePrepaidPurchases(ctx, client) },
		h.retryPrepaidEnrolment,
		h.startPrepaidEnforcement,
		func(ctx context.Context) error { return h.voidSpentPrepaidGrants(ctx, client) },
		func(ctx context.Context) error { return h.reviewPrepaidReversals(ctx, client) },
		func(ctx context.Context) error { return h.revokeReversedPrepaidCredit(ctx, client) },
		h.notifyDisabledAutoRecharges,
	)
}

const prepaidAutoRechargeCapReason = "the recharge amount or threshold exceeds the $10,000 limit; update your settings before enabling it again"

func (h *Handlers) disableOversizedAutoRecharges(ctx context.Context) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT t.id FROM team t JOIN billing_prepaid_auto_recharge a ON a.team_id=t.id
 WHERE a.enabled AND (a.amount_cents>$1 OR a.threshold_cents>$1)
 ORDER BY t.id LIMIT 50 FOR NO KEY UPDATE OF t SKIP LOCKED`, prepaidPurchaseMaxCents)
	if err != nil {
		return err
	}
	teams, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	// Recheck after taking the same team lock as settings edits. Never disable a
	// corrected setting or reset a prior disable notification.
	_, err = tx.Exec(ctx, `UPDATE billing_prepaid_auto_recharge SET enabled=false,
 disabled_reason=$1,disabled_at=clock_timestamp(),disabled_by=NULL,notified_at=NULL,updated_at=clock_timestamp()
 WHERE team_id=ANY($2) AND enabled AND (amount_cents>$3 OR threshold_cents>$3)`, prepaidAutoRechargeCapReason, teams, prepaidPurchaseMaxCents)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// A charge is created only from a balance observed after the team's latest
// credit, so a purchase the observation has not yet seen never triggers another.
func (h *Handlers) recordAutoRecharges(ctx context.Context) error {
	if err := h.disableOversizedAutoRecharges(ctx); err != nil {
		return err
	}
	if _, err := h.Pool.Exec(ctx, `UPDATE billing_prepaid_auto_recharge a SET enabled=false,disabled_reason=$1,disabled_at=clock_timestamp(),notified_at=NULL
 WHERE a.enabled AND (SELECT count(*) FROM billing_prepaid_purchase p WHERE p.team_id=a.team_id AND p.source='auto_recharge' AND p.created_at>clock_timestamp()-interval '24 hours')>=$2`,
		fmt.Sprintf("more than %d automatic recharges in 24 hours", prepaidAutoRechargeDailyCap), prepaidAutoRechargeDailyCap); err != nil {
		return err
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	selection := ` FROM billing_prepaid_auto_recharge a
 JOIN team t ON t.id=a.team_id
 JOIN billing_funding_account f USING(team_id)
 JOIN team_billing_account b USING(team_id)
 WHERE a.enabled AND a.amount_cents BETWEEN 500 AND $2 AND a.amount_cents%500=0
 AND a.threshold_cents BETWEEN 500 AND $2 AND a.threshold_cents%500=0 AND EXISTS(SELECT 1 FROM team_plan_assignment p WHERE p.team_id=a.team_id AND p.effective_to IS NULL AND p.kind='prepaid')
 AND f.observe AND f.payment_method_ready AND f.payment_method_id IS NOT NULL
  AND f.observed_generation=f.generation AND f.customer_id=b.stripe_customer_id
  AND f.credit_checked_at>clock_timestamp()-interval '2 minutes' AND f.credit_usd*100<a.threshold_cents
  AND NOT EXISTS(SELECT 1 FROM billing_prepaid_purchase p WHERE p.team_id=a.team_id
   AND ((p.source='auto_recharge' AND p.payment_state IN ('pending','uncertain','processing'))
    OR (p.payment_state='succeeded' AND (p.credit_state<>'issued' OR p.credited_at>=f.credit_checked_at)
     AND NOT billing_prepaid_credit_withheld(p))))
  AND (SELECT count(*) FROM billing_prepaid_purchase p WHERE p.team_id=a.team_id AND p.payment_state<>'failed' AND p.credit_voided_at IS NULL
   AND NOT billing_prepaid_credit_withheld(p))<$1`
	rows, err := tx.Query(ctx, `SELECT t.id`+selection+` ORDER BY t.id LIMIT 50 FOR NO KEY UPDATE OF t SKIP LOCKED`, prepaidLiveGrantLimit, prepaidPurchaseMaxCents)
	if err != nil {
		return err
	}
	teams, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_prepaid_purchase(team_id,customer_id,source,amount_cents,payment_idempotency_key,credit_idempotency_key,payment_request)
 SELECT a.team_id,b.stripe_customer_id,'auto_recharge',a.amount_cents,'','',
  jsonb_build_object('customer',b.stripe_customer_id,'payment_method',f.payment_method_id,'amount_cents',a.amount_cents)`+selection+`
 AND a.team_id=ANY($3) ON CONFLICT DO NOTHING`, prepaidLiveGrantLimit, prepaidPurchaseMaxCents, teams)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) settleDuePrepaidPurchases(ctx context.Context, client *stripeHTTPClient) error {
	rows, err := h.Pool.Query(ctx, `SELECT id FROM billing_prepaid_purchase
 WHERE (payment_state IN ('pending','uncertain','processing') OR credit_state IN ('none','pending','uncertain')) AND payment_state<>'failed'
  AND NOT (payment_state='succeeded' AND credit_state='issued') AND next_attempt_at<=clock_timestamp()
  AND NOT billing_prepaid_credit_withheld(billing_prepaid_purchase)
 ORDER BY next_attempt_at,id LIMIT 20`)
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
		workErr := h.settlePrepaidPurchase(ctx, client, id)
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		var err error
		switch {
		case workErr == nil:
			_, err = h.Pool.Exec(ack, `UPDATE billing_prepaid_purchase SET failures=0,last_error=NULL WHERE id=$1`, id)
		case errors.Is(workErr, errCreditIssuanceDeferred) || errors.Is(workErr, errCreditInventoryPending):
			_, err = h.Pool.Exec(ack, `UPDATE billing_prepaid_purchase SET last_error=$2,next_attempt_at=clock_timestamp()+interval '30 seconds' WHERE id=$1`, id, workErr.Error())
			workErr = nil
		case errors.Is(workErr, errPrepaidPaymentPending):
			var seconds int64
			_ = h.Pool.QueryRow(ack, `SELECT extract(epoch FROM clock_timestamp()-created_at)::bigint FROM billing_prepaid_purchase WHERE id=$1`, id).Scan(&seconds)
			age := time.Duration(seconds) * time.Second
			delay := 30 * time.Second
			if age > time.Hour {
				delay = 10 * time.Minute
			}
			if age > 72*time.Hour {
				delay = time.Hour
				log.Error().Str("prepaid_purchase_id", id.String()).Err(workErr).Msg("prepaid purchase has been unsettled for days; operator review required")
			}
			_, err = h.Pool.Exec(ack, `UPDATE billing_prepaid_purchase SET last_error=$2,next_attempt_at=clock_timestamp()+$3::interval WHERE id=$1`, id, workErr.Error(), delay.String())
			workErr = nil
		default:
			log.Error().Err(workErr).Str("prepaid_purchase_id", id.String()).Msg("prepaid purchase settlement failed")
			_, err = h.Pool.Exec(ack, `UPDATE billing_prepaid_purchase SET failures=least(failures+1,10000),last_error=$2,
 next_attempt_at=clock_timestamp()+make_interval(secs=>least(300,10*power(2,least(failures,5)))::double precision) WHERE id=$1`, id, workErr.Error())
		}
		cancel()
		errs = append(errs, workErr, err)
	}
	return errors.Join(errs...)
}

var errPrepaidPaymentPending = errors.New("prepaid payment is still processing")

func (h *Handlers) settlePrepaidPurchase(ctx context.Context, client *stripeHTTPClient, id uuid.UUID) error {
	var team uuid.UUID
	var source, paymentState string
	if err := h.Pool.QueryRow(ctx, `SELECT team_id,source,payment_state FROM billing_prepaid_purchase WHERE id=$1`, id).Scan(&team, &source, &paymentState); err != nil {
		return err
	}
	if paymentState != "succeeded" {
		var err error
		if source == "auto_recharge" {
			err = h.chargeAutoRecharge(ctx, client, id)
		} else {
			err = h.settleCheckoutPurchase(ctx, client, id)
		}
		if err != nil {
			return err
		}
		if err = h.Pool.QueryRow(ctx, `SELECT payment_state FROM billing_prepaid_purchase WHERE id=$1`, id).Scan(&paymentState); err != nil || paymentState != "succeeded" {
			return err
		}
	}
	if source == "checkout" {
		// Record verified cash before holding first-subscription fulfillment. The
		// managed account policy forbids the association needed to complete it.
		var managedFirst bool
		if err := h.Pool.QueryRow(ctx, `SELECT COALESCE(payment_evidence->'checkout_session'->>'mode'='subscription',payment_request IS NULL) AND qm_team_managed_billing(team_id) FROM billing_prepaid_purchase WHERE id=$1`, id).Scan(&managedFirst); err != nil {
			return err
		}
		if managedFirst {
			return errPrepaidPaymentPending
		}
		if err := assignStarterAfterPurchase(ctx, h, team, id); err != nil {
			return err
		}
		if err := h.enrolPrepaidObservation(ctx, team); err != nil {
			return err
		}
	}
	return h.issuePrepaidCredit(ctx, client, id)
}

func (h *Handlers) chargeAutoRecharge(ctx context.Context, client *stripeHTTPClient, id uuid.UUID) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var team uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT team_id FROM billing_prepaid_purchase WHERE id=$1`, id).Scan(&team); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
		return err
	}
	var state, key string
	err = tx.QueryRow(ctx, `SELECT payment_state,payment_idempotency_key FROM billing_prepaid_purchase WHERE id=$1 FOR UPDATE`, id).Scan(&state, &key)
	if err != nil {
		return err
	}
	if state == "pending" {
		var enabled bool
		if err = tx.QueryRow(ctx, `SELECT enabled FROM billing_prepaid_auto_recharge WHERE team_id=$1 FOR SHARE`, team).Scan(&enabled); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		plan, ok, err := currentTeamPlan(ctx, tx, team)
		if err != nil {
			return err
		}
		if !enabled || !ok || plan.Kind != planKindPrepaid {
			if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_purchase SET payment_state='failed',failure_reason='auto-recharge is disabled or the team has left prepaid before dispatch' WHERE id=$1 AND payment_state='pending'`, id); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
	}
	var raw []byte
	var first *time.Time
	var intentID *string
	err = tx.QueryRow(ctx, `UPDATE billing_prepaid_purchase SET payment_state=CASE WHEN payment_state='pending' THEN 'uncertain' ELSE payment_state END,
 payment_first_attempt_at=COALESCE(payment_first_attempt_at,clock_timestamp())
 WHERE id=$1 AND payment_state IN ('pending','uncertain','processing') RETURNING payment_request,payment_first_attempt_at,payment_intent_id`, id).Scan(&raw, &first, &intentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	var req prepaidPaymentRequest
	if err = json.Unmarshal(raw, &req); err != nil {
		return err
	}
	if req.Customer == "" || req.PaymentMethod == "" || req.AmountCents <= 0 {
		return errors.New("incomplete saved auto-recharge request")
	}
	var pi prepaidPaymentIntent
	switch {
	case intentID != nil:
		pi, err = client.retrievePrepaidPaymentIntent(ctx, *intentID)
	case time.Since(*first) >= 23*time.Hour:
		var found bool
		pi, found, err = client.findPrepaidPaymentIntent(ctx, req.Customer, id, *first)
		if err == nil && !found {
			return h.failPrepaidPayment(ctx, id, "", "the charge never reached Stripe", false)
		}
	default:
		form := url.Values{
			"amount": {strconv.FormatInt(req.AmountCents, 10)}, "currency": {"usd"}, "customer": {req.Customer},
			"payment_method": {req.PaymentMethod}, "payment_method_types[]": {"card"}, "off_session": {"true"}, "confirm": {"true"},
			"description":                   {"Superserve prepaid credit (auto-recharge)"},
			"metadata[prepaid_purchase_id]": {id.String()}, "metadata[team_id]": {team.String()},
		}
		err = client.doForm(ctx, http.MethodPost, "/v1/payment_intents", form, &pi, key)
		var se *stripeRequestError
		if errors.As(err, &se) && (se.Status == http.StatusPaymentRequired || definitiveStripeRejection(err)) && !strings.Contains(se.Message, "idempotency_error") {
			return h.failPrepaidPayment(ctx, id, "card_error", "the saved card was declined or needs authentication", true)
		}
	}
	if err != nil {
		return err
	}
	return h.recordPrepaidPaymentIntent(ctx, id, req, pi)
}

func (h *Handlers) recordPrepaidPaymentIntent(ctx context.Context, id uuid.UUID, req prepaidPaymentRequest, pi prepaidPaymentIntent) error {
	if pi.ID == "" || pi.Customer != req.Customer || pi.Metadata["prepaid_purchase_id"] != id.String() || pi.Currency != "usd" || pi.Amount != req.AmountCents {
		return errors.New("payment intent does not match the saved auto-recharge request")
	}
	var state string
	if err := h.Pool.QueryRow(ctx, `UPDATE billing_prepaid_purchase SET payment_intent_id=COALESCE(payment_intent_id,$2),
 payment_state=CASE WHEN payment_state='uncertain' THEN 'processing' ELSE payment_state END WHERE id=$1 RETURNING payment_state`, id, pi.ID).Scan(&state); err != nil {
		return err
	}
	if state == "failed" {
		if pi.Status == "succeeded" || pi.Status == "processing" {
			log.Error().Str("prepaid_purchase_id", id.String()).Str("payment_intent", pi.ID).Msg("a failed prepaid purchase has a live payment; operator must credit or refund it")
			return errors.New("failed prepaid purchase has a live payment; operator recovery required")
		}
		return nil
	}
	switch pi.Status {
	case "succeeded":
		if pi.AmountReceived != req.AmountCents {
			return errors.New("payment intent received a different amount")
		}
		raw, _ := json.Marshal(map[string]any{"amount_cents": pi.AmountReceived, "customer": pi.Customer, "payment_intent": pi})
		_, err := h.Pool.Exec(ctx, `UPDATE billing_prepaid_purchase SET payment_state='succeeded',payment_evidence=$2,paid_at=clock_timestamp() WHERE id=$1 AND payment_state='processing'`, id, raw)
		return err
	case "processing":
		return errPrepaidPaymentPending
	case "requires_payment_method", "requires_action", "canceled":
		code := ""
		if pi.LastError != nil {
			code = pi.LastError.Code
		}
		return h.failPrepaidPayment(ctx, id, code, "the saved card was declined or needs authentication", true)
	default:
		return fmt.Errorf("unexpected auto-recharge payment status %q", pi.Status)
	}
}

// A failed automatic charge turns auto-recharge off so the customer is never
// retried silently; they choose whether to fix the card and enable it again.
// A payment fails only from the states the caller's evidence covers: a row that
// may already have reached Stripe needs terminal provider evidence to fail.
func (h *Handlers) failPrepaidPayment(ctx context.Context, id uuid.UUID, code, reason string, disable bool, from ...string) error {
	if len(from) == 0 {
		from = []string{"pending", "uncertain", "processing"}
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var team uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE billing_prepaid_purchase SET payment_state='failed',failure_code=NULLIF($2,''),failure_reason=$3 WHERE id=$1 AND payment_state=ANY($4) RETURNING team_id`, id, code, reason, from).Scan(&team)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if disable {
		if _, err = tx.Exec(ctx, `UPDATE billing_prepaid_auto_recharge SET enabled=false,disabled_reason=$2,disabled_at=clock_timestamp(),notified_at=NULL WHERE team_id=$1 AND enabled`, team, reason); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (c *stripeHTTPClient) retrievePrepaidPaymentIntent(ctx context.Context, id string) (prepaidPaymentIntent, error) {
	var pi prepaidPaymentIntent
	err := c.doForm(ctx, http.MethodGet, "/v1/payment_intents/"+url.PathEscape(id), nil, &pi, "")
	if err == nil && pi.ID != id {
		err = errors.New("payment intent identity changed")
	}
	return pi, err
}

func (c *stripeHTTPClient) findPrepaidPaymentIntent(ctx context.Context, customer string, id uuid.UUID, first time.Time) (prepaidPaymentIntent, bool, error) {
	var found []prepaidPaymentIntent
	cursor := ""
	for page := 0; page < 20; page++ {
		q := url.Values{"customer": {customer}, "limit": {"100"}, "created[gte]": {strconv.FormatInt(first.Add(-time.Minute).Unix(), 10)}}
		if cursor != "" {
			q.Set("starting_after", cursor)
		}
		var list struct {
			Data    []prepaidPaymentIntent `json:"data"`
			HasMore bool                   `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/payment_intents?"+q.Encode(), nil, &list, ""); err != nil {
			return prepaidPaymentIntent{}, false, err
		}
		for _, pi := range list.Data {
			if pi.Metadata["prepaid_purchase_id"] == id.String() {
				found = append(found, pi)
			}
		}
		if !list.HasMore {
			if len(found) > 1 {
				return prepaidPaymentIntent{}, false, errors.New("multiple payment intents carry one purchase identity; operator recovery required")
			}
			if len(found) == 1 {
				return found[0], true, nil
			}
			return prepaidPaymentIntent{}, false, nil
		}
		if len(list.Data) == 0 {
			return prepaidPaymentIntent{}, false, errors.New("empty incomplete payment intent page")
		}
		cursor = list.Data[len(list.Data)-1].ID
	}
	return prepaidPaymentIntent{}, false, errors.New("payment intent inventory exceeds the discovery bound")
}

func (h *Handlers) notifyDisabledAutoRecharges(ctx context.Context) error {
	sender, from := h.EmailTransport.Sender(os.Getenv("RESEND_API_KEY")), os.Getenv("QUOTA_EMAIL_FROM")
	if sender == nil || from == "" {
		return nil
	}
	rows, err := h.Pool.Query(ctx, `SELECT team_id,disabled_reason,disabled_at FROM billing_prepaid_auto_recharge
 WHERE NOT enabled AND disabled_at IS NOT NULL AND notified_at IS NULL AND disabled_by IS NULL AND disabled_at>clock_timestamp()-interval '7 days' LIMIT 20`)
	if err != nil {
		return err
	}
	type disabled struct {
		Team   uuid.UUID
		Reason string
		At     time.Time
	}
	var due []disabled
	for rows.Next() {
		var d disabled
		if err = rows.Scan(&d.Team, &d.Reason, &d.At); err != nil {
			rows.Close()
			return err
		}
		due = append(due, d)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	var errs []error
	for _, d := range due {
		recipients, err := h.DB.ListTrialCreditWarningRecipients(ctx, d.Team)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sent := true
		for _, to := range dedupeWarningRecipients(recipients) {
			err = sender.SendEmail(ctx, EmailMessage{From: from, To: to, Subject: "Superserve auto-recharge was turned off",
				Text:           "Automatic recharge of your Superserve prepaid credit was turned off: " + d.Reason + ".\n\nYour sandboxes keep running while you have credit left. To keep them running, add credit or update your card and turn auto-recharge back on from the billing page.",
				IdempotencyKey: fmt.Sprintf("prepaid-auto-recharge-off:%s:%d:%s", d.Team, d.At.Unix(), to)})
			var rejected *rejectedEmailError
			if err != nil && !errors.As(err, &rejected) {
				sent = false
				errs = append(errs, err)
			}
		}
		if sent {
			_, err = h.Pool.Exec(ctx, `UPDATE billing_prepaid_auto_recharge SET notified_at=clock_timestamp() WHERE team_id=$1 AND disabled_at=$2 AND notified_at IS NULL`, d.Team, d.At)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
