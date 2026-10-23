package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
)

func (h *Handlers) RecoverProCheckout(c *gin.Context) {
	team, err := customerContextTeamID(c)
	if err != nil {
		return
	}
	if !h.requireCustomerTeamPermission(c, team, "billing:write") {
		return
	}
	if h.Pool == nil {
		respondError(c, ErrInternal)
		return
	}
	var input struct {
		Restart bool `json:"restart"`
	}
	if c.ShouldBindJSON(&input) != nil {
		respondErrorMsg(c, "bad_request", "invalid recovery request", 400)
		return
	}
	outcome, err := h.reconcileProCheckout(c.Request.Context(), team, input.Restart)
	if err != nil {
		log.Warn().Err(err).Str("team_id", team.String()).Msg("Pro checkout recovery pending")
		c.JSON(http.StatusAccepted, gin.H{"outcome": "payment_confirmation_pending"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"outcome": outcome})
}

func (h *Handlers) reconcileProCheckout(ctx context.Context, team uuid.UUID, restart bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return "", errors.New("Pro provider verification unavailable")
	}
	choice, err := h.getProChoice(ctx, team)
	if errors.Is(err, pgx.ErrNoRows) {
		return "no_pending_pro_purchase", nil
	}
	if err != nil {
		return "", err
	}
	var params StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(choice.Payload, &params); err != nil {
		return "", err
	}
	// Share the existing customer lease with legacy webhook processing.
	token := uuid.New()
	if _, err = h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: params.CustomerID, Token: token}); err != nil {
		return "", err
	}
	choice.LeaseToken = token
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = h.DB.ReleaseStripeWebhookProcessingLease(cleanup, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: params.CustomerID, Token: token})
	}()
	sessionID := derefString(choice.Session)
	if sessionID == "" {
		// Replay only frozen parameters within the existing safe retention window.
		if time.Since(choice.Generation) < 23*time.Hour {
			attempt := uuid.New()
			if _, err = h.DB.ResumeTeamBillingCheckout(ctx, db.ResumeTeamBillingCheckoutParams{TeamID: team, ActorID: pgtype.UUID{Bytes: choice.Actor, Valid: true}, RequestKey: &params.IdempotencyKey, AttemptID: attempt}); err != nil {
				return "", err
			}
			s, e := client.CreateCheckoutSession(ctx, params)
			if e != nil {
				released, finishErr := h.finishProCheckoutAttempt(ctx, choice, attempt, !definitiveStripeRejection(e))
				if finishErr != nil {
					return "", finishErr
				}
				if released {
					return "retryable", nil
				}
				return "", e
			}
			sessionID = s.ID
		} else {
			var list struct {
				Data    []StripeRetrievedCheckoutSession `json:"data"`
				HasMore bool                             `json:"has_more"`
			}
			if err = client.doForm(ctx, http.MethodGet, "/v1/checkout/sessions?"+url.Values{"customer": {params.CustomerID}, "limit": {"100"}}.Encode(), nil, &list, ""); err != nil {
				return "", err
			}
			if list.HasMore {
				return "", errors.New("checkout inventory requires operator recovery")
			}
			for _, s := range list.Data {
				if s.ClientReferenceID == team.String() && s.Metadata["checkout_generation"] == choice.Generation.Format(time.RFC3339Nano) {
					if sessionID != "" {
						return "", errors.New("multiple sessions match checkout generation")
					}
					sessionID = s.ID
				}
			}
			if sessionID == "" {
				return "", errors.New("unknown checkout creation outcome requires operator recovery")
			}
		}
	}
	session, err := client.RetrieveCheckoutSession(ctx, sessionID)
	if err != nil {
		return "", err
	}
	validSession := func(session StripeRetrievedCheckoutSession) bool {
		return session.ID == sessionID && session.CustomerID == params.CustomerID && session.ClientReferenceID == team.String() && session.Mode == "subscription" && session.Metadata["activation_user_id"] == choice.Actor.String() && session.Metadata["checkout_generation"] == choice.Generation.Format(time.RFC3339Nano) && session.Metadata["commercial_offer"] == choice.Offer
	}
	if !validSession(session) {
		return "", errors.New("checkout evidence differs from frozen purchase")
	}
	if restart && session.Status == "open" {
		var expired StripeRetrievedCheckoutSession
		if err = client.doForm(ctx, http.MethodPost, "/v1/checkout/sessions/"+url.PathEscape(sessionID)+"/expire", url.Values{}, &expired, "expire:"+sessionID); err != nil {
			return "", err
		}
		session, err = client.RetrieveCheckoutSession(ctx, sessionID)
		if err != nil {
			return "", err
		}
	}
	if !validSession(session) {
		return "", errors.New("checkout expiration evidence differs from purchase")
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: params.CustomerID, Token: token}); err != nil {
		return "", err
	}
	account, err := q.LockTeamBillingAccount(ctx, team)
	if err != nil {
		return "", err
	}
	current, err := scanProChoice(tx.QueryRow(ctx, `SELECT `+proChoiceColumns+` FROM billing_signup_choice WHERE team_id=$1 FOR UPDATE`, team))
	if err != nil {
		return "", err
	}
	if !current.Generation.Equal(choice.Generation) || derefString(account.StripeCustomerID) != session.CustomerID {
		return "", errors.New("checkout generation changed")
	}
	if session.Status == "expired" && session.SubscriptionID == "" && session.PaymentStatus != "paid" && current.Subscription == nil && current.State == "pending" {
		if err = q.RecordStripeCheckoutExpiration(ctx, db.RecordStripeCheckoutExpirationParams{TeamID: team, StripeCustomerID: session.CustomerID, CheckoutGeneration: choice.Generation, CheckoutSessionID: session.ID}); err != nil {
			return "", err
		}
		if err = q.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{TeamID: team, LeaseStartedAt: pgtype.Timestamptz{Time: choice.Generation, Valid: true}}); err != nil {
			return "", err
		}
		_, err = tx.Exec(ctx, resetProChoiceSQL, team)
		if err == nil {
			err = tx.Commit(ctx)
		}
		return "retryable", err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET session_id=$2,revision=revision+1 WHERE team_id=$1`, team, session.ID)
	if err != nil {
		return "", err
	}
	// Retain the generation after success so every late callback resolves to it.
	_, err = tx.Exec(ctx, `UPDATE team_billing_account SET checkout_session_id=$2,checkout_may_exist=true,checkout_pending_attempt_ids='{}' WHERE team_id=$1 AND checkout_initializing_at=$3`, team, session.ID, choice.Generation)
	if err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	if session.Status != "complete" || session.SubscriptionID == "" {
		return "payment_confirmation_pending", nil
	}
	sub, err := client.invoiceSubscription(ctx, session.SubscriptionID)
	if err != nil {
		return "", err
	}
	if sub.Customer != session.CustomerID || sub.Metadata["checkout_generation"] != session.Metadata["checkout_generation"] || sub.Metadata["commercial_offer"] != choice.Offer {
		return "", errors.New("subscription differs from checkout")
	}
	if sub.LatestInvoice != "" {
		var latest StripeInvoiceAmounts
		if err = client.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(sub.LatestInvoice), nil, &latest, ""); err != nil {
			return "", err
		}
		if latest.ID != sub.LatestInvoice || latest.Customer != sub.Customer || latest.Parent.SubscriptionDetails == nil || latest.Parent.SubscriptionDetails.Subscription != sub.ID || latest.Status == "" {
			return "", errors.New("latest invoice association is incomplete")
		}
		if _, err = h.Pool.Exec(ctx, `UPDATE team_billing_account b SET stripe_invoice_status=$3,updated_at=clock_timestamp() WHERE b.team_id=$1 AND b.stripe_customer_id=$2`, team, sub.Customer, latest.Status); err != nil {
			return "", err
		}
	}
	if restart && choice.State == "pending" && (sub.Status == "canceled" || sub.Status == "incomplete_expired") {
		reset, err := h.resetTerminalUnpaidPro(ctx, choice, session, sub, client)
		if err != nil {
			return "", err
		}
		if reset {
			return "retryable", nil
		}
	}
	offer, err := choice.frozenOffer()
	if err != nil {
		return "", err
	}
	ids, nextCursor, err := client.proInvoices(ctx, session.CustomerID, sub.ID, derefString(choice.InvoiceCursor))
	if err != nil {
		return "", err
	}
	known := map[string]bool{}
	rows, err := h.Pool.Query(ctx, `SELECT invoice_id FROM billing_pro_invoice_seen WHERE team_id=$1 AND invoice_id=ANY($2::text[])`, team, ids)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return "", err
		}
		known[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	// Revalidate every unexpired receipt independently of the history cache.
	usableReceipts := map[string]bool{}
	periods := map[string][2]int64{}
	rows, err = h.Pool.Query(ctx, `SELECT invoice_id,extract(epoch FROM service_period_start)::bigint,extract(epoch FROM service_period_end)::bigint FROM billing_contract_payment WHERE team_id=$1 AND service_period_end>clock_timestamp() ORDER BY service_period_end LIMIT 11`, team)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var id string
		var period [2]int64
		if err = rows.Scan(&id, &period[0], &period[1]); err != nil {
			rows.Close()
			return "", err
		}
		usableReceipts[id] = true
		periods[id] = period
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if len(usableReceipts) > 10 {
		return "", errors.New("unexpired payment inventory exceeds recovery bound")
	}
	listed := map[string]bool{}
	for _, id := range ids {
		listed[id] = true
	}
	for id := range usableReceipts {
		if !listed[id] {
			ids = append(ids, id)
		}
	}
	var receipts []proPaymentEvidence
	var verificationErrors []error
	var verifiedIDs []string
	for _, id := range ids {
		if known[id] && !usableReceipts[id] {
			verifiedIDs = append(verifiedIDs, id)
			continue
		}
		receipt, paid, e := client.verifyProInvoice(ctx, id, offer, session.CustomerID, sub.ID)
		if usableReceipts[id] {
			if e == nil && (!paid || periods[id] != [2]int64{receipt.Start, receipt.End}) {
				e = &proPaymentReviewError{reason: "paid invoice service period changed"}
			}
			if observeErr := h.observeProPaymentReview(ctx, team, id, receipt, e); observeErr != nil {
				e = errors.Join(e, observeErr)
			}
		}
		if e != nil {
			verificationErrors = append(verificationErrors, e)
			continue
		}
		verifiedIDs = append(verifiedIDs, id)
		if paid {
			receipts = append(receipts, receipt)
		}
	}
	// Observability only: this does not authorize activation or usage credits.
	for _, receipt := range receipts {
		if _, err = h.Pool.Exec(ctx, `UPDATE billing_signup_choice SET paid_observed_at=COALESCE(paid_observed_at,clock_timestamp()),paid_observed_until=GREATEST(paid_observed_until,$3) WHERE team_id=$1 AND generation=$2 AND state='pending'`, team, choice.Generation, time.Unix(receipt.End, 0)); err != nil {
			return "", err
		}
	}
	var resourceErr error
	if len(params.DeferredResourcePriceIDs) != 0 {
		sub, resourceErr = client.ensureProDeferredResources(ctx, sub, params, receipts)
	}
	resourcesReady := resourceErr == nil
	if resourcesReady {
		if _, _, err = proMeteredPeriod(sub, offer); err != nil {
			return "", err
		}
		if err = h.validateProResourceIdentities(ctx, team, sub, params); err != nil {
			return "", err
		}
	}
	terminalClosed := false
	if (sub.Status == "canceled" || sub.Status == "incomplete_expired") && nextCursor == "" && len(verificationErrors) == 0 {
		terminalClosed, err = h.proInvoicesClosed(ctx, client, team, sub.Customer, sub.ID, verifiedIDs)
		if err != nil {
			return "", err
		}
	}
	err = h.persistProPayments(ctx, choice, sub, receipts, terminalClosed, resourcesReady)
	if errors.Is(err, errProEnrollmentPending) {
		// Payment is already durable. Provider or local enrollment failures
		// leave activation pending and the existing worker can retry safely.
		err = h.enrollInvoiceAccount(ctx, team, nil)
		if err == nil {
			sub, err = client.invoiceSubscription(ctx, session.SubscriptionID)
		}
		if err == nil && (sub.ID != session.SubscriptionID || sub.Customer != session.CustomerID || sub.Metadata["checkout_generation"] != session.Metadata["checkout_generation"] || sub.Metadata["commercial_offer"] != choice.Offer) {
			err = errors.New("subscription changed during invoice enrollment")
		}
		if err == nil {
			err = h.validateProResourceIdentities(ctx, team, sub, params)
		}
		if err == nil {
			err = h.persistProPayments(ctx, choice, sub, receipts, false, true)
		}
	}
	if err != nil {
		return "", errors.Join(append(verificationErrors, err, resourceErr)...)
	}
	if resourceErr != nil && !errors.Is(resourceErr, errProResourcesUnpaid) {
		return "", resourceErr
	}
	// Cache only after the verified payments and activation transaction commits.
	_, err = h.Pool.Exec(ctx, `INSERT INTO billing_pro_invoice_seen(team_id,invoice_id) SELECT $1,unnest($2::text[]) ON CONFLICT DO NOTHING`, team, verifiedIDs)
	if err != nil {
		return "", err
	}
	_, err = h.Pool.Exec(ctx, `UPDATE billing_signup_choice SET invoice_cursor=NULLIF($3,''),next_check_at=CASE WHEN $4 AND $3='' AND NOT EXISTS(SELECT 1 FROM billing_contract_payment p WHERE p.team_id=$1 AND p.service_period_end>clock_timestamp()) THEN 'infinity'::timestamptz WHEN state='committed' THEN clock_timestamp()+interval '1 hour' ELSE clock_timestamp()+interval '2 minutes' END,last_error=NULL WHERE team_id=$1 AND generation=$2`, team, choice.Generation, nextCursor, terminalClosed)
	if err != nil {
		return "", err
	}
	if len(verificationErrors) > 0 {
		joined := errors.Join(verificationErrors...)
		_, saveErr := h.Pool.Exec(ctx, `UPDATE billing_signup_choice SET last_error=$2 WHERE team_id=$1 AND generation=$3`, team, joined.Error(), choice.Generation)
		return "", errors.Join(joined, saveErr)
	}
	var active bool
	err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND subscription_id=$2 AND status='active')`, team, sub.ID).Scan(&active)
	if err != nil {
		return "", err
	}
	if active {
		return "active", nil
	}
	return "payment_confirmation_pending", nil
}

// Reconciliation runs off the sandbox request path and recovers missed callbacks.
func (h *Handlers) StartProPaymentReconciliation(ctx context.Context) {
	h.startProBillingMonitoring(ctx)
	h.startYCReconciliation(ctx)
	if h.Pool == nil || h.Stripe == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			tick, cancel := context.WithTimeout(ctx, 50*time.Second)
			count, err := h.proPaymentReconciliationTick(tick)
			if err != nil {
				log.Warn().Err(err).Msg("Pro payment reconciliation pending")
			}
			cancel()
			if count == 4 {
				ticker.Reset(time.Second)
			} else {
				ticker.Reset(30 * time.Second)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
func (h *Handlers) proPaymentReconciliationTick(ctx context.Context) (int, error) {
	// offer_key<>'free' matches the partial recovery index predicate.
	rows, err := h.Pool.Query(ctx, `WITH candidate AS (SELECT team_id FROM billing_signup_choice WHERE offer_key<>'free' AND offer_key IN `+paidPlanOffers+` AND next_check_at<=clock_timestamp() ORDER BY next_check_at,team_id FOR UPDATE SKIP LOCKED LIMIT 4) UPDATE billing_signup_choice c SET next_check_at=clock_timestamp()+interval '2 minutes' FROM candidate WHERE c.team_id=candidate.team_id RETURNING c.team_id`)
	if err != nil {
		return 0, err
	}
	var teams []uuid.UUID
	for rows.Next() {
		var team uuid.UUID
		if err = rows.Scan(&team); err != nil {
			rows.Close()
			return 0, err
		}
		teams = append(teams, team)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	jobs := make(chan uuid.UUID, len(teams))
	for _, team := range teams {
		jobs <- team
	}
	close(jobs)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for team := range jobs {
				started := time.Now()
				_, e := h.reconcileProCheckout(ctx, team, false)
				var message *string
				if e != nil {
					s := e.Error()
					message = &s
					log.Warn().Err(e).Str("team_id", team.String()).Msg("Pro payment reconciliation pending")
				}
				ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
				_, saveErr := h.Pool.Exec(ack, `UPDATE billing_signup_choice SET last_error=$2 WHERE team_id=$1`, team, message)
				cancel()
				currentBillingRecorder().RecordBillingWork(ctx, "pro_payment", e != nil || saveErr != nil, time.Since(started), 1)
			}
		}()
	}
	wg.Wait()
	return len(teams), ctx.Err()
}

func (h *Handlers) validateProResourceIdentities(ctx context.Context, team uuid.UUID, sub invoiceSubscription, params StripeCreateCheckoutSessionParams) error {
	expected := map[string]bool{}
	for _, id := range append(append([]string{}, params.PriceIDs...), params.DeferredResourcePriceIDs...) {
		expected[id] = false
	}
	var rounding string
	err := h.Pool.QueryRow(ctx, `SELECT adjustment_price_id FROM billing_invoice_account WHERE team_id=$1 AND subscription_id=$2`, team, sub.ID).Scan(&rounding)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	for _, item := range sub.Items.Data {
		if item.Price.ID == params.BasePriceID || (rounding != "" && item.Price.ID == rounding) {
			continue
		}
		if _, ok := expected[item.Price.ID]; !ok {
			return errors.New("unexpected Pro resource price")
		}
		expected[item.Price.ID] = true
	}
	for _, present := range expected {
		if !present {
			return errors.New("Pro resource price is missing")
		}
	}
	offer, err := frozenProOffer(params.Metadata["commercial_offer"], params)
	if err != nil {
		return err
	}
	offer.Price = params.BasePriceID
	base := invoiceBase{Price: offer.Price, Amount: offer.Amount, Months: offer.Months, Anchor: time.Unix(sub.StartDate, 0)}
	filtered, err := base.stripSubscription(sub)
	if err != nil {
		return err
	}
	if err = invoiceCalendarCompatible(base.Anchor, filtered, rounding); err != nil {
		return err
	}
	return validateFrozenProResources(filtered, params.ResourceTerms, rounding)
}

// A terminal subscription is restartable only when every invoice and payment
// is closed without funds. Keep the tombstone so late events cannot enter PAYG.
func (h *Handlers) resetTerminalUnpaidPro(ctx context.Context, choice proChoice, session StripeRetrievedCheckoutSession, sub invoiceSubscription, client *stripeHTTPClient) (bool, error) {
	var list struct {
		Data    []proPaidInvoice `json:"data"`
		HasMore bool             `json:"has_more"`
	}
	if err := client.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"customer": {sub.Customer}, "subscription": {sub.ID}, "limit": {"100"}}.Encode(), nil, &list, ""); err != nil {
		return false, err
	}
	if list.HasMore {
		return false, errors.New("unpaid subscription inventory is incomplete")
	}
	for _, inv := range list.Data {
		if inv.AmountPaid > 0 || inv.Status == "paid" {
			return false, nil
		}
		if inv.Customer != sub.Customer || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != sub.ID || inv.AmountPaid != 0 || inv.Status != "void" {
			return false, errors.New("subscription retains payment capability or paid evidence")
		}
		var payments struct {
			Data []struct {
				Status     string `json:"status"`
				AmountPaid int64  `json:"amount_paid"`
				Payment    struct {
					Type   string `json:"type"`
					Intent string `json:"payment_intent"`
				} `json:"payment"`
			} `json:"data"`
			HasMore bool `json:"has_more"`
		}
		if err := client.doForm(ctx, http.MethodGet, "/v1/invoice_payments?"+url.Values{"invoice": {inv.ID}, "limit": {"100"}}.Encode(), nil, &payments, ""); err != nil {
			return false, err
		}
		if payments.HasMore {
			return false, errors.New("unpaid invoice payment inventory is incomplete")
		}
		for _, p := range payments.Data {
			if p.Status == "paid" || p.AmountPaid != 0 || p.Payment.Type != "payment_intent" || p.Payment.Intent == "" {
				return false, errors.New("invoice payment is not proven unpaid")
			}
			var intent struct {
				ID, Status, Customer string
				AmountReceived       int64 `json:"amount_received"`
			}
			if err := client.doForm(ctx, http.MethodGet, "/v1/payment_intents/"+url.PathEscape(p.Payment.Intent), nil, &intent, ""); err != nil {
				return false, err
			}
			if intent.ID != p.Payment.Intent || intent.Customer != sub.Customer || intent.Status != "canceled" || intent.AmountReceived != 0 {
				return false, errors.New("payment intent can still complete or received funds")
			}
		}
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: sub.Customer, Token: choice.LeaseToken}); err != nil {
		return false, err
	}
	a, err := q.LockTeamBillingAccount(ctx, choice.Team)
	if err != nil {
		return false, err
	}
	current, err := scanProChoice(tx.QueryRow(ctx, `SELECT `+proChoiceColumns+` FROM billing_signup_choice WHERE team_id=$1 FOR UPDATE`, choice.Team))
	if err != nil {
		return false, err
	}
	if !current.Generation.Equal(choice.Generation) || current.State != "pending" || a.TrialEndedAt.Valid || a.StripeSubscriptionID != nil {
		return false, errors.New("purchase is already associated or committed")
	}
	var historical bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1)`, choice.Team).Scan(&historical); err != nil {
		return false, err
	}
	if historical {
		return false, errors.New("commercial history requires reconciliation")
	}
	evidence, _ := json.Marshal(struct {
		Session      StripeRetrievedCheckoutSession
		Subscription invoiceSubscription
		Invoices     any
	}{session, sub, list})
	if _, err = tx.Exec(ctx, `INSERT INTO billing_pro_closed_purchase(team_id,generation,session_id,subscription_id,evidence) VALUES($1,$2,$3,$4,$5)`, choice.Team, choice.Generation, session.ID, sub.ID, evidence); err != nil {
		return false, err
	}
	// Older webhook processors use this generation fence as well.
	if err = q.RecordStripeCheckoutExpiration(ctx, db.RecordStripeCheckoutExpirationParams{TeamID: choice.Team, StripeCustomerID: sub.Customer, CheckoutGeneration: choice.Generation, CheckoutSessionID: session.ID}); err != nil {
		return false, err
	}
	if err = q.AbortTeamBillingCheckout(ctx, db.AbortTeamBillingCheckoutParams{TeamID: choice.Team, LeaseStartedAt: pgtype.Timestamptz{Time: choice.Generation, Valid: true}}); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, resetProChoiceSQL, choice.Team); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// An unfiltered inventory cannot hide an invoice transitioning from open to
// paid between status-filtered reads. Every paid invoice must already be verified.
func (h *Handlers) proInvoicesClosed(ctx context.Context, c *stripeHTTPClient, team uuid.UUID, customer, subscription string, verified []string) (bool, error) {
	var list struct {
		Data    []proPaidInvoice `json:"data"`
		HasMore bool             `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+url.Values{"customer": {customer}, "subscription": {subscription}, "limit": {"100"}}.Encode(), nil, &list, ""); err != nil {
		return false, err
	}
	if list.HasMore {
		return false, nil
	}
	known := map[string]bool{}
	for _, id := range verified {
		known[id] = true
	}
	var ids []string
	for _, inv := range list.Data {
		ids = append(ids, inv.ID)
	}
	rows, err := h.Pool.Query(ctx, `SELECT invoice_id FROM billing_pro_invoice_seen WHERE team_id=$1 AND invoice_id=ANY($2::text[])`, team, ids)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		known[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	for _, inv := range list.Data {
		if inv.Status == "paid" && known[inv.ID] {
			continue
		}
		if inv.Status == "void" && inv.AmountPaid == 0 {
			continue
		}
		return false, nil
	}
	return true, nil
}
