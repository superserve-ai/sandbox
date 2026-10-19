package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

var errEntitlementNotFound = errors.New("saved entitlement is absent from completed grant inventory")

type entitlementJob struct{ Contract, Token uuid.UUID }

// Fresh work and retries have separate bounded capacity. Provider I/O never
// runs while selecting or locking due rows.
func (h *Handlers) StartUsageEntitlementService(ctx context.Context) {
	if h.Pool == nil {
		return
	}
	if _, ok := h.Stripe.(*stripeHTTPClient); !ok {
		return
	}
	workers := 8
	h.startEntitlementCoverageMonitoring(ctx)
	h.startSponsoredReconciliation(ctx)
	if h.Config != nil && h.Config.BillingEntitlementWorkers >= 2 {
		workers = min(h.Config.BillingEntitlementWorkers, 32)
	}
	for _, retry := range []bool{false, true} {
		go func() {
			for ctx.Err() == nil {
				count, err := h.usageEntitlementBatch(ctx, retry, workers/2)
				if err != nil {
					log.Warn().Err(err).Msg("usage entitlement scheduler failed")
				}
				wait := time.Second
				if count == 0 {
					wait = 5 * time.Second
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}()
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			sample, cancel := context.WithTimeout(ctx, 3*time.Second)
			started := time.Now()
			var late int64
			var age float64
			err := h.Pool.QueryRow(sample, `SELECT (SELECT count(*) FROM (SELECT 1 FROM billing_entitlement_work WHERE next_check_at<clock_timestamp()-interval '1 minute' ORDER BY next_check_at LIMIT 1000) q),COALESCE((SELECT greatest(0,extract(epoch FROM clock_timestamp()-next_check_at))::double precision FROM billing_entitlement_work ORDER BY next_check_at LIMIT 1),0)`).Scan(&late, &age)
			currentBillingRecorder().RecordBillingWork(ctx, "usage_entitlement_backlog", err != nil, time.Since(started), 0)
			if err == nil {
				currentBillingRecorder().RecordBillingBacklog(ctx, "entitlement_due", late, age)
			}
			cancel()
		}
	}()
}
func (h *Handlers) usageEntitlementBatch(ctx context.Context, retry bool, limit int) (int, error) {
	claim, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	token := uuid.New()
	rows, err := h.Pool.Query(claim, `WITH due AS (SELECT contract_id FROM billing_entitlement_work WHERE next_check_at<=clock_timestamp() AND (failures>0)=$2 AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY next_check_at,contract_id FOR UPDATE SKIP LOCKED LIMIT $3)
 UPDATE billing_entitlement_work w SET lease_token=$1,lease_until=clock_timestamp()+interval '1 minute',next_check_at=clock_timestamp()+interval '1 minute' FROM due WHERE w.contract_id=due.contract_id RETURNING w.contract_id`, token, retry, limit)
	if err != nil {
		return 0, err
	}
	var jobs []entitlementJob
	for rows.Next() {
		j := entitlementJob{Token: token}
		if err = rows.Scan(&j.Contract); err != nil {
			rows.Close()
			return 0, err
		}
		jobs = append(jobs, j)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			work, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			_ = h.processEntitlementJob(work, j)
		}()
	}
	wg.Wait()
	return len(jobs), nil
}
func (h *Handlers) processEntitlementJob(ctx context.Context, j entitlementJob) error {
	started := time.Now()
	next, err := h.reconcileUsageEntitlement(ctx, j.Contract)
	progress := errors.Is(err, errCreditInventoryPending)
	currentBillingRecorder().RecordBillingWork(ctx, "usage_entitlement", err != nil && !progress, time.Since(started), 1)
	ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	var message *string
	if err != nil {
		v := err.Error()
		message = &v
		next = time.Now().Add(10 * time.Second)
		if errors.Is(err, errCreditInventoryPending) {
			next = time.Now().Add(time.Second)
			message = nil
		}
	}
	var alert bool
	finish := h.Pool.QueryRow(ack, `WITH previous AS MATERIALIZED (SELECT contract_id AS old_contract_id,alerted_at AS old_alerted_at FROM billing_entitlement_work WHERE contract_id=$1 AND lease_token=$2 FOR UPDATE), finished AS (UPDATE billing_entitlement_work SET lease_token=NULL,lease_until=NULL,next_check_at=CASE WHEN $4::text IS NULL THEN $3 ELSE greatest($3,clock_timestamp()+make_interval(secs=>least(300,10*power(2,least(failures,5)))::double precision)) END,
 failures=CASE WHEN $4::text IS NULL THEN 0 ELSE least(failures+1,10000) END,
 problem_since=CASE WHEN $4::text IS NULL THEN NULL ELSE COALESCE(problem_since,clock_timestamp()) END,
 last_error=$4,
 alerted_at=CASE WHEN (($4::text IS NOT NULL AND COALESCE(problem_since,clock_timestamp())<clock_timestamp()-interval '5 minutes') OR EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.contract_id=$1 AND e.state<>'issued' AND (e.state='uncertain' OR NOT (EXISTS(SELECT 1 FROM billing_yc_operation o WHERE o.contract_id=e.contract_id AND o.revoked_at IS NOT NULL) OR EXISTS(SELECT 1 FROM billing_sponsored_operation o WHERE o.contract_id=e.contract_id AND o.revoked_at IS NOT NULL))) AND (e.first_attempt_at<clock_timestamp()-interval '5 minutes' OR e.period_end<clock_timestamp()+interval '15 minutes'))) AND (alerted_at IS NULL OR alerted_at<clock_timestamp()-interval '1 hour') THEN clock_timestamp() ELSE alerted_at END
 FROM previous WHERE contract_id=previous.old_contract_id AND lease_token=$2 RETURNING alerted_at) SELECT finished.alerted_at IS DISTINCT FROM previous.old_alerted_at FROM finished CROSS JOIN previous`, j.Contract, j.Token, next, message).Scan(&alert)
	if alert {
		_, incidentErr := h.Pool.Exec(ack, `INSERT INTO billing_entitlement_withheld(contract_id,period_start,period_end,evidence,platform_failure_at)
 SELECT c.id,p.period_start,p.period_end,'{}'::jsonb,clock_timestamp() FROM billing_commercial_contract c CROSS JOIN LATERAL billing_contract_entitlement(c,clock_timestamp()) p WHERE c.id=$1
 ON CONFLICT(contract_id,period_start) DO UPDATE SET platform_failure_at=COALESCE(billing_entitlement_withheld.platform_failure_at,EXCLUDED.platform_failure_at)`, j.Contract)
		if incidentErr != nil {
			return incidentErr
		}
		log.Error().Str("contract_id", j.Contract.String()).Err(err).Msg("usage entitlement requires operator recovery; inspect pending grants before collecting invoices")
	}
	if finish != nil {
		log.Error().Err(finish).Str("contract_id", j.Contract.String()).Msg("entitlement result could not be saved")
		return finish
	}
	if progress {
		return nil
	}
	return err
}

func (h *Handlers) reconcileUsageEntitlement(ctx context.Context, id uuid.UUID) (time.Time, error) {
	next := time.Now().Add(20 * time.Second)
	var team uuid.UUID
	if err := h.Pool.QueryRow(ctx, `SELECT team_id FROM billing_commercial_contract WHERE id=$1`, id).Scan(&team); err != nil {
		return next, err
	}
	c, err := h.DB.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: team, ContractID: id})
	if err != nil {
		return next, err
	}
	// Recover a possible success before deciding whether a new period is eligible.
	var unresolved uuid.UUID
	err = h.Pool.QueryRow(ctx, `SELECT id FROM billing_usage_entitlement WHERE contract_id=$1 AND state<>'issued' ORDER BY period_start LIMIT 1`, id).Scan(&unresolved)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return next, err
	}
	client := h.Stripe.(*stripeHTTPClient)
	if unresolved != uuid.Nil {
		e, eerr := h.DB.GetUsageEntitlement(ctx, db.GetUsageEntitlementParams{TeamID: team, EntitlementID: unresolved})
		if eerr != nil {
			return next, eerr
		}
		if e.State == "uncertain" {
			recoveryErr := h.discoverUsageEntitlement(ctx, c, e, client)
			if recoveryErr == nil {
				return next, nil
			}
			if !errors.Is(recoveryErr, errEntitlementNotFound) {
				return next, recoveryErr
			}
			if !e.PeriodEnd.After(time.Now()) || time.Since(e.FirstAttemptAt.Time) >= 23*time.Hour || c.Status != "active" {
				return next, errors.New("unknown grant outcome exceeded safe replay window; operator recovery required")
			}
		}
		if c.OfferKey == "yc_2026" {
			operation, e := h.ycOperation(ctx, team)
			if e != nil {
				return next, e
			}
			if e = h.syncYCRevocation(ctx, &operation); e != nil {
				return next, e
			}
		}
		if c.ChargeKind == "sponsored_entitlement" {
			var revoked bool
			if err = h.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM billing_sponsored_operation WHERE contract_id=$1`, c.ID).Scan(&revoked); err != nil {
				return next, err
			}
			if revoked {
				if e.State == "uncertain" {
					return next, h.finishSponsoredAttempt(ctx, c, e, client)
				}
				return time.Now().Add(time.Hour), nil
			}
		}
		if e.State == "pending" && c.OfferKey == "yc_2026" {
			var revoked bool
			if err = h.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM billing_yc_operation WHERE contract_id=$1`, c.ID).Scan(&revoked); err != nil {
				return next, err
			}
			if revoked {
				return time.Now().Add(time.Hour), nil
			}
		}
		if !e.PeriodEnd.After(time.Now()) {
			return next, errors.New("eligible entitlement expired before issuance; manual remediation required before invoice collection")
		}
	}
	if h.Config == nil || !h.Config.BillingUsageEntitlementsEnabled {
		return time.Now().Add(time.Minute), nil
	}
	if c.Status != "active" || (c.EndsAt.Valid && !c.EndsAt.Time.After(time.Now())) {
		return time.Now().Add(24 * time.Hour), nil
	}
	if c.ChargeKind == "sponsored_entitlement" {
		var revoked bool
		if err = h.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM billing_sponsored_operation WHERE contract_id=$1`, c.ID).Scan(&revoked); err != nil {
			return next, err
		}
		if revoked {
			return time.Now().Add(time.Hour), nil
		}
	}
	start, end, ok := billing.AnniversaryPeriod(c.EntitlementAnchor, time.Now())
	if !ok {
		return next, errors.New("commercial anniversary unavailable")
	}
	e, err := h.DB.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: team, Kind: c.EntitlementKind})
	if err == nil && e.State == "issued" {
		return end.Add(time.Second), nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return next, err
	}
	if c.OfferKey == "yc_2026" {
		operation, e := h.ycOperation(ctx, team)
		if e != nil {
			return next, e
		}
		if e = h.syncYCRevocation(ctx, &operation); e != nil {
			return next, e
		}
	}
	if c.OfferKey == "yc_2026" {
		var allowed bool
		if err = h.Pool.QueryRow(ctx, `SELECT billing_yc_covered(c,$2,$3,true) FROM billing_commercial_contract c WHERE id=$1`, id, start, end).Scan(&allowed); err != nil {
			return next, err
		}
		if !allowed {
			return next, nil
		}
	}
	// Reuse the verified payment path; an invoice event alone cannot establish coverage.
	var paid bool
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_contract_payment p WHERE contract_id=$1 AND service_period_start<=$2 AND service_period_end>=$3 AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=p.invoice_id AND v.review_required))`, id, start, end).Scan(&paid); err != nil {
		return next, err
	}
	if !paid && c.OfferKey != "yc_2026" && c.ChargeKind != "sponsored_entitlement" {
		if _, err = h.reconcileProCheckout(ctx, team, false); err != nil {
			return next, err
		}
	}
	token := uuid.New()
	if _, err = h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: c.CustomerID, Token: token}); err != nil {
		return next, err
	}
	defer func() {
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: c.CustomerID, Token: token})
	}()
	c, err = h.DB.GetCommercialContract(ctx, db.GetCommercialContractParams{TeamID: team, ContractID: id})
	if err != nil {
		return next, err
	}
	debt, err := client.entitlementDebt(ctx, c.CustomerID)
	if err != nil {
		return next, err
	}
	if debt != "" {
		evidence, _ := json.Marshal(map[string]string{"unpaid_invoice": debt})
		_, err = h.Pool.Exec(ctx, `INSERT INTO billing_entitlement_withheld(contract_id,period_start,period_end,evidence) VALUES($1,$2,$3,$4) ON CONFLICT(contract_id,period_start) DO UPDATE SET observed_at=clock_timestamp(),evidence=EXCLUDED.evidence`, id, start, end, evidence)
		if err == nil {
			_, err = h.Pool.Exec(ctx, `INSERT INTO billing_entitlement_debt(contract_id,period_start,invoice_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, id, start, debt)
		}
		return next, err
	}
	// A prior debt observation cannot excuse a later platform failure after settlement.
	if _, err = h.Pool.Exec(ctx, `UPDATE billing_entitlement_withheld SET evidence='{}'::jsonb WHERE contract_id=$1 AND period_start=$2`, id, start); err != nil {
		return next, err
	}
	if err = h.entitlementClosingInvoice(ctx, c, start, client); err != nil {
		return next, err
	}
	a, enrolled, err := h.invoiceAccount(ctx, team)
	if err != nil {
		return next, err
	}
	if !enrolled {
		return next, errors.New("entitlement requires held invoice reconciliation enrollment")
	}
	if a, err = client.ensureInvoiceSubscription(ctx, a, false, false); err != nil {
		return next, err
	}
	states, err := h.billingSubscriptionResourceStates(ctx, team, c.SubscriptionID, true)
	if err != nil {
		return next, err
	}
	var terms []StripeCheckoutResourceTerms
	var prices []map[string]string
	for _, s := range states {
		if s.PurchasedTerms == nil {
			return next, errors.New("entitlement resource evidence missing")
		}
		terms = append(terms, *s.PurchasedTerms)
		prices = append(prices, map[string]string{"id": s.StripePriceID})
	}
	sub, err := client.invoiceSubscription(ctx, c.SubscriptionID)
	if err != nil {
		return next, err
	}
	sub, err = a.Base.stripSubscription(sub)
	if err != nil {
		return next, err
	}
	if err = validateFrozenProResources(sub, terms, a.Price); err != nil {
		return next, err
	}
	prices = append(prices, map[string]string{"id": a.Price})
	sort.Slice(prices, func(i, j int) bool { return prices[i]["id"] < prices[j]["id"] })
	storage, err := h.billingStorageBillingEnabledForWindow(ctx, team, end)
	if err != nil {
		return next, err
	}
	if err = validateEntitlementResourceTerms(terms, a.Price, a.Event, a.Meter, storage); err != nil {
		return next, err
	}
	p := billing.ExportPeriod{TeamID: team, Start: start, End: end}
	if _, err = h.DB.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{TeamID: team, PeriodStart: start, PeriodEnd: end, Status: "open"}); err != nil {
		return next, err
	}
	mapped, err := h.ensureInvoiceCalendar(ctx, p, a, client)
	if err != nil {
		return next, err
	}
	if time.Now().Unix() <= mapped.Start.Unix() {
		return mapped.Start.Add(2 * time.Second), nil
	}
	if c.OfferKey != "yc_2026" && c.ChargeKind != "sponsored_entitlement" {
		// Refresh the exact covering receipt through the existing payment verifier.
		var paymentInvoice string
		if err = h.Pool.QueryRow(ctx, `SELECT invoice_id FROM billing_contract_payment WHERE contract_id=$1 AND service_period_start<=$2 AND service_period_end>=$3 ORDER BY service_period_start DESC,invoice_id LIMIT 1`, id, start, end).Scan(&paymentInvoice); err != nil {
			return next, err
		}
		payment, verified, verifyErr := client.verifyProInvoice(ctx, paymentInvoice, proOffer{Key: c.OfferKey, Price: c.BasePriceID, Amount: c.ChargeAmountCents, Months: c.ChargeIntervalMonths}, c.CustomerID, c.SubscriptionID)
		if observeErr := h.observeProPaymentReview(ctx, team, paymentInvoice, payment, verifyErr); observeErr != nil {
			return next, observeErr
		}
		if verifyErr != nil {
			return next, verifyErr
		}
		if !verified || payment.Start > start.Unix() || payment.End < end.Unix() {
			return next, errors.New("current base coverage could not be freshly verified")
		}
	}
	// Observe at the end of validation, immediately before durable authorization.
	debt, err = client.entitlementDebt(ctx, c.CustomerID)
	if err != nil {
		return next, err
	}
	if debt != "" {
		return next, nil
	}
	var observed time.Time
	if err = h.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed); err != nil {
		return next, err
	}
	evidence, _ := json.Marshal(map[string]any{"gate": "finalized_invoice_gate_v1", "period_start": start, "period_end": end, "closing_invoice_verified": true})
	c, err = h.DB.ObserveCommercialCollection(ctx, db.ObserveCommercialCollectionParams{TeamID: team, ContractID: id, ExpectedRevision: c.Revision, HasOverdueBalance: new(bool), CheckedAt: pgtype.Timestamptz{Time: observed, Valid: true}, ValidUntil: pgtype.Timestamptz{Time: observed.Add(30 * time.Second), Valid: true}, Evidence: evidence})
	if err != nil {
		return next, fmt.Errorf("observe entitlement collection: %w", err)
	}
	if c.OfferKey == "yc_2026" {
		operation, e := h.ycOperation(ctx, team)
		if e != nil {
			return next, e
		}
		authority, e := h.lockYCAuthority(ctx, operation)
		if e != nil {
			return next, e
		}
		defer authority()
	}

	if e.ID == uuid.Nil {
		e, err = h.DB.ClaimCurrentUsageEntitlement(ctx, db.ClaimCurrentUsageEntitlementParams{TeamID: team, ContractID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			e, err = h.DB.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: team, Kind: c.EntitlementKind})
		}
		if err != nil {
			return next, err
		}
	}
	if e.State == "pending" {
		raw, _ := json.Marshal(prices)
		e, err = h.beginValidatedUsageEntitlementIssuance(ctx, db.BeginImmediateUsageEntitlementIssuanceParams{TeamID: team, ContractID: id, EntitlementID: e.ID, InvoiceStart: pgtype.Timestamptz{Time: mapped.Start, Valid: true}, InvoiceEnd: pgtype.Timestamptz{Time: mapped.End, Valid: true}, Prices: raw}, prices)
		if err != nil {
			return next, err
		}
	}
	if e.State == "issued" {
		return end.Add(time.Second), nil
	}
	e, err = h.DB.GetReplayableUsageEntitlement(ctx, db.GetReplayableUsageEntitlementParams{TeamID: team, EntitlementID: e.ID})
	if err != nil {
		return next, err
	}

	// Recheck the shared lease after provider reads; no network I/O occurs in this transaction.
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return next, err
	}
	defer tx.Rollback(ctx)
	if _, err = h.DB.WithTx(tx).LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: c.CustomerID, Token: token}); err != nil {
		return next, err
	}
	if err = tx.Commit(ctx); err != nil {
		return next, err
	}
	return end.Add(time.Second), h.dispatchUsageEntitlement(ctx, c, e, client, prices)
}

func (h *Handlers) dispatchUsageEntitlement(ctx context.Context, c db.BillingCommercialContract, e db.BillingUsageEntitlement, client *stripeHTTPClient, prices []map[string]string) error {
	if err := client.rejectCompetingCreditInvoice(ctx, c.CustomerID, "", e.ProviderInvoiceEnd.Time.Unix()); err != nil {
		return err
	}
	form, err := entitlementGrantForm(e.RequestPayload, prices)
	if err != nil {
		return err
	}
	var grant entitlementGrant
	if err = client.doForm(ctx, http.MethodPost, "/v1/billing/credit_grants", form, &grant, e.IdempotencyKey); err != nil {
		return err
	}
	if grant.VoidedAt != 0 {
		return errors.New("created grant was voided; operator recovery required")
	}
	raw, _ := json.Marshal(grant)
	_, err = h.DB.ConfirmUsageEntitlementIssued(ctx, db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant.ID, Evidence: raw})
	return err
}

func (h *Handlers) entitlementClosingInvoice(ctx context.Context, c db.BillingCommercialContract, start time.Time, client *stripeHTTPClient) error {
	if start.Equal(c.EntitlementAnchor) {
		return nil
	}
	var initialRecovery bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_invoice_account a WHERE a.team_id=$1 AND a.customer_id=$2 AND a.subscription_id=$3 AND a.enrolled_at>=$4) AND NOT EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.contract_id=$5 AND e.period_start<$4)`, c.TeamID, c.CustomerID, c.SubscriptionID, start, c.ID).Scan(&initialRecovery); err != nil {
		return err
	}
	if initialRecovery {
		return nil
	}
	var invoice string
	err := h.Pool.QueryRow(ctx, `SELECT j.invoice_id FROM billing_invoice_close j JOIN team_billing_period p USING(team_id,period_start,period_end) WHERE j.team_id=$1 AND j.period_end=$2 AND j.state='released' AND p.finalized_at IS NOT NULL AND billing_invoice_close_matches(j.team_id,j.period_start,j.period_end)`, c.TeamID, start).Scan(&invoice)
	if err != nil {
		return fmt.Errorf("prior closing invoice is not reconciled and released: %w", err)
	}
	inv, err := client.RetrieveBillingInvoice(ctx, invoice)
	if err != nil {
		return err
	}
	if inv.ID != invoice || inv.Customer != c.CustomerID || inv.Status != "paid" || inv.AmountRemaining == nil || *inv.AmountRemaining != 0 || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != c.SubscriptionID {
		return errors.New("prior closing invoice is not settled")
	}
	return nil
}

func (h *Handlers) discoverUsageEntitlement(ctx context.Context, c db.BillingCommercialContract, e db.BillingUsageEntitlement, client *stripeHTTPClient) error {
	if err := h.syncCreditInventory(ctx, c.ID, c.CustomerID, client); err != nil {
		return err
	}
	rows, err := h.Pool.Query(ctx, `SELECT grant_id FROM billing_provider_credit WHERE customer_id=$1 AND entitlement_id=$2 LIMIT 2`, c.CustomerID, e.ID.String())
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
	if len(ids) == 0 {
		return errEntitlementNotFound
	}
	if len(ids) != 1 {
		return errors.New("multiple grants match saved entitlement; operator recovery required")
	}
	grant, err := client.retrieveEntitlementGrant(ctx, ids[0])
	if err != nil {
		return err
	}
	if grant.VoidedAt != 0 {
		return errors.New("recovered grant was voided; operator recovery required")
	}
	raw, _ := json.Marshal(grant)
	_, err = h.DB.ConfirmUsageEntitlementIssued(ctx, db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant.ID, Evidence: raw})
	return err
}

// Commit issuance intent only after the exact database-generated request is valid.
func (h *Handlers) beginValidatedUsageEntitlementIssuance(ctx context.Context, params db.BeginImmediateUsageEntitlementIssuanceParams, prices []map[string]string) (db.BillingUsageEntitlement, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return db.BillingUsageEntitlement{}, err
	}
	defer tx.Rollback(ctx)
	e, err := h.DB.WithTx(tx).BeginImmediateUsageEntitlementIssuance(ctx, params)
	if err != nil {
		return e, err
	}
	if _, err = entitlementGrantForm(e.RequestPayload, prices); err != nil {
		return e, err
	}
	return e, tx.Commit(ctx)
}
