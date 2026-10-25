package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
)

const fundingSweepName = "billing-funding-observation"

type fundingJob struct{ Team, Token uuid.UUID }

type fundingSnapshot struct {
	Generation         int64
	ObservedGeneration *int64
	Customer           *string
	Subscription       *string
	CreditChecked      pgtype.Timestamptz
	CreditValid        pgtype.Timestamptz
	CreditPositive     bool
	ProviderChecked    pgtype.Timestamptz
	ProviderValid      pgtype.Timestamptz
	Charge             *string
	Cursor             *string
	Account            db.TeamBillingAccount
	At                 time.Time
}

func (s fundingSnapshot) sameAuthority() bool {
	return s.ObservedGeneration != nil && *s.ObservedGeneration == s.Generation && derefString(s.Customer) == derefString(s.Account.StripeCustomerID) && derefString(s.Subscription) == derefString(s.Account.StripeSubscriptionID)
}

func fundingObservationDue(checked, valid pgtype.Timestamptz, at time.Time, refresh time.Duration) bool {
	return !checked.Valid || !valid.Valid || !valid.Time.After(at.Add(10*time.Second)) || !checked.Time.Add(refresh).After(at)
}

// A database-wide scheduler lease bounds provider concurrency across replicas.
// Team leases and generation/mapping checks fence every result independently.
func (h *Handlers) StartFundingObservationService(ctx context.Context) {
	if h.Pool == nil || h.DB == nil {
		return
	}
	go func() {
		for ctx.Err() == nil {
			count, err := h.fundingObservationBatch(ctx)
			if err != nil && ctx.Err() == nil {
				log.Warn().Err(err).Msg("funding observation scheduler failed")
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

func (h *Handlers) fundingObservationBatch(ctx context.Context) (int, error) {
	claim, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	holder := uuid.New().String()
	_, err := h.DB.ClaimSweepLease(claim, db.ClaimSweepLeaseParams{Name: fundingSweepName, LockedBy: holder, LeaseSeconds: 60})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer func() {
		ack, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		_, _ = h.Pool.Exec(ack, `UPDATE sweep_lease SET locked_until=clock_timestamp() WHERE name=$1 AND locked_by=$2`, fundingSweepName, holder)
	}()
	token := uuid.New()
	rows, err := h.Pool.Query(claim, `WITH due AS (
 SELECT team_id FROM billing_funding_account WHERE observe AND next_check_at<=clock_timestamp()
 AND (lease_until IS NULL OR lease_until<clock_timestamp())
 ORDER BY next_check_at,team_id FOR UPDATE SKIP LOCKED LIMIT (SELECT batch_size FROM billing_funding_policy WHERE singleton))
 UPDATE billing_funding_account w SET lease_token=$1,lease_until=clock_timestamp()+interval '1 minute',next_check_at=clock_timestamp()+interval '1 minute'
 FROM due WHERE w.team_id=due.team_id RETURNING w.team_id`, token)
	if err != nil {
		return 0, err
	}
	var jobs []fundingJob
	for rows.Next() {
		j := fundingJob{Token: token}
		if err = rows.Scan(&j.Team); err != nil {
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
	for _, job := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			work, done := context.WithTimeout(ctx, 45*time.Second)
			defer done()
			_ = h.processFundingJob(work, job)
		}()
	}
	wg.Wait()
	sample, done := context.WithTimeout(ctx, 3*time.Second)
	defer done()
	var late int64
	var age float64
	err = h.Pool.QueryRow(sample, `SELECT
 (SELECT count(*) FROM (SELECT 1 FROM billing_funding_account WHERE observe AND next_check_at<clock_timestamp()-interval '20 seconds' ORDER BY next_check_at LIMIT 1000) q),
 COALESCE((SELECT greatest(0,extract(epoch FROM clock_timestamp()-next_check_at))::double precision FROM billing_funding_account WHERE observe ORDER BY next_check_at LIMIT 1),0)`).Scan(&late, &age)
	if err == nil {
		currentBillingRecorder().RecordBillingBacklog(ctx, "funding_due", late, age)
		if age >= 20 {
			log.Warn().Int64("overdue_teams", late).Float64("oldest_due_seconds", age).Msg("funding observation capacity is behind its freshness budget")
		}
	}
	return len(jobs), err
}

func (h *Handlers) fundingSnapshot(ctx context.Context, j fundingJob) (fundingSnapshot, error) {
	var s fundingSnapshot
	s.Account.TeamID = j.Team
	err := h.Pool.QueryRow(ctx, `SELECT f.generation,f.observed_generation,f.customer_id,f.subscription_id,
 f.credit_checked_at,f.credit_valid_until,f.credit_usd>0,f.provider_checked_at,f.provider_valid_until,f.cash_charge_id,f.charge_cursor,
 a.stripe_customer_id,a.stripe_subscription_id,a.stripe_subscription_status,a.stripe_activation_credit_grant_id,a.stripe_activation_credit_granted_at,
 clock_timestamp() FROM billing_funding_account f LEFT JOIN team_billing_account a USING(team_id)
 WHERE f.team_id=$1 AND f.lease_token=$2 AND f.lease_until>clock_timestamp()`, j.Team, j.Token).Scan(
		&s.Generation, &s.ObservedGeneration, &s.Customer, &s.Subscription, &s.CreditChecked, &s.CreditValid, &s.CreditPositive, &s.ProviderChecked, &s.ProviderValid, &s.Charge, &s.Cursor,
		&s.Account.StripeCustomerID, &s.Account.StripeSubscriptionID, &s.Account.StripeSubscriptionStatus, &s.Account.StripeActivationCreditGrantID, &s.Account.StripeActivationCreditGrantedAt, &s.At)
	return s, err
}

func (h *Handlers) processFundingJob(ctx context.Context, j fundingJob) error {
	started := time.Now()
	s, err := h.fundingSnapshot(ctx, j)
	if err != nil {
		return err
	}
	same := s.sameAuthority()
	var credit *fundingCreditObservation
	var provider *fundingProviderObservation
	var creditErr, providerErr error
	var observations sync.WaitGroup
	if !same || fundingObservationDue(s.CreditChecked, s.CreditValid, s.At, 30*time.Second) {
		observations.Add(1)
		go func() {
			defer observations.Done()
			work, done := context.WithTimeout(ctx, 20*time.Second)
			defer done()
			observed, e := h.observeFundingCredit(work, j.Team, s.Account, s.At)
			creditErr = e
			if e == nil {
				credit = &observed
			}
		}()
	}
	if !same || fundingObservationDue(s.ProviderChecked, s.ProviderValid, s.At, 2*time.Minute) {
		observations.Add(1)
		go func() {
			defer observations.Done()
			work, done := context.WithTimeout(ctx, 20*time.Second)
			defer done()
			previous, cursor := "", ""
			if same {
				previous, cursor = derefString(s.Charge), derefString(s.Cursor)
			}
			observed, e := h.observeFundingProvider(work, j.Team, s.Account, previous, cursor)
			providerErr = e
			if e == nil {
				provider = &observed
			}
		}()
	}
	observations.Wait()
	workErr := errors.Join(creditErr, providerErr)
	ack, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer done()
	err = h.publishFundingObservation(ack, j, s, credit, provider, workErr)
	currentBillingRecorder().RecordBillingWork(ack, "funding_observation", workErr != nil || err != nil, time.Since(started), 1)
	return errors.Join(workErr, err)
}

func (h *Handlers) observeFundingProvider(ctx context.Context, team uuid.UUID, account db.TeamBillingAccount, previous, cursor string) (fundingProviderObservation, error) {
	if derefString(account.StripeCustomerID) == "" {
		return fundingProviderObservation{ValidUntil: time.Now().Add(5 * time.Minute), Evidence: []byte(`{"customer":"absent"}`)}, nil
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return fundingProviderObservation{}, errors.New("funding provider unavailable")
	}
	live, err := fundingStripeMode(client.secretKey)
	if err != nil {
		return fundingProviderObservation{}, err
	}
	out, err := client.observeFundingPage(ctx, *account.StripeCustomerID, derefString(account.StripeSubscriptionID), live, previous, cursor)
	if err != nil || !out.CollectionReady {
		return out, err
	}
	// The current export scheduler enrolls new usage only for active mappings.
	// Credit access remains independent of this payment-only prerequisite.
	if derefString(account.StripeSubscriptionStatus) != "active" || out.Subscription.Status != "active" {
		out.CollectionReady = false
	} else {
		out.CollectionReady, err = h.fundingCollectionEnrolled(ctx, team, account, out.Subscription, client)
	}
	if err == nil {
		out.Evidence, err = json.Marshal(out)
	}
	return out, err
}

func fundingStripeMode(key string) (bool, error) {
	if strings.HasPrefix(key, "sk_live_") || strings.HasPrefix(key, "rk_live_") {
		return true, nil
	}
	if strings.HasPrefix(key, "sk_test_") || strings.HasPrefix(key, "rk_test_") {
		return false, nil
	}
	return false, errors.New("funding provider mode is not configured")
}

func (h *Handlers) fundingCollectionEnrolled(ctx context.Context, team uuid.UUID, account db.TeamBillingAccount, sub invoiceSubscription, client *stripeHTTPClient) (bool, error) {
	if os.Getenv("BILLING_AUTOMATIC_CLOSE_DISABLED") == "true" {
		return false, nil
	}
	a, enrolled, err := h.invoiceAccount(ctx, team)
	if err != nil || !enrolled {
		return false, err
	}
	if a.Customer != derefString(account.StripeCustomerID) || a.Subscription != derefString(account.StripeSubscriptionID) || a.Customer != sub.Customer || a.Subscription != sub.ID {
		return false, errors.New("funding collection association changed")
	}
	var export bool
	if err = h.Pool.QueryRow(ctx, `SELECT feature_enabled('billing_export_enabled',$1)`, team).Scan(&export); err != nil || !export {
		return false, err
	}
	if sub.PauseCollection == nil || sub.PauseCollection.Behavior != "keep_as_draft" || sub.PauseCollection.ResumesAt != 0 || a.Price == "" || a.Meter == "" || a.Event != invoiceRoundingEvent {
		return false, nil
	}
	found := false
	for _, item := range sub.Items.Data {
		if item.Price.ID != a.Price {
			continue
		}
		amount, e := meterDecimal(item.Price.UnitAmountDecimal)
		if found || e != nil || amount.Cmp(big.NewRat(1, 1)) != 0 || item.Price.Recurring.Meter != a.Meter || !proResourceShape(item.Price) {
			return false, errors.New("funding adjustment meter differs from enrollment")
		}
		found = true
	}
	if !found {
		return false, nil
	}
	if err = h.validateInvoiceEnrollmentSubscription(ctx, team, a, client, sub, h.Pool); err != nil {
		return false, err
	}
	return true, nil
}

func (h *Handlers) publishFundingObservation(ctx context.Context, j fundingJob, s fundingSnapshot, credit *fundingCreditObservation, provider *fundingProviderObservation, workErr error) error {
	var c fundingCreditObservation
	var p fundingProviderObservation
	if credit != nil {
		c = *credit
	}
	if provider != nil {
		p = *provider
	}
	if c.SpendableUSD == "" {
		c.SpendableUSD = "0"
	}
	if len(c.Evidence) == 0 {
		c.Evidence = []byte(`{}`)
	}
	if len(p.Evidence) == 0 {
		p.Evidence = []byte(`{}`)
	}
	var message *string
	if workErr != nil {
		v := workErr.Error()
		if len(v) > 1000 {
			v = v[:1000]
		}
		message = &v
	}
	delay := fundingNextObservation(s, credit, workErr)
	result, err := h.Pool.Exec(ctx, `UPDATE billing_funding_account f SET
 customer_id=$4,subscription_id=$5,observed_generation=$3,
 credit_usd=CASE WHEN $6 THEN $7::numeric WHEN $8 THEN credit_usd ELSE 0 END,
 credit_valid_until=CASE WHEN $6 THEN $9::timestamptz WHEN $8 THEN credit_valid_until ELSE NULL END,
 credit_checked_at=CASE WHEN $6 THEN $10::timestamptz WHEN $8 THEN credit_checked_at ELSE NULL END,
 credit_evidence=CASE WHEN $6 THEN $11::jsonb WHEN $8 THEN credit_evidence ELSE '{}'::jsonb END,
 payment_method_id=CASE WHEN $12 THEN NULLIF($13,'') WHEN $8 THEN payment_method_id ELSE NULL END,
 payment_method_ready=CASE WHEN $12 THEN $14 WHEN $8 THEN payment_method_ready ELSE false END,
 collection_ready=CASE WHEN $12 THEN $15 WHEN $8 THEN collection_ready ELSE false END,
 cash_charge_id=CASE WHEN $12 THEN NULLIF($16,'') WHEN $8 THEN cash_charge_id ELSE NULL END,
 cash_collected=CASE WHEN $12 THEN $17 WHEN $8 THEN cash_collected ELSE false END,
 charge_cursor=CASE WHEN $12 THEN NULLIF($18,'') WHEN $8 THEN charge_cursor ELSE NULL END,
 provider_valid_until=CASE WHEN $12 THEN $19::timestamptz WHEN $8 THEN provider_valid_until ELSE NULL END,
 provider_checked_at=CASE WHEN $12 THEN $10::timestamptz WHEN $8 THEN provider_checked_at ELSE NULL END,
 provider_evidence=CASE WHEN $12 THEN $20::jsonb WHEN $8 THEN provider_evidence ELSE '{}'::jsonb END,
 checked_at=clock_timestamp(),last_error=$21,failures=CASE WHEN $21::text IS NULL THEN 0 ELSE LEAST(failures+1,10000) END,
 next_check_at=$10::timestamptz+make_interval(secs=>$22::double precision),lease_token=NULL,lease_until=NULL
 WHERE team_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp() AND generation=$3
 AND (SELECT (a.stripe_customer_id,a.stripe_subscription_id) IS NOT DISTINCT FROM ($4::text,$5::text)
 FROM (SELECT $1::uuid team_id) t LEFT JOIN team_billing_account a USING(team_id))`,
		j.Team, j.Token, s.Generation, s.Account.StripeCustomerID, s.Account.StripeSubscriptionID,
		credit != nil, c.SpendableUSD, s.sameAuthority(), nullableFundingTime(c.ValidUntil), s.At, c.Evidence,
		provider != nil, p.PaymentMethodID, p.PaymentMethodReusable, p.CollectionReady, p.CashChargeID, p.CashCollected, p.NextChargeCursor,
		nullableFundingTime(p.ValidUntil), p.Evidence, message, delay.Seconds())
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		_, _ = h.Pool.Exec(ctx, `UPDATE billing_funding_account SET lease_token=NULL,lease_until=NULL,next_check_at=LEAST(next_check_at,clock_timestamp()) WHERE team_id=$1 AND lease_token=$2`, j.Team, j.Token)
		return fmt.Errorf("funding observation authority changed before publication")
	}
	return nil
}

func fundingNextObservation(s fundingSnapshot, credit *fundingCreditObservation, workErr error) time.Duration {
	positive := s.sameAuthority() && s.CreditPositive
	if credit != nil {
		amount, err := meterDecimal(credit.SpendableUSD)
		positive = err == nil && amount.Sign() > 0
	}
	if positive || workErr != nil {
		return 30 * time.Second
	}
	if derefString(s.Account.StripeCustomerID) != "" {
		return 2 * time.Minute
	}
	// Empty accounts cannot consume anything; grants and mapping changes wake
	// them through the generation trigger rather than fleet-wide busy polling.
	return 5 * time.Minute
}

func nullableFundingTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
