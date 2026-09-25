// Command billing-recovery audits incomplete Stripe activation state and, only
// with an explicit target and -apply, reconciles one currently eligible team.
// The default is read-only so a fleet audit cannot accidentally change billing.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type billingAccount struct {
	TeamID            uuid.UUID
	CustomerID        *string
	SubscriptionID    *string
	Status            *string
	EventAt           *time.Time
	GrantID           *string
	TrialEndedAt      *time.Time
	CheckoutAt        *time.Time
	CheckoutSessionID *string
	UserPromotion     bool
}

type stripeSubscription struct {
	ID                 string                  `json:"id"`
	Customer           string                  `json:"customer"`
	Status             string                  `json:"status"`
	CurrentPeriodStart int64                   `json:"current_period_start"`
	CurrentPeriodEnd   int64                   `json:"current_period_end"`
	CancelAtPeriodEnd  bool                    `json:"cancel_at_period_end"`
	Items              stripeSubscriptionItems `json:"items"`
}

type stripeSubscriptionItems struct {
	Data []stripeSubscriptionItem `json:"data"`
}

type stripeSubscriptionItem struct {
	CurrentPeriodStart int64 `json:"current_period_start"`
	CurrentPeriodEnd   int64 `json:"current_period_end"`
}

func (s stripeSubscription) periodBounds() (int64, int64, bool) {
	for _, item := range s.Items.Data {
		if item.CurrentPeriodStart > 0 && item.CurrentPeriodEnd > 0 {
			return item.CurrentPeriodStart, item.CurrentPeriodEnd, true
		}
	}
	if s.CurrentPeriodStart > 0 && s.CurrentPeriodEnd > 0 {
		return s.CurrentPeriodStart, s.CurrentPeriodEnd, true
	}
	return 0, 0, false
}

type stripeGrant struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Amount   struct {
		Monetary struct {
			Value    int64  `json:"value"`
			Currency string `json:"currency"`
		} `json:"monetary"`
	} `json:"amount"`
	ApplicabilityConfig struct {
		Scope struct {
			PriceType string `json:"price_type"`
		} `json:"scope"`
	} `json:"applicability_config"`
	ExpiresAt *int64            `json:"expires_at"`
	VoidedAt  *int64            `json:"voided_at"`
	Metadata  map[string]string `json:"metadata"`
}

type stripeGrantList struct {
	Data    []stripeGrant `json:"data"`
	HasMore bool          `json:"has_more"`
}

type stripeClient struct {
	baseURL          string
	secret           string
	version          string
	httpClient       *http.Client
	grantAmountCents int64
}

func (c stripeClient) activationCreditCents() int64 {
	if c.grantAmountCents == 0 {
		return 9500
	}
	return c.grantAmountCents
}

var errRecoveryCheckoutUnverified = errors.New("checkout not verified complete")

func (c stripeClient) verifyRecoveryCheckout(ctx context.Context, account billingAccount) error {
	if account.CheckoutAt == nil {
		return nil
	}
	if strings.TrimSpace(deref(account.CheckoutSessionID)) == "" {
		return fmt.Errorf("%w: pending checkout has no session identity", errRecoveryCheckoutUnverified)
	}
	var session struct {
		ID                string `json:"id"`
		Status            string `json:"status"`
		Customer          string `json:"customer"`
		Subscription      string `json:"subscription"`
		ClientReferenceID string `json:"client_reference_id"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/checkout/sessions/"+url.PathEscape(*account.CheckoutSessionID), nil, &session, ""); err != nil {
		return fmt.Errorf("verify checkout: %w", err)
	}
	if session.ID != *account.CheckoutSessionID || session.Status != "complete" || session.Customer == "" || session.Customer != deref(account.CustomerID) || session.Subscription == "" || session.Subscription != deref(account.SubscriptionID) || session.ClientReferenceID != account.TeamID.String() {
		return fmt.Errorf("%w: session does not match the current team/customer/subscription", errRecoveryCheckoutUnverified)
	}
	return nil
}

const billingRecoveryOperationTimeout = 2 * time.Minute

func (c stripeClient) request(ctx context.Context, method, path string, form url.Values, out any, idempotency string) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	requestCtx, cancel := context.WithTimeout(ctx, billingRecoveryOperationTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, strings.TrimRight(c.baseURL, "/")+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.secret, "")
	req.Header.Set("Stripe-Version", c.version)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	client := c.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("stripe %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c stripeClient) subscription(ctx context.Context, id string) (stripeSubscription, error) {
	var sub stripeSubscription
	err := c.request(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(id), nil, &sub, "")
	return sub, err
}

func (c stripeClient) grants(ctx context.Context, customer string) ([]stripeGrant, error) {
	var all []stripeGrant
	path := "/v1/billing/credit_grants?customer=" + url.QueryEscape(customer) + "&limit=100"
	previousCursor := ""
	for {
		var page stripeGrantList
		if err := c.request(ctx, http.MethodGet, path, nil, &page, ""); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		if !page.HasMore || len(page.Data) == 0 {
			return all, nil
		}
		lastID := page.Data[len(page.Data)-1].ID
		if strings.TrimSpace(lastID) == "" {
			return nil, errors.New("Stripe credit grant page has no cursor")
		}
		if lastID == previousCursor {
			return nil, errors.New("Stripe credit grant pagination cursor did not advance")
		}
		previousCursor = lastID
		path = "/v1/billing/credit_grants?customer=" + url.QueryEscape(customer) + "&limit=100&starting_after=" + url.QueryEscape(lastID)
	}
}

const activationGrantIdentityMetadataKey = "activation_identity"

func activationGrantIdentity(teamID uuid.UUID) string {
	return "stripe-activation-credit-" + teamID.String()
}

func (c stripeClient) isActivationGrantAmount(grant stripeGrant) bool {
	return grant.Category == "promotional" &&
		grant.Amount.Monetary.Currency == "usd" &&
		grant.Amount.Monetary.Value == c.activationCreditCents()
}

func isActivationGrantApplicable(grant stripeGrant) bool {
	return strings.EqualFold(strings.TrimSpace(grant.ApplicabilityConfig.Scope.PriceType), "metered")
}

func (c stripeClient) isActivationGrantUsable(grant stripeGrant, now time.Time) bool {
	if !c.isActivationGrantAmount(grant) || !isActivationGrantApplicable(grant) {
		return false
	}
	if grant.VoidedAt != nil {
		return false
	}
	return grant.ExpiresAt == nil || *grant.ExpiresAt > now.Unix()
}

func (c stripeClient) isVerifiedActivationGrant(grant stripeGrant, localGrantID, identity string) bool {
	if strings.TrimSpace(grant.ID) == "" || !c.isActivationGrantUsable(grant, time.Now().UTC()) {
		return false
	}
	// A persisted grant ID is an immutable local identity. When local state is
	// missing that identity, require the team-scoped marker written at creation;
	// amount and category alone cannot establish ownership of an old grant.
	if localGrantID != "" {
		return grant.ID == localGrantID
	}
	return strings.TrimSpace(grant.Metadata[activationGrantIdentityMetadataKey]) == identity
}

func (c stripeClient) createGrant(ctx context.Context, customer, key, identity string) (string, error) {
	form := url.Values{}
	form.Set("customer", customer)
	form.Set("category", "promotional")
	form.Set("amount[type]", "monetary")
	form.Set("amount[monetary][currency]", "usd")
	form.Set("amount[monetary][value]", strconv.FormatInt(c.activationCreditCents(), 10))
	form.Set("applicability_config[scope][price_type]", "metered")
	form.Set("metadata["+activationGrantIdentityMetadataKey+"]", identity)
	var grant stripeGrant
	if err := c.request(ctx, http.MethodPost, "/v1/billing/credit_grants", form, &grant, key); err != nil {
		return "", err
	}
	if strings.TrimSpace(grant.ID) == "" {
		return "", errors.New("Stripe credit grant response did not include an ID")
	}
	return grant.ID, nil
}

func main() {
	var target string
	var excluded string
	var apply bool
	var grantAmountCents int64
	var databaseURL string
	var stripeBaseURL string
	var stripeVersion string
	var batchSize int
	flag.StringVar(&target, "team", "", "team UUID to audit; required with -apply")
	flag.StringVar(&excluded, "exclude-team", "", "team UUID to report as excluded (repeat command for more exclusions)")
	flag.BoolVar(&apply, "apply", false, "apply one verified repair; default is dry-run")
	flag.StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"), "Postgres URL (default DATABASE_URL)")
	flag.StringVar(&stripeBaseURL, "stripe-api-base-url", envOr("STRIPE_API_BASE_URL", "https://api.stripe.com"), "Stripe API base URL")
	flag.StringVar(&stripeVersion, "stripe-api-version", os.Getenv("STRIPE_API_VERSION"), "Stripe API version")
	flag.IntVar(&batchSize, "batch-size", 100, "number of audit rows to fetch per page")
	flag.Int64Var(&grantAmountCents, "activation-credit-cents", 9500, "activation credit in USD cents; non-default requires -team")
	flag.Parse()
	if grantAmountCents <= 0 || (grantAmountCents != 9500 && target == "") {
		fatal("positive activation credit required; non-default amount requires -team")
	}
	if databaseURL == "" {
		fatal("database URL is required")
	}
	if apply && target == "" {
		fatal("-apply requires exactly one -team target")
	}
	if apply && excluded != "" && target == excluded {
		fatal("target is explicitly excluded")
	}
	if os.Getenv("STRIPE_SECRET_KEY") == "" {
		fatal("STRIPE_SECRET_KEY is required for the live evidence audit")
	}
	if batchSize <= 0 {
		fatal("-batch-size must be positive")
	}
	targetID, err := parseOptionalUUID(target)
	if err != nil {
		fatal(err.Error())
	}
	excludedID, err := parseOptionalUUID(excluded)
	if err != nil {
		fatal(err.Error())
	}
	// Keep fleet scans alive across pages; individual DB, Stripe, and account
	// operations are bounded below.
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		fatal(err.Error())
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		fatal(err.Error())
	}
	defer pool.Close()
	stripe := stripeClient{baseURL: stripeBaseURL, secret: os.Getenv("STRIPE_SECRET_KEY"), version: stripeVersion, grantAmountCents: grantAmountCents}
	var after *uuid.UUID
	for {
		loadCtx, cancelLoad := context.WithTimeout(ctx, billingRecoveryOperationTimeout)
		accounts, err := loadAccounts(loadCtx, pool, targetID, after, batchSize)
		cancelLoad()
		if err != nil {
			fatal(err.Error())
		}
		if apply && len(accounts) != 1 {
			fatal("-apply target did not resolve to one billing account")
		}
		for _, account := range accounts {
			accountCtx, cancelAccount := context.WithTimeout(ctx, billingRecoveryOperationTimeout)
			outcome := auditAccount(accountCtx, pool, stripe, account, excludedID, apply)
			cancelAccount()
			encoded, _ := json.Marshal(outcome)
			fmt.Println(string(encoded))
		}
		if targetID != nil || len(accounts) < batchSize {
			break
		}
		after = &accounts[len(accounts)-1].TeamID
	}
}

// User-scoped promotions must be reconciled by the webhook workflow, which
// owns their durable reservations and settles both user and team entitlements.
const recoveryUserPromotionSQL = `(stripe_activation_user_id IS NOT NULL
        OR stripe_activation_credit_reserved_at IS NOT NULL
        OR stripe_activation_credit_reservation_event_id IS NOT NULL
        OR stripe_checkout_actor_id IS NOT NULL
        OR stripe_checkout_actor_claimed_at IS NOT NULL
        OR EXISTS (
            SELECT 1 FROM user_promotion_entitlement u
            WHERE u.stripe_redemption_team_id = team_billing_account.team_id
               OR u.stripe_redemption_reserved_team_id = team_billing_account.team_id
        ))`

func loadAccounts(ctx context.Context, pool *pgxpool.Pool, target, after *uuid.UUID, batchSize int) ([]billingAccount, error) {
	query := `SELECT team_id, stripe_customer_id, stripe_subscription_id,
        stripe_subscription_status, stripe_subscription_event_at,
        stripe_activation_credit_grant_id, trial_ended_at,
        checkout_initializing_at, checkout_session_id, ` + recoveryUserPromotionSQL + `
 FROM team_billing_account
	 WHERE (($1::uuid IS NOT NULL AND team_id = $1)
	    OR ($1::uuid IS NULL
	        AND (stripe_activation_credit_grant_id IS NULL
	             OR stripe_activation_credit_granted_at IS NULL
	             OR trial_ended_at IS NULL)))
	   AND ($2::uuid IS NULL OR team_id > $2)
 ORDER BY team_id
 LIMIT $3`
	rows, err := pool.Query(ctx, query, target, after, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []billingAccount
	for rows.Next() {
		var a billingAccount
		if err := rows.Scan(&a.TeamID, &a.CustomerID, &a.SubscriptionID, &a.Status, &a.EventAt, &a.GrantID, &a.TrialEndedAt, &a.CheckoutAt, &a.CheckoutSessionID, &a.UserPromotion); err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

func auditAccount(ctx context.Context, pool *pgxpool.Pool, stripe stripeClient, account billingAccount, excluded *uuid.UUID, apply bool) map[string]any {
	out := map[string]any{"team_id": account.TeamID.String(), "mode": "dry-run", "activation_credit_cents": stripe.activationCreditCents()}
	if apply {
		out["mode"] = "apply"
	}
	if excluded != nil && account.TeamID == *excluded {
		out["outcome"], out["reason"] = "skipped", "operationally_excluded"
		return out
	}
	if err := stripe.verifyRecoveryCheckout(ctx, account); err != nil {
		out["outcome"], out["reason"], out["error"] = "unresolved", "stripe_checkout_lookup_failed", err.Error()
		if errors.Is(err, errRecoveryCheckoutUnverified) {
			out["outcome"], out["reason"] = "skipped", "checkout_not_verified_complete"
		}
		return out
	}
	if account.UserPromotion {
		out["outcome"], out["reason"] = "unresolved", "user_promotion_requires_webhook_reconciliation"
		return out
	}
	if account.CustomerID == nil || account.SubscriptionID == nil || strings.TrimSpace(*account.CustomerID) == "" || strings.TrimSpace(*account.SubscriptionID) == "" {
		out["outcome"], out["reason"] = "skipped", "uncertain_local_ownership"
		return out
	}
	sub, err := stripe.subscription(ctx, *account.SubscriptionID)
	if err != nil {
		out["outcome"], out["reason"] = "unresolved", "stripe_subscription_lookup_failed"
		out["error"] = err.Error()
		return out
	}
	if sub.Customer != *account.CustomerID || sub.ID != *account.SubscriptionID {
		out["outcome"], out["reason"] = "skipped", "subscription_ownership_mismatch"
		return out
	}
	if !isActivating(sub.Status) {
		out["outcome"], out["reason"] = "skipped", "subscription_not_active"
		out["stripe_status"] = sub.Status
		return out
	}
	if periodStart, periodEnd, ok := sub.periodBounds(); !ok || periodEnd <= periodStart {
		out["outcome"], out["reason"] = "unresolved", "subscription_period_bounds_missing"
		return out
	}
	grants, err := stripe.grants(ctx, *account.CustomerID)
	if err != nil {
		out["outcome"], out["reason"] = "unresolved", "stripe_grant_lookup_failed"
		out["error"] = err.Error()
		return out
	}
	localGrantID := strings.TrimSpace(deref(account.GrantID))
	identity := activationGrantIdentity(account.TeamID)
	grantID := ""
	matchingGrants := 0
	possibleGrants := 0
	for _, grant := range grants {
		if grant.Category != "promotional" || grant.Amount.Monetary.Currency != "usd" {
			continue
		}
		possibleGrants++
		if stripe.isVerifiedActivationGrant(grant, localGrantID, identity) {
			matchingGrants++
			grantID = grant.ID
		}
	}
	if localGrantID != "" && matchingGrants == 0 {
		out["outcome"], out["reason"] = "unresolved", "local_grant_not_found_in_stripe"
		return out
	}
	if localGrantID == "" && matchingGrants > 1 {
		out["outcome"], out["reason"] = "unresolved", "multiple_possible_activation_grants"
		return out
	}
	if localGrantID == "" && matchingGrants == 0 && possibleGrants > 0 {
		out["outcome"], out["reason"] = "unresolved", "activation_grant_identity_unverified"
		return out
	}
	if grantID == "" {
		out["outcome"], out["reason"] = "unresolved", "activation_grant_requires_webhook_reconciliation"
		return out
	}
	if !apply {
		out["outcome"], out["reason"], out["grant_id"] = "candidate", "existing_stripe_grant_reconcile", grantID
		return out
	}
	grantID, err = applyVerifiedActivation(ctx, pool, stripe, account)
	if err != nil {
		out["outcome"], out["reason"] = "unresolved", "local_activation_failed"
		out["error"] = err.Error()
		return out
	}
	out["outcome"], out["grant_id"] = "repaired", grantID
	return out
}

type stripeActivationEvidence struct {
	subscription stripeSubscription
	grantID      string
	// watermark is the Stripe ordering boundary observed before grant
	// pagination. It must not be derived after those reads, because a later
	// local timestamp could outrank a terminal webhook created in the gap.
	watermark time.Time
}

// revalidateStripeActivation reads the current Stripe authority for a locked
// local account. Recovery must not use the audit snapshot after another
// writer has had a chance to change the subscription or credit grant.
func revalidateStripeActivation(ctx context.Context, stripe stripeClient, account billingAccount) (stripeActivationEvidence, error) {
	if err := stripe.verifyRecoveryCheckout(ctx, account); err != nil {
		return stripeActivationEvidence{}, err
	}
	if account.CustomerID == nil || account.SubscriptionID == nil || strings.TrimSpace(*account.CustomerID) == "" || strings.TrimSpace(*account.SubscriptionID) == "" {
		return stripeActivationEvidence{}, errors.New("local billing ownership is incomplete; rerun the audit")
	}
	sub, err := stripe.subscription(ctx, *account.SubscriptionID)
	if err != nil {
		return stripeActivationEvidence{}, fmt.Errorf("revalidate Stripe subscription: %w", err)
	}
	watermark := stripeRecoveryWatermark(time.Now())
	if sub.ID != *account.SubscriptionID || sub.Customer != *account.CustomerID {
		return stripeActivationEvidence{}, errors.New("Stripe subscription ownership changed; rerun the audit")
	}
	if !isActivating(sub.Status) {
		return stripeActivationEvidence{}, fmt.Errorf("Stripe subscription is no longer active (status %q)", sub.Status)
	}
	if periodStart, periodEnd, ok := sub.periodBounds(); !ok || periodEnd <= periodStart {
		return stripeActivationEvidence{}, errors.New("Stripe subscription period bounds are no longer valid")
	}
	grants, err := stripe.grants(ctx, *account.CustomerID)
	if err != nil {
		return stripeActivationEvidence{}, fmt.Errorf("revalidate Stripe credit grants: %w", err)
	}
	localGrantID := strings.TrimSpace(deref(account.GrantID))
	identity := activationGrantIdentity(account.TeamID)
	grantID := ""
	matchingGrants := 0
	possibleGrants := 0
	for _, grant := range grants {
		if grant.Category != "promotional" || grant.Amount.Monetary.Currency != "usd" {
			continue
		}
		possibleGrants++
		if stripe.isVerifiedActivationGrant(grant, localGrantID, identity) {
			matchingGrants++
			grantID = grant.ID
		}
	}
	if localGrantID != "" && grantID == "" {
		return stripeActivationEvidence{}, errors.New("local activation grant is no longer present in Stripe")
	}
	if localGrantID == "" && matchingGrants > 1 {
		return stripeActivationEvidence{}, errors.New("multiple possible activation grants are present in Stripe")
	}
	if localGrantID == "" && matchingGrants == 0 && possibleGrants > 0 {
		return stripeActivationEvidence{}, errors.New("Stripe activation grant identity or applicability is unverified")
	}
	return stripeActivationEvidence{subscription: sub, grantID: grantID, watermark: watermark}, nil
}

func applyVerifiedActivation(ctx context.Context, pool *pgxpool.Pool, stripe stripeClient, original billingAccount) (string, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var current billingAccount
	err = tx.QueryRow(ctx, `SELECT team_id, stripe_customer_id, stripe_subscription_id,
        stripe_subscription_status, stripe_subscription_event_at,
        stripe_activation_credit_grant_id, trial_ended_at,
        checkout_initializing_at, checkout_session_id, `+recoveryUserPromotionSQL+`
        FROM team_billing_account WHERE team_id = $1 FOR UPDATE`, original.TeamID).
		Scan(&current.TeamID, &current.CustomerID, &current.SubscriptionID, &current.Status, &current.EventAt, &current.GrantID, &current.TrialEndedAt, &current.CheckoutAt, &current.CheckoutSessionID, &current.UserPromotion)
	if err != nil {
		return "", err
	}
	if !sameRecoveryBillingSnapshot(current, original) {
		return "", errors.New("local billing association changed; rerun the audit")
	}
	if current.UserPromotion {
		return "", errors.New("user promotion requires webhook reconciliation")
	}
	// A locked terminal projection is authoritative local evidence that this
	// subscription must not be resurrected from an active Stripe snapshot.
	// The equality checks above reject a terminal update racing with the audit;
	// this guard also rejects a terminal projection that was already present
	// when the audit began.
	if isTerminalSubscriptionStatus(deref(current.Status)) {
		return "", fmt.Errorf("local subscription is already terminal (status %q); rerun the audit", deref(current.Status))
	}
	// The audit evidence was collected before this lock. Re-read Stripe after
	// acquiring the row lock so a replacement, cancellation, or concurrent
	// grant creation cannot be applied from a stale snapshot.
	evidence, err := revalidateStripeActivation(ctx, stripe, current)
	if err != nil {
		return "", err
	}
	sub := evidence.subscription
	periodStart, periodEnd, ok := sub.periodBounds()
	if !ok || periodEnd <= periodStart {
		return "", errors.New("Stripe subscription period bounds are no longer valid")
	}
	grantID := evidence.grantID
	watermark := evidence.watermark
	if current.EventAt != nil && current.EventAt.After(watermark) {
		return "", errors.New("a newer subscription event watermark is already present; rerun the audit")
	}
	if grantID == "" {
		return "", errors.New("missing activation grant requires webhook reconciliation")
	}
	// Bind the verified grant ID into the final read so a change to the grant
	// list cannot substitute a different grant before committing activation.
	verificationAccount := current
	verificationAccount.GrantID = &grantID
	finalEvidence, err := revalidateStripeActivation(ctx, stripe, verificationAccount)
	if err != nil {
		return "", err
	}
	sub = finalEvidence.subscription
	periodStart, periodEnd, ok = sub.periodBounds()
	if !ok || periodEnd <= periodStart {
		return "", errors.New("Stripe subscription period bounds are no longer valid")
	}
	grantID = finalEvidence.grantID
	watermark = finalEvidence.watermark
	// Re-read the locked projection immediately before the local write so the
	// guarded update uses the current subscription status and event watermark.
	var latest billingAccount
	err = tx.QueryRow(ctx, `SELECT team_id, stripe_customer_id, stripe_subscription_id,
        stripe_subscription_status, stripe_subscription_event_at,
        stripe_activation_credit_grant_id, trial_ended_at,
        checkout_initializing_at, checkout_session_id, `+recoveryUserPromotionSQL+`
        FROM team_billing_account WHERE team_id = $1 FOR UPDATE`, original.TeamID).
		Scan(&latest.TeamID, &latest.CustomerID, &latest.SubscriptionID, &latest.Status, &latest.EventAt, &latest.GrantID, &latest.TrialEndedAt, &latest.CheckoutAt, &latest.CheckoutSessionID, &latest.UserPromotion)
	if err != nil {
		return "", err
	}
	if !sameRecoveryBillingSnapshot(latest, current) {
		return "", errors.New("local subscription state changed during revalidation; rerun the audit")
	}
	if isTerminalSubscriptionStatus(deref(latest.Status)) {
		return "", fmt.Errorf("local subscription became terminal during revalidation (status %q); rerun the audit", deref(latest.Status))
	}
	current = latest
	if current.EventAt != nil && current.EventAt.After(watermark) {
		return "", errors.New("a newer subscription event watermark is already present; rerun the audit")
	}
	// Advance the local event watermark in the same transaction as activation;
	// delayed deliveries then fail the normal stale-event check.
	result, err := tx.Exec(ctx, `UPDATE team_billing_account
        SET stripe_subscription_status = $2,
            checkout_initializing_at = NULL,
            checkout_anchor_snapshot = NULL,
            checkout_session_id = CASE WHEN checkout_initializing_at IS NOT NULL THEN NULL ELSE checkout_session_id END,
            current_period_start = to_timestamp($3),
            current_period_end = to_timestamp($4),
            cancel_at_period_end = $5,
            stripe_subscription_event_at = GREATEST(COALESCE(stripe_subscription_event_at, '-infinity'::timestamptz), $7::timestamptz),
            trial_ended_at = COALESCE(trial_ended_at, now()),
            stripe_activation_credit_granted_at = COALESCE(stripe_activation_credit_granted_at, now()),
            stripe_activation_credit_grant_id = COALESCE(stripe_activation_credit_grant_id, $6),
            updated_at = now()
		WHERE team_id = $1
		  AND stripe_subscription_status IS NOT DISTINCT FROM $9::text
		  AND (stripe_subscription_event_at IS NULL OR stripe_subscription_event_at <= $7::timestamptz)
		  AND stripe_subscription_event_at IS NOT DISTINCT FROM $8::timestamptz`, original.TeamID, sub.Status, periodStart, periodEnd, sub.CancelAtPeriodEnd, grantID, watermark, current.EventAt, current.Status)
	if err != nil {
		return "", err
	}
	if result.RowsAffected() != 1 {
		return "", errors.New("subscription event watermark changed; rerun the audit")
	}
	if _, err := tx.Exec(ctx, `UPDATE team_credit_grant SET remaining_usd = 0, updated_at = now() WHERE team_id = $1 AND reason = 'signup trial credit'`, original.TeamID); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return grantID, nil
}

func isActivating(status string) bool {
	return strings.EqualFold(status, "active") ||
		strings.EqualFold(status, "trialing") ||
		strings.EqualFold(status, "past_due")
}

// Stripe webhook created timestamps have whole-second precision. Keep the
// recovery watermark at that same precision so an event created later in the
// same second is not incorrectly treated as stale.
func stripeRecoveryWatermark(now time.Time) time.Time {
	return now.UTC().Truncate(time.Second)
}

func sameRecoveryBillingSnapshot(left, right billingAccount) bool {
	return left.TeamID == right.TeamID &&
		deref(left.CustomerID) == deref(right.CustomerID) &&
		deref(left.SubscriptionID) == deref(right.SubscriptionID) &&
		deref(left.Status) == deref(right.Status) &&
		deref(left.GrantID) == deref(right.GrantID) &&
		sameTime(left.EventAt, right.EventAt) &&
		sameTime(left.CheckoutAt, right.CheckoutAt) &&
		deref(left.CheckoutSessionID) == deref(right.CheckoutSessionID) &&
		left.UserPromotion == right.UserPromotion
}

func isTerminalSubscriptionStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "canceled", "unpaid", "paused", "incomplete_expired":
		return true
	default:
		return false
	}
}

func parseOptionalUUID(raw string) (*uuid.UUID, error) {
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid UUID %q: %w", raw, err)
	}
	return &id, nil
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func sameTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
