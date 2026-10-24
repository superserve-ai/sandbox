package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

type sponsoredAnnualRequest struct {
	Merchant     string    `json:"merchant_account"`
	Key          string    `json:"idempotency_key"`
	Sponsorship  uuid.UUID `json:"sponsorship_id"`
	Customer     string    `json:"customer_id"`
	Subscription string    `json:"subscription_id"`
	Item         string    `json:"item_id"`
	Price        string    `json:"base_price_id"`
	Live         *bool     `json:"live_mode"`
	Reason       string    `json:"reason"`
	Reference    string    `json:"reference"`
	Fingerprint  string    `json:"preflight_fingerprint,omitempty"`
}

func (r sponsoredAnnualRequest) validate() error {
	if !strings.HasPrefix(r.Merchant, "acct_") || strings.TrimSpace(r.Key) == "" || len(r.Key) > 200 || r.Sponsorship == uuid.Nil || !strings.HasPrefix(r.Customer, "cus_") || !strings.HasPrefix(r.Subscription, "sub_") || !strings.HasPrefix(r.Item, "si_") || !strings.HasPrefix(r.Price, "price_") || r.Live == nil || strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 2000 || strings.TrimSpace(r.Reference) == "" || len(r.Reference) > 2000 {
		return errors.New("exact sponsorship, customer, subscription, annual item, price, mode and audited reason/reference are required")
	}
	return nil
}

type sponsoredAnnualAuthority struct {
	ID, Team, Sponsorship, Contract, Renewal                            uuid.UUID
	Customer, Subscription, Item, Price, Product, Region, State, Cursor string
	Live                                                                bool
	Start, End                                                          time.Time
	Request                                                             sponsoredAnnualRequest
	Params                                                              StripeCreateCheckoutSessionParams
}

func (o sponsoredAnnualAuthority) base() invoiceBase {
	return invoiceBase{Price: o.Price, Item: o.Item, Product: o.Product, Live: o.Live, Amount: 1200000, Months: 12, Anchor: o.Start, WaiverEnd: o.End.Unix()}
}
func (h *Handlers) sponsoredAnnualAuthority(ctx context.Context, team uuid.UUID, reader db.DBTX) (sponsoredAnnualAuthority, error) {
	var o sponsoredAnnualAuthority
	var request, terms []byte
	err := reader.QueryRow(ctx, `SELECT a.id,a.team_id,a.sponsorship_id,a.contract_id,a.renewal_contract_id,a.customer_id,a.subscription_id,a.item_id,a.base_price_id,a.base_product_id,a.home_region,a.live_mode,a.starts_at,a.waiver_ends_at,a.state,COALESCE(a.invoice_cursor,''),a.request,o.resource_terms FROM billing_sponsored_annual_authority a JOIN billing_sponsored_operation o ON o.id=a.sponsorship_id WHERE a.team_id=$1 ORDER BY a.approved_at DESC LIMIT 1`, team).Scan(&o.ID, &o.Team, &o.Sponsorship, &o.Contract, &o.Renewal, &o.Customer, &o.Subscription, &o.Item, &o.Price, &o.Product, &o.Region, &o.Live, &o.Start, &o.End, &o.State, &o.Cursor, &request, &terms)
	if err != nil {
		return o, err
	}
	if err = json.Unmarshal(request, &o.Request); err != nil {
		return o, err
	}
	err = json.Unmarshal(terms, &o.Params)
	return o, err
}
func (h *Handlers) loadSponsoredAnnualBase(ctx context.Context, team uuid.UUID, a *invoiceAccount, reader db.DBTX) error {
	var item, price, product string
	var live bool
	var start, end time.Time
	var renewal uuid.UUID
	err := reader.QueryRow(ctx, `SELECT item_id,base_price_id,starts_at,waiver_ends_at,renewal_contract_id,base_product_id,live_mode FROM billing_sponsored_annual_authority WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3`, team, a.Customer, a.Subscription).Scan(&item, &price, &start, &end, &renewal, &product, &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if a.Base.Price != "" && (a.Base.Price != price || a.Base.Amount != 1200000 || a.Base.Months != 12 || !a.Base.Anchor.Equal(start)) {
		return errors.New("annual fee authority conflicts with commercial terms")
	}
	var conflict bool
	if err = reader.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3 AND charge_kind<>'sponsored_entitlement' AND id<>$4)`, team, a.Customer, a.Subscription, renewal).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return errors.New("annual fee has an undesignated commercial successor")
	}
	a.Base = invoiceBase{Price: price, Item: item, Product: product, Live: live, Amount: 1200000, Months: 12, Anchor: start, WaiverEnd: end.Unix()}
	return nil
}

// A separate billing_schedules field can override item timing even when schedule
// is null. Unknown settings cannot be silently erased or treated as an anniversary.
func validateSponsoredAnnualTiming(sub invoiceSubscription) error {
	raw := strings.TrimSpace(string(sub.BillingSchedules))
	if raw != "" && raw != "null" && raw != "[]" {
		return errors.New("unsupported billing_schedules override; verified provider reconciliation required")
	}
	if sub.Schedule != "" || sub.PendingUpdate != nil || sub.TrialStart != 0 || sub.TrialEnd != 0 || len(sub.Discounts) != 0 || sub.AutomaticTax.Enabled || sub.BillingThresholds != nil {
		return errors.New("annual adoption has unsupported schedule, trial, discount, tax or pending update")
	}
	return nil
}
func validateSponsoredAnnualSubscription(o sponsoredAnnualAuthority, sub invoiceSubscription, rounding string, initial bool) error {
	if sub.ID != o.Subscription || sub.Customer != o.Customer || sub.LiveMode != o.Live || sub.StartDate != o.Start.Unix() || sub.BillingCycleAnchor != o.Start.Unix() || sub.CollectionMethod != "charge_automatically" || sub.Items.HasMore {
		return errors.New("annual subscription association or anniversary changed")
	}
	if err := validateSponsoredAnnualTiming(sub); err != nil {
		return err
	}
	if initial && (sub.Status != "active" || sub.CancelAt != 0 || sub.CancelAtPeriodEnd || sub.CanceledAt != 0) {
		return errors.New("annual adoption requires an active uncanceled subscription")
	}
	if sub.PauseCollection == nil || sub.PauseCollection.Behavior != "keep_as_draft" || sub.PauseCollection.ResumesAt != 0 {
		return errors.New("annual adoption requires the existing durable invoice hold")
	}
	resources, err := o.base().stripSubscription(sub)
	if err != nil {
		return err
	}
	if initial {
		for _, item := range sub.Items.Data {
			if item.ID == o.Item && (item.Start != o.Start.Unix() || item.End != o.End.Unix()) {
				return errors.New("annual item does not retain the original service year")
			}
		}
	}
	roundingItems := 0
	for _, item := range resources.Items.Data {
		if rounding != "" && item.Price.ID == rounding {
			roundingItems++
			p := item.Price
			amount, err := meterDecimal(p.UnitAmountDecimal)
			if item.ID == "" || !p.Active || !proResourceShape(p) || p.Recurring.Meter == "" || err != nil || amount.Cmp(big.NewRat(1, 1)) != 0 {
				return errors.New("rounding adjustment item must use an active USD monthly metered one-cent price")
			}
		}
	}
	if roundingItems != 1 {
		return errors.New("subscription must include exactly one rounding adjustment item")
	}
	if err = validateFrozenProResources(resources, o.Params.ResourceTerms, rounding); err != nil {
		return err
	}
	return invoiceCalendarCompatible(o.Start, resources, rounding)
}
func annualBoundary(anchor time.Time, months int) time.Time {
	anchor = anchor.UTC()
	first := time.Date(anchor.Year(), anchor.Month(), 1, anchor.Hour(), anchor.Minute(), anchor.Second(), 0, time.UTC).AddDate(0, months, 0)
	day := min(anchor.Day(), first.AddDate(0, 1, -1).Day())
	return time.Date(first.Year(), first.Month(), day, first.Hour(), first.Minute(), first.Second(), 0, time.UTC)
}

func (h *Handlers) annualPreflight(ctx context.Context, team uuid.UUID, r sponsoredAnnualRequest, reader db.DBTX, client *stripeHTTPClient) (sponsoredAnnualAuthority, []byte, string, error) {
	o := sponsoredAnnualAuthority{Team: team, Sponsorship: r.Sponsorship, Customer: r.Customer, Subscription: r.Subscription, Item: r.Item, Price: r.Price, Live: *r.Live, Request: r}
	var terms []byte
	var rounding string
	var valid bool
	err := reader.QueryRow(ctx, `SELECT o.contract_id,o.anchor,o.ends_at,o.resource_terms,t.home_region,i.adjustment_price_id,
 o.state='active' AND o.revoked_at IS NULL AND c.status='active' AND a.stripe_customer_id=o.customer_id AND a.stripe_subscription_id=o.subscription_id AND a.commercial_billing_anchor=o.anchor AND o.starts_at=o.anchor AND o.ends_at=billing_anniversary_boundary(o.anchor,12) AND o.ends_at>clock_timestamp()
 FROM billing_sponsored_operation o JOIN team t ON t.id=o.team_id JOIN team_billing_account a ON a.team_id=o.team_id JOIN billing_commercial_contract c ON c.id=o.contract_id JOIN billing_invoice_account i ON i.team_id=o.team_id AND i.customer_id=o.customer_id AND i.subscription_id=o.subscription_id
 WHERE o.id=$1 AND o.team_id=$2 AND o.customer_id=$3 AND o.subscription_id=$4`, r.Sponsorship, team, r.Customer, r.Subscription).Scan(&o.Contract, &o.Start, &o.End, &terms, &o.Region, &rounding, &valid)
	if err != nil {
		return o, nil, "", err
	}
	if !valid || h.Config == nil || o.Region != h.Config.TeamCreationRegion {
		return o, nil, "", errors.New("active sponsorship or home region differs")
	}
	if err = json.Unmarshal(terms, &o.Params); err != nil {
		return o, nil, "", err
	}
	var schedule bool
	err = reader.QueryRow(ctx, `SELECT count(*)=12 AND bool_and(month_offset BETWEEN 0 AND 11 AND amount_cents=CASE WHEN month_offset<3 THEN 3000000 ELSE 100000 END) FROM billing_contract_entitlement_schedule WHERE contract_id=$1`, o.Contract).Scan(&schedule)
	if err != nil {
		return o, nil, "", err
	}
	if !schedule {
		return o, nil, "", errors.New("annual adoption requires the original three large and nine standard allowances")
	}
	var pending bool
	if err = reader.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_usage_entitlement WHERE contract_id=$1 AND state<>'issued') OR EXISTS(SELECT 1 FROM billing_invoice_close WHERE team_id=$2 AND state NOT IN ('verified','released')) OR EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$2 AND stripe_activation_credit_reserved_at IS NOT NULL) OR EXISTS(SELECT 1 FROM billing_sponsored_promotion_recovery WHERE team_id=$2 AND completed_at IS NULL)`, o.Contract, team).Scan(&pending); err != nil {
		return o, nil, "", err
	}
	// Existing close plans freeze the fee authority. Supporting their adoption needs
	// a separate historical-plan reconciliation rather than silently changing it.
	if pending {
		return o, nil, "", errors.New("in-flight entitlements, activation promotions, or unfinished invoice close plans require explicit reconciliation before adoption")
	}
	if err = client.ycMerchant(ctx, ycApproval{Merchant: r.Merchant}); err != nil {
		return o, nil, "", err
	}
	sub, err := client.invoiceSubscription(ctx, o.Subscription)
	if err != nil {
		return o, nil, "", err
	}
	for _, item := range sub.Items.Data {
		if item.ID == o.Item {
			o.Product = item.Price.Product
		}
	}
	if o.Product == "" {
		return o, nil, "", errors.New("exact annual item is missing")
	}
	if err = validateSponsoredAnnualSubscription(o, sub, rounding, true); err != nil {
		return o, nil, "", err
	}
	debt, err := client.entitlementDebt(ctx, o.Customer)
	if err != nil {
		return o, nil, "", err
	}
	if debt != "" {
		return o, nil, "", errors.New("existing debt blocks annual adoption")
	}
	grants, err := h.annualGrantEvidence(ctx, o, reader, client)
	if err != nil {
		return o, nil, "", err
	}
	inventory, err := client.annualWaiverInventory(ctx, o, rounding)
	if err != nil {
		return o, nil, "", err
	}
	var history json.RawMessage
	err = reader.QueryRow(ctx, `SELECT jsonb_build_object('entitlements',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.period_start) FROM billing_usage_entitlement e WHERE e.contract_id=$1),'[]'::jsonb),'usage_exports',(SELECT count(*) FROM billing_usage_export WHERE team_id=$2),'compute_intervals',(SELECT count(*) FROM sandbox_compute_billing_interval WHERE team_id=$2))`, o.Contract, team).Scan(&history)
	if err != nil {
		return o, nil, "", err
	}
	fresh, err := client.invoiceSubscription(ctx, o.Subscription)
	if err != nil {
		return o, nil, "", err
	}
	oldSub, _ := json.Marshal(sub)
	newSub, _ := json.Marshal(fresh)
	if string(oldSub) != string(newSub) {
		return o, nil, "", errors.New("subscription changed during annual preflight")
	}
	evidence, _ := json.Marshal(gin.H{"subscription": sub, "waiver_inventory": inventory, "history": history, "grants": grants, "observed_at": time.Now().UTC()})
	// Configuration is compared while consumption is allowed to advance normally.
	stable, _ := json.Marshal(gin.H{"subscription": sub, "contract": o.Contract, "terms": json.RawMessage(terms), "inventory": inventory})
	hash := sha256.Sum256(stable)
	return o, evidence, hex.EncodeToString(hash[:]), nil
}

func (c *stripeHTTPClient) annualWaiverInventory(ctx context.Context, o sponsoredAnnualAuthority, rounding string) (json.RawMessage, error) {
	usagePrices := map[string]bool{}
	if rounding != "" {
		usagePrices[rounding] = true
	}
	for _, term := range o.Params.ResourceTerms {
		if term.PriceID != "" {
			usagePrices[term.PriceID] = true
		}
	}
	var page struct {
		Data    []StripeInvoiceAmounts `json:"data"`
		HasMore bool                   `json:"has_more"`
	}
	q := url.Values{"customer": {o.Customer}, "subscription": {o.Subscription}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+q.Encode(), nil, &page, ""); err != nil {
		return nil, err
	}
	if page.HasMore {
		return nil, errors.New("annual waiver invoice inventory exceeds reconciliation bound")
	}
	for _, inv := range page.Data {
		if inv.ID == "" || inv.Customer != o.Customer || inv.LiveMode != o.Live || inv.Lines.HasMore || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != o.Subscription {
			return nil, errors.New("annual waiver invoice inventory is incomplete")
		}
		for _, line := range inv.Lines.Data {
			itemMatches := line.Parent.SubscriptionItemDetails != nil && line.Parent.SubscriptionItemDetails.SubscriptionItem == o.Item
			priceMatches := line.Pricing.PriceDetails != nil && line.Pricing.PriceDetails.Price == o.Price
			if inv.Status != "void" && (itemMatches || priceMatches) {
				if itemMatches && !priceMatches {
					return nil, errors.New("historical annual item price differs; explicit financial reconciliation required")
				}
				// An explicit local waiver is adopted only when there is no collectible
				// historical base line. Discounted gross invoices require separate accounting.
				if line.Amount != 0 || inv.Status != "paid" {
					return nil, errors.New("historical annual fee needs explicit financial reconciliation")
				}
				if line.Period.End > o.End.Unix() {
					return nil, errors.New("historical annual line extends into paid renewal; provider billed-through reconciliation required")
				}
			} else if inv.Status != "void" && (line.Pricing.PriceDetails == nil || !usagePrices[line.Pricing.PriceDetails.Price]) {
				// A replaced annual item and price must not disappear from the
				// waiver check merely because neither matches the current item.
				return nil, errors.New("unrecognized historical invoice price; explicit financial reconciliation required")
			}
		}
	}
	var pending struct {
		Data    []json.RawMessage `json:"data"`
		HasMore bool              `json:"has_more"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoiceitems?"+url.Values{"customer": {o.Customer}, "pending": {"true"}, "limit": {"1"}}.Encode(), nil, &pending, ""); err != nil {
		return nil, err
	}
	if pending.HasMore || len(pending.Data) != 0 {
		return nil, errors.New("pending invoice items block annual adoption")
	}
	preview, err := c.PreviewBillingInvoice(ctx, o.Subscription)
	if err != nil {
		return nil, err
	}
	if preview.Customer != o.Customer || preview.LiveMode != o.Live {
		return nil, errors.New("annual preview ownership differs")
	}
	for _, line := range preview.Lines.Data {
		if (line.Parent.SubscriptionItemDetails != nil && line.Parent.SubscriptionItemDetails.SubscriptionItem == o.Item) || (line.Pricing.PriceDetails != nil && line.Pricing.PriceDetails.Price == o.Price) {
			return nil, errors.New("first-year preview includes an annual fee")
		}
		if line.Pricing.PriceDetails == nil || !usagePrices[line.Pricing.PriceDetails.Price] {
			return nil, errors.New("first-year preview includes an unrecognized price")
		}
	}
	// Preview usage amounts change as the team runs; do not turn them into terms.
	raw, err := json.Marshal(page.Data)
	return raw, err
}

func (h *Handlers) SponsoredAnnualPreflight(c *gin.Context) { h.sponsoredAnnualApply(c, false) }
func (h *Handlers) SponsoredAnnualApply(c *gin.Context)     { h.sponsoredAnnualApply(c, true) }
func (h *Handlers) sponsoredAnnualApply(c *gin.Context, apply bool) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	var r sponsoredAnnualRequest
	if c.ShouldBindJSON(&r) != nil || r.validate() != nil {
		respondErrorMsg(c, "bad_request", "invalid annual adoption request", 400)
		return
	}
	actor, actorOK := c.Get("actor_id")
	if apply && !actorOK {
		respondErrorMsg(c, "bad_request", "X-Actor-User-Id is required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	fingerprint := r.Fingerprint
	r.Fingerprint = ""
	request, _ := json.Marshal(r)
	var id uuid.UUID
	var same bool
	err := h.Pool.QueryRow(ctx, `SELECT id,request=$3::jsonb FROM billing_sponsored_annual_authority WHERE team_id=$1 AND idempotency_key=$2`, team, r.Key, request).Scan(&id, &same)
	if err == nil {
		if !same {
			respondErrorMsg(c, "conflict", "idempotency key has different annual terms", 409)
			return
		}
		h.sponsoredAnnualStatus(c, team, id)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		respondError(c, ErrInternal)
		return
	}
	var reader db.DBTX = h.Pool
	token := uuid.New()
	if apply {
		if _, err = h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: r.Customer, Token: token}); err != nil {
			respondErrorMsg(c, "conflict", "billing reconciliation is busy", 409)
			return
		}
		defer func() {
			ack, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: r.Customer, Token: token})
		}()
	}
	var tx pgx.Tx
	if apply {
		if fingerprint == "" {
			respondErrorMsg(c, "bad_request", "preflight_fingerprint is required", 400)
			return
		}
		var e error
		tx, e = h.Pool.Begin(ctx)
		if e != nil {
			respondError(c, ErrInternal)
			return
		}
		defer tx.Rollback(ctx)
		if _, e = h.DB.WithTx(tx).LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: r.Customer, Token: token}); e != nil {
			respondError(c, ErrInternal)
			return
		}
		if _, e = h.DB.WithTx(tx).LockTeamBillingAccount(ctx, team); e != nil {
			respondError(c, ErrInternal)
			return
		}
		reader = tx
	}
	o, evidence, observed, err := h.annualPreflight(ctx, team, r, reader, client)
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), 409)
		return
	}
	if !apply {
		c.JSON(200, gin.H{"eligible": true, "preflight_fingerprint": observed, "starts_at": o.Start, "waiver_ends_at": o.End, "renewal_amount_cents": 1200000, "evidence": json.RawMessage(evidence)})
		return
	}
	if fingerprint != observed {
		respondErrorMsg(c, "conflict", "provider configuration changed; repeat preflight", 409)
		return
	}
	err = tx.QueryRow(ctx, `INSERT INTO billing_sponsored_annual_authority(team_id,sponsorship_id,contract_id,idempotency_key,request,approved_by,customer_id,subscription_id,item_id,base_price_id,base_product_id,live_mode,home_region,starts_at,waiver_ends_at,provider_evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(team_id,idempotency_key) DO NOTHING RETURNING id`, team, o.Sponsorship, o.Contract, r.Key, request, actor, o.Customer, o.Subscription, o.Item, o.Price, o.Product, o.Live, o.Region, o.Start, o.End, evidence).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id,request=$3::jsonb FROM billing_sponsored_annual_authority WHERE team_id=$1 AND idempotency_key=$2`, team, r.Key, request).Scan(&id, &same)
		if err == nil && !same {
			err = errors.New("idempotency key has different annual terms")
		}
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE billing_funding_account SET next_check_at=clock_timestamp() WHERE team_id=$1`, team)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		respondErrorMsg(c, "conflict", fmt.Sprint(err), 409)
		return
	}
	h.sponsoredAnnualStatus(c, team, id)
}
func (h *Handlers) SponsoredAnnualStatus(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("operation_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid operation id", 400)
		return
	}
	h.sponsoredAnnualStatus(c, team, id)
}
func (h *Handlers) sponsoredAnnualStatus(c *gin.Context, team, id uuid.UUID) {
	var raw json.RawMessage
	err := h.Pool.QueryRow(c.Request.Context(), `SELECT to_jsonb(a)-ARRAY['lease_token','lease_until'] FROM billing_sponsored_annual_authority a WHERE team_id=$1 AND id=$2`, team, id).Scan(&raw)
	if err != nil {
		respondErrorMsg(c, "not_found", "annual adoption not found", 404)
		return
	}
	c.Data(200, "application/json", raw)
}

func (h *Handlers) annualGrantEvidence(ctx context.Context, o sponsoredAnnualAuthority, reader db.DBTX, c *stripeHTTPClient) ([]map[string]any, error) {
	rows, err := reader.Query(ctx, `SELECT stripe_credit_grant_id,amount_cents,extract(epoch FROM provider_invoice_end)::bigint+1,issuance_evidence FROM billing_usage_entitlement WHERE contract_id=$1 AND state='issued' ORDER BY period_start`, o.Contract)
	if err != nil {
		return nil, err
	}
	type saved struct {
		id          string
		amount, end int64
		evidence    []byte
	}
	var expected []saved
	for rows.Next() {
		var e saved
		if err = rows.Scan(&e.id, &e.amount, &e.end, &e.evidence); err != nil {
			rows.Close()
			return nil, err
		}
		expected = append(expected, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(expected) == 0 || len(expected) > 12 {
		return nil, errors.New("annual adoption requires a bounded existing issued grant inventory")
	}
	var page struct {
		Data    []entitlementGrant `json:"data"`
		HasMore bool               `json:"has_more"`
	}
	if err = c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+url.Values{"customer": {o.Customer}, "limit": {"100"}}.Encode(), nil, &page, ""); err != nil {
		return nil, err
	}
	if page.HasMore {
		return nil, errors.New("annual credit inventory is incomplete")
	}
	byID := map[string]entitlementGrant{}
	for _, g := range page.Data {
		if _, exists := byID[g.ID]; exists || g.Customer != o.Customer || g.ID == "" {
			return nil, errors.New("annual credit inventory identity differs")
		}
		byID[g.ID] = g
	}
	var result []map[string]any
	for _, e := range expected {
		g, ok := byID[e.id]
		var issued entitlementGrant
		if err := json.Unmarshal(e.evidence, &issued); err != nil {
			return nil, err
		}
		if !ok || g.VoidedAt != 0 || !reflect.DeepEqual(g, issued) || g.Amount.Monetary.Value != e.amount || g.Amount.Monetary.Currency != "usd" || g.ExpiresAt != e.end || g.Applicability.Scope.PriceType != "" {
			return nil, errors.New("issued sponsored grant differs from provider history")
		}
		for _, price := range g.Applicability.Scope.Prices {
			if price.ID == o.Price {
				return nil, errors.New("sponsored credit must not fund annual fees")
			}
		}
		balance, e2 := c.grantLedgerBalance(ctx, o.Customer, g.ID)
		if e2 != nil {
			return nil, e2
		}
		if balance < 0 || balance > e.amount {
			return nil, errors.New("issued grant balance is invalid")
		}
		result = append(result, map[string]any{"grant": g, "remaining_cents": balance})
		delete(byID, g.ID)
	}
	staff, err := h.issuedStaffCredits(ctx, reader, o.Customer)
	if err != nil {
		return nil, err
	}
	for _, g := range byID {
		if g.VoidedAt == 0 && (g.ExpiresAt == 0 || g.ExpiresAt > time.Now().Unix()) && !isStaffCredit(g, staff) {
			return nil, errors.New("unrecognized unexpired credit conflicts with annual adoption")
		}
	}
	return result, nil
}
