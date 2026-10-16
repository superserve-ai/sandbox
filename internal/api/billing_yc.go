package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

type ycApproval struct {
	CompanyIdentity              string `json:"company_identity"`
	ExistingGrantID              string `json:"existing_grant_id,omitempty"`
	ClaimID                      string `json:"claim_id,omitempty"`
	Merchant                     string `json:"merchant_account"`
	Live                         *bool  `json:"live_mode"`
	Region                       string `json:"home_region"`
	Customer                     string `json:"customer_id"`
	Subscription                 string `json:"subscription_id"`
	ExistingSubscriptionApproved bool   `json:"existing_subscription_approved"`
	Evidence                     string `json:"eligibility_reference"`
	SignupEmail                  string `json:"signup_email"`
	FounderEmail                 string `json:"founder_email"`
	EmailMismatchApproved        bool   `json:"email_mismatch_approved"`
}
type ycOperation struct {
	ApprovedGrant                 entitlementGrant
	Team, ID, Contract, Renewal   uuid.UUID
	Request                       ycApproval
	Params                        StripeCreateCheckoutSessionParams
	Customer, Subscription, State string
	FirstInvoice                  string
	Start, End, Attempt           pgtype.Timestamptz
	Revoked                       pgtype.Timestamptz
}

func (h *Handlers) ycOperation(ctx context.Context, team uuid.UUID) (ycOperation, error) {
	o := ycOperation{Team: team}
	var request, terms, grant []byte
	err := h.Pool.QueryRow(ctx, `SELECT id,contract_id,renewal_contract_id,request,resource_terms,COALESCE(customer_id,''),COALESCE(subscription_id,''),state,starts_at,ends_at,provider_attempt_at,revoked_at,COALESCE(first_invoice_id,''),COALESCE(approved_grant_evidence,'{}'::jsonb) FROM billing_yc_operation WHERE team_id=$1`, team).Scan(&o.ID, &o.Contract, &o.Renewal, &request, &terms, &o.Customer, &o.Subscription, &o.State, &o.Start, &o.End, &o.Attempt, &o.Revoked, &o.FirstInvoice, &grant)
	if err != nil {
		return o, err
	}
	if err = json.Unmarshal(request, &o.Request); err != nil {
		return o, err
	}
	if err = json.Unmarshal(grant, &o.ApprovedGrant); err != nil {
		return o, err
	}
	err = json.Unmarshal(terms, &o.Params)
	return o, err
}
func ycTeam(c *gin.Context) (uuid.UUID, bool) {
	team, err := uuid.Parse(c.Param("team_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid team", 400)
		return uuid.Nil, false
	}
	return team, true
}
func (h *Handlers) YCStatus(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	var raw []byte
	err := h.Pool.QueryRow(c.Request.Context(), `SELECT jsonb_build_object('operation_id',id,'contract_id',contract_id,'renewal_contract_id',renewal_contract_id,'company_identity',request->>'company_identity','first_invoice_id',first_invoice_id,'state',state,'customer_id',customer_id,'subscription_id',subscription_id,'starts_at',starts_at,'ends_at',ends_at,'payment_method_ready',payment_method_ready,'revoked_at',revoked_at,'last_error',last_error,'next_check_at',next_check_at) FROM billing_yc_operation WHERE team_id=$1`, team).Scan(&raw)
	if err != nil {
		respondErrorMsg(c, "not_found", "YC operation not found", 404)
		return
	}
	c.Data(200, "application/json", raw)
}
func (h *Handlers) YCPreflight(c *gin.Context) { h.ycApprove(c, false) }
func (h *Handlers) YCApprove(c *gin.Context)   { h.ycApprove(c, true) }
func (h *Handlers) ycApprove(c *gin.Context, apply bool) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	var input ycApproval
	if c.ShouldBindJSON(&input) != nil {
		respondErrorMsg(c, "bad_request", "invalid approval", 400)
		return
	}
	actor, ok := c.Get("actor_id")
	if apply && !ok {
		respondErrorMsg(c, "bad_request", "X-Actor-User-Id is required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	if existing, e := h.ycOperation(ctx, team); e == nil {
		wanted, _ := json.Marshal(input)
		saved, _ := json.Marshal(existing.Request)
		if string(wanted) != string(saved) {
			respondErrorMsg(c, "conflict", "approval differs from existing durable operation", 409)
			return
		}
		h.YCStatus(c)
		return
	} else if !errors.Is(e, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	params, sub, err := h.ycPreflight(ctx, team, input)
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), 409)
		return
	}
	var grantEvidence []byte
	if input.ExistingGrantID != "" {
		verified, e := h.Stripe.(*stripeHTTPClient).validateYCExistingGrant(ctx, sub, params, input.ExistingGrantID)
		if e != nil {
			respondErrorMsg(c, "conflict", e.Error(), 409)
			return
		}
		grantEvidence, _ = json.Marshal(verified)
	}
	if apply {
		approval, err := h.reserveYCAuthority(ctx, team, actor.(uuid.UUID), input)
		if err != nil {
			respondErrorMsg(c, "conflict", err.Error(), 409)
			return
		}
		request, _ := json.Marshal(input)
		terms, _ := json.Marshal(params)
		tx, e := h.Pool.Begin(ctx)
		if e != nil {
			respondError(c, ErrInternal)
			return
		}
		defer tx.Rollback(ctx)
		// Lock the team even before a billing account exists. Checkout locks this
		// account too, and the database fence protects older API replicas.
		if _, e = tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR UPDATE`, team); e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1) ON CONFLICT DO NOTHING`, team)
		}
		if e == nil {
			_, e = h.DB.WithTx(tx).LockTeamBillingAccount(ctx, team)
		}
		if e == nil {
			e = h.ycLocalPreflight(ctx, tx, team, input)
		}
		if e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO billing_yc_operation(team_id,approved_by,evidence_reference,request,resource_terms,customer_id,subscription_id,id,first_invoice_id,approved_grant_evidence) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,NULLIF($9,''),$10) ON CONFLICT(team_id) DO NOTHING`, team, fmt.Sprint(actor), input.Evidence, request, terms, input.Customer, input.Subscription, approval, sub.LatestInvoice, grantEvidence)
		}
		if e == nil {
			var same bool
			e = tx.QueryRow(ctx, `SELECT request=$2::jsonb AND resource_terms=$3::jsonb FROM billing_yc_operation WHERE team_id=$1`, team, request, terms).Scan(&same)
			if e == nil && !same {
				e = errors.New("approval differs from existing durable operation")
			}
		}
		if e == nil {
			e = tx.Commit(ctx)
		}
		if e != nil {
			respondErrorMsg(c, "conflict", e.Error(), 409)
			return
		}
	}
	var start, end any
	if sub.ID != "" {
		for _, item := range sub.Items.Data {
			if item.Price.ID == params.BasePriceID {
				start = time.Unix(item.Start, 0)
				end = time.Unix(item.End, 0)
			}
		}
	}
	c.JSON(200, gin.H{"approved": apply, "customer_id": input.Customer, "subscription_id": input.Subscription, "starts_at": start, "ends_at": end, "new_subscription_anchor": "subscription activation", "usage_requires_payment_method": true})
}
func (h *Handlers) ycLocalPreflight(ctx context.Context, q db.DBTX, team uuid.UUID, in ycApproval) error {
	var region string
	var conflicts bool
	err := q.QueryRow(ctx, `SELECT home_region FROM team WHERE id=$1`, team).Scan(&region)
	if err != nil {
		return err
	}
	if h.Config == nil || region == "" || region != in.Region || region != h.Config.TeamCreationRegion {
		return errors.New("team home region differs from this API cell")
	}
	err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND
 (COALESCE(stripe_customer_id,'')<>$2 OR (stripe_subscription_id IS NOT NULL AND stripe_subscription_id<>$3) OR checkout_initializing_at IS NOT NULL OR stripe_activation_credit_reserved_at IS NOT NULL OR stripe_activation_credit_grant_id IS NOT NULL))
 OR EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND id NOT IN(SELECT contract_id FROM billing_yc_operation WHERE team_id=$1))
 OR EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=$1 AND state<>'selecting')
 OR (NOT $4 AND NOT EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=$1 AND state='selecting'))`, team, in.Customer, in.Subscription, in.ExistingSubscriptionApproved).Scan(&conflicts)
	if err != nil {
		return err
	}
	if conflicts {
		return errors.New("existing billing, checkout, promotion or commercial binding conflicts")
	}
	return nil
}
func (h *Handlers) ycPreflight(ctx context.Context, team uuid.UUID, in ycApproval) (StripeCreateCheckoutSessionParams, invoiceSubscription, error) {
	var params StripeCreateCheckoutSessionParams
	var sub invoiceSubscription
	if !regexp.MustCompile(`^https://www[.]ycombinator[.]com/companies/[a-z0-9]+(-[a-z0-9]+)*$`).MatchString(in.CompanyIdentity) || in.Merchant == "" || in.Live == nil || in.Region == "" || strings.TrimSpace(in.Evidence) == "" || in.SignupEmail == "" || in.FounderEmail == "" {
		return params, sub, errors.New("merchant, mode, home region, eligibility reference and verified emails are required")
	}
	if !strings.EqualFold(strings.TrimSpace(in.SignupEmail), strings.TrimSpace(in.FounderEmail)) && !in.EmailMismatchApproved {
		return params, sub, errors.New("email mismatch requires explicit audited operator approval")
	}
	if in.Subscription != "" && !in.ExistingSubscriptionApproved {
		return params, sub, errors.New("existing subscription requires explicit conversion approval")
	}
	if err := h.ycLocalPreflight(ctx, h.Pool, team, in); err != nil {
		return params, sub, err
	}
	if err := h.ycAuthorityPreflight(ctx, team, in); err != nil {
		return params, sub, err
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return params, sub, errors.New("Stripe verification unavailable")
	}
	if err := client.ycMerchant(ctx, in); err != nil {
		return params, sub, err
	}
	offer, err := h.proOffer("pro_annual")
	if err != nil {
		return params, sub, err
	}
	if err = client.validateProPrice(ctx, offer); err != nil {
		return params, sub, err
	}
	var priceMode struct {
		Live bool `json:"livemode"`
	}
	if err = client.doForm(ctx, http.MethodGet, "/v1/prices/"+url.PathEscape(offer.Price), nil, &priceMode, ""); err != nil {
		return params, sub, err
	}
	if priceMode.Live != *in.Live {
		return params, sub, errors.New("annual price live/test mode differs")
	}
	enabled, err := h.billingExportEnabled(ctx, team)
	if err != nil {
		return params, sub, err
	}
	if !enabled {
		return params, sub, errors.New("invoice export must be enabled")
	}
	prices, err := billingCheckoutPriceIDs(h.billingResourceStates(true))
	if err != nil {
		return params, sub, err
	}
	terms, err := h.freezeProResourceTerms(ctx, team, prices, client)
	if err != nil {
		return params, sub, err
	}
	params = StripeCreateCheckoutSessionParams{BasePriceID: offer.Price, CustomerID: in.Customer, Flexible: true, DeferredResourcePriceIDs: prices, ResourceTerms: terms}
	if in.Customer == "" {
		if in.Subscription != "" || in.ExistingGrantID != "" {
			return params, sub, errors.New("subscription requires mapped customer")
		}
		return params, sub, nil
	}
	var customer ycCustomer
	if err = client.doForm(ctx, http.MethodGet, "/v1/customers/"+url.PathEscape(in.Customer), nil, &customer, ""); err != nil {
		return params, sub, err
	}
	if customer.ID != in.Customer || customer.Deleted || customer.Live != *in.Live {
		return params, sub, errors.New("customer mode or identity differs")
	}
	if err = client.ycSubscriptionInventory(ctx, in.Customer, in.Subscription, ""); err != nil {
		return params, sub, err
	}
	if in.Subscription != "" {
		sub, err = client.invoiceSubscription(ctx, in.Subscription)
		if err != nil {
			return params, sub, err
		}
		if err = validateYCSubscription(sub, params, in); err != nil {
			return params, sub, err
		}
		if err = client.verifyYCFirstInvoice(ctx, sub, params.BasePriceID); err != nil {
			return params, sub, err
		}
	}
	if err = client.ycGrantPreflight(ctx, in.Customer, "", in.ExistingGrantID); err != nil {
		return params, sub, err
	}
	if in.ExistingGrantID != "" {
		if sub.ID == "" {
			return params, sub, errors.New("existing grant adoption requires an existing annual subscription")
		}
		if _, err = client.validateYCExistingGrant(ctx, sub, params, in.ExistingGrantID); err != nil {
			return params, sub, err
		}
	}
	return params, sub, nil
}
func (c *stripeHTTPClient) ycMerchant(ctx context.Context, in ycApproval) error {
	var merchant struct {
		ID string `json:"id"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/account", nil, &merchant, ""); err != nil {
		return err
	}
	if merchant.ID != in.Merchant {
		return errors.New("Stripe merchant differs from approved account")
	}
	return nil
}

type ycCustomer struct {
	ID              string `json:"id"`
	Deleted         bool   `json:"deleted"`
	Live            bool   `json:"livemode"`
	Account         string `json:"customer_account"`
	InvoiceSettings struct {
		DefaultPaymentMethod string `json:"default_payment_method"`
	} `json:"invoice_settings"`
}

func (c *stripeHTTPClient) ycPaymentMethod(ctx context.Context, customer string, sub invoiceSubscription, live bool) (bool, error) {
	var cust ycCustomer
	if err := c.doForm(ctx, http.MethodGet, "/v1/customers/"+url.PathEscape(customer), nil, &cust, ""); err != nil {
		return false, err
	}
	if cust.ID != customer || cust.Deleted || cust.Live != live {
		return false, errors.New("customer identity or mode changed")
	}
	id := sub.DefaultPaymentMethod
	if id == "" {
		id = cust.InvoiceSettings.DefaultPaymentMethod
	}
	if id == "" {
		return false, nil
	}
	var method struct {
		ID       string `json:"id"`
		Customer string `json:"customer"`
		Account  string `json:"customer_account"`
		Type     string `json:"type"`
		Live     bool   `json:"livemode"`
		Card     *struct {
			Month int `json:"exp_month"`
			Year  int `json:"exp_year"`
		} `json:"card"`
	}
	if err := c.doForm(ctx, http.MethodGet, "/v1/payment_methods/"+url.PathEscape(id), nil, &method, ""); err != nil {
		return false, err
	}
	if method.ID != id || method.Live != live || (method.Customer != customer && (cust.Account == "" || method.Account != cust.Account)) {
		return false, errors.New("payment method is not owned by adopted customer")
	}
	if method.Type == "card" && method.Card != nil {
		now := time.Now().UTC()
		return method.Card.Year > now.Year() || (method.Card.Year == now.Year() && method.Card.Month >= int(now.Month())), nil
	}
	if method.Type == "link" {
		if types := sub.PaymentSettings.PaymentMethodTypes; len(types) > 0 && !slices.Contains(types, "link") {
			return false, errors.New("payment_method_required: subscription payment settings do not allow the saved Link method")
		}
		return c.ycLinkSetup(ctx, cust, id, live)
	}
	return false, errors.New("payment_method_required: saved method is not supported for activation; choose a supported reusable method in billing")
}

// A portal-saved Link method has no card expiry. Verify the completed setup for
// this exact method instead of inferring off-session reuse from attachment.
func (c *stripeHTTPClient) ycLinkSetup(ctx context.Context, customer ycCustomer, method string, live bool) (bool, error) {
	var setups struct {
		Data []struct {
			ID               string `json:"id"`
			Customer         string `json:"customer"`
			Account          string `json:"customer_account"`
			PaymentMethod    string `json:"payment_method"`
			Status           string `json:"status"`
			Usage            string `json:"usage"`
			Live             bool   `json:"livemode"`
			Mandate          string `json:"mandate"`
			SingleUseMandate string `json:"single_use_mandate"`
			OnBehalfOf       string `json:"on_behalf_of"`
		} `json:"data"`
	}
	// Filter by method so unrelated setup history cannot consume the refresh
	// budget. One bounded page is enough to fail closed without a history scan.
	query := url.Values{"payment_method": {method}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/setup_intents?"+query.Encode(), nil, &setups, ""); err != nil {
		return false, err
	}
	for _, setup := range setups.Data {
		if setup.ID == "" || setup.PaymentMethod != method || setup.Live != live ||
			(setup.Customer != customer.ID && (customer.Account == "" || setup.Account != customer.Account)) ||
			setup.Status != "succeeded" || setup.Usage != "off_session" || setup.SingleUseMandate != "" || setup.OnBehalfOf != "" {
			continue
		}
		if setup.Mandate != "" {
			var mandate struct {
				ID            string `json:"id"`
				PaymentMethod string `json:"payment_method"`
				Status        string `json:"status"`
				Type          string `json:"type"`
				Live          bool   `json:"livemode"`
				OnBehalfOf    string `json:"on_behalf_of"`
			}
			if err := c.doForm(ctx, http.MethodGet, "/v1/mandates/"+url.PathEscape(setup.Mandate), nil, &mandate, ""); err != nil {
				return false, err
			}
			if mandate.ID != setup.Mandate || mandate.PaymentMethod != method || mandate.Live != live || mandate.Status != "active" || mandate.Type != "multi_use" || mandate.OnBehalfOf != "" {
				return false, errors.New("payment_method_required: Link authorization is no longer reusable; update the payment method in billing")
			}
		}
		return true, nil
	}
	return false, errors.New("payment_method_required: complete Link setup for future payments in billing")
}
func validateYCSubscription(sub invoiceSubscription, p StripeCreateCheckoutSessionParams, in ycApproval) error {
	if sub.ID == "" || sub.Customer != in.Customer || sub.LiveMode != *in.Live || sub.Status != "active" || sub.CollectionMethod != "charge_automatically" || sub.Schedule != "" || sub.Items.HasMore || sub.StartDate <= 0 || sub.BillingCycleAnchor != sub.StartDate || sub.AutomaticTax.Enabled || sub.BillingThresholds != nil || sub.PendingUpdate != nil || len(sub.Discounts) != 0 {
		return errors.New("subscription configuration is incompatible with YC adoption")
	}
	if sub.CancelAt != 0 && !sub.CancelAtPeriodEnd && sub.CancelAt != ycAnnualEnd(time.Unix(sub.StartDate, 0)).Unix() {
		return errors.New("absolute cancellation differs from the approved annual boundary")
	}
	base := invoiceBase{Price: p.BasePriceID, Amount: 1200000, Months: 12}
	resources, err := base.stripSubscription(sub)
	if err != nil {
		return err
	}
	for _, item := range sub.Items.Data {
		if item.Price.ID == p.BasePriceID {
			anchor := time.Unix(sub.StartDate, 0).UTC()
			if item.Start != sub.StartDate || item.End != ycAnnualEnd(anchor).Unix() {
				return errors.New("annual subscription is not in its original annual service term")
			}
		}
	}
	if len(resources.Items.Data) > 0 {
		return validateFrozenProResources(resources, p.ResourceTerms, "")
	}
	return nil
}
func (c *stripeHTTPClient) verifyYCFirstInvoice(ctx context.Context, sub invoiceSubscription, price string) error {
	if sub.LatestInvoice == "" {
		return errors.New("discounted first invoice is missing")
	}
	var inv proPaidInvoice
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(sub.LatestInvoice), nil, &inv, ""); err != nil {
		return err
	}
	if inv.ID != sub.LatestInvoice || inv.Customer != sub.Customer || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != sub.ID || inv.Status != "paid" || inv.Currency != "usd" || inv.Total != 0 || inv.AmountDue != 0 || inv.AmountPaid != 0 || inv.AmountRemaining != 0 || inv.Subtotal != 1200000 || inv.Lines.HasMore || len(inv.Lines.Data) != 1 || inv.StartingBalance != 0 || inv.EndingBalance == nil || *inv.EndingBalance != 0 || inv.PaidOutOfBand || len(inv.Taxes) > 0 || inv.AmountShipping != 0 || inv.PrePaymentCreditNotes != 0 || inv.PostPaymentCreditNotes != 0 {
		return errors.New("first invoice does not prove an actual annual fee discount")
	}
	line := inv.Lines.Data[0]
	var discounts int64
	for _, d := range inv.DiscountAmounts {
		discounts += d.Amount
	}
	if line.Pricing.PriceDetails == nil || line.Pricing.PriceDetails.Price != price || line.Amount != 1200000 || line.Quantity != 1 || discounts != 1200000 || line.Period.Start != sub.StartDate || line.Parent.SubscriptionItemDetails == nil || line.Parent.SubscriptionItemDetails.Proration || line.Parent.SubscriptionItemDetails.Subscription != sub.ID || line.Currency != "usd" || line.Period.End != ycAnnualEnd(time.Unix(sub.StartDate, 0)).Unix() {
		return errors.New("first invoice discount or base service period differs")
	}
	return nil
}
func (c *stripeHTTPClient) ycSubscriptionInventory(ctx context.Context, customer, allowed, operation string) error {
	var list struct {
		Data    []invoiceSubscription `json:"data"`
		HasMore bool                  `json:"has_more"`
	}
	q := url.Values{"customer": {customer}, "status": {"all"}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/subscriptions?"+q.Encode(), nil, &list, ""); err != nil {
		return err
	}
	if list.HasMore {
		return errors.New("subscription inventory exceeds preflight bound; operator reconciliation required")
	}
	for _, s := range list.Data {
		if s.ID != allowed && !(operation != "" && s.Metadata["yc_operation"] == operation) && s.Status != "canceled" && s.Status != "incomplete_expired" {
			return errors.New("conflicting customer subscription")
		}
	}
	return nil
}
func (h *Handlers) YCActivate(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	err := h.reconcileYC(ctx, team)
	if err != nil {
		h.ycSaveError(ctx, team, err)
		c.JSON(202, gin.H{"state": "pending", "error": err.Error()})
		return
	}
	h.YCStatus(c)
}
func (h *Handlers) YCRevoke(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	actor, ok := c.Get("actor_id")
	if !ok {
		respondErrorMsg(c, "bad_request", "X-Actor-User-Id is required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	o, err := h.ycOperation(ctx, team)
	if err != nil {
		respondErrorMsg(c, "not_found", "YC operation not found", 404)
		return
	}
	if h.PromotionAuthPool == nil {
		respondError(c, ErrInternal)
		return
	}
	token := uuid.New()
	if o.Customer != "" {
		if _, err = h.DB.ClaimStripeWebhookProcessingLease(ctx, db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token}); err != nil {
			respondErrorMsg(c, "conflict", "billing operation in progress; retry revocation", 409)
			return
		}
		defer func() {
			ack, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: o.Customer, Token: token})
		}()
	}
	_, err = h.PromotionAuthPool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, o.ID, team, actor.(uuid.UUID))
	if err == nil {
		err = h.syncYCRevocation(ctx, &o)
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	h.YCStatus(c)
}

func (h *Handlers) ycPaymentGate(ctx context.Context, team uuid.UUID) (found, ready bool, state string, err error) {
	if h.Pool == nil {
		return
	}
	err = h.Pool.QueryRow(ctx, `SELECT payment_method_ready AND payment_method_checked_at>clock_timestamp()-interval '5 minutes',state FROM billing_yc_operation WHERE team_id=$1`, team).Scan(&ready, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		return
	}
	found = err == nil
	return
}

func ycAnnualEnd(start time.Time) time.Time {
	start = start.UTC()
	year, month, day := start.Date()
	last := time.Date(year+1, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
	return time.Date(year+1, month, min(day, last), start.Hour(), start.Minute(), start.Second(), start.Nanosecond(), time.UTC)
}

func (o ycOperation) currentApprovedGrant() string {
	if o.ApprovedGrant.ID == "" || o.ApprovedGrant.ExpiresAt <= time.Now().Unix() {
		return ""
	}
	return o.ApprovedGrant.ID
}
