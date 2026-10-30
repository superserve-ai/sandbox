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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

func (c *stripeHTTPClient) verifyProUpgradePayment(ctx context.Context, u proUpgrade, s StripeRetrievedCheckoutSession, verifyMethod bool) (string, []byte, error) {
	if s.Currency != "usd" || s.AmountSubtotal != u.Amount || s.AmountTotal < 0 || s.AmountTotal > u.Amount || s.TotalDetails.Tax != 0 || s.TotalDetails.Shipping != 0 || s.TotalDetails.Discount != u.Amount-s.AmountTotal || (s.PaymentStatus != "paid" && s.PaymentStatus != "no_payment_required") || s.InvoiceID == "" {
		return "", nil, &proPaymentReviewError{reason: "upgrade checkout amount or payment evidence differs"}
	}
	var invoice proPaidInvoice
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(s.InvoiceID), nil, &invoice, ""); err != nil {
		return "", nil, err
	}
	if invoice.ID != s.InvoiceID || invoice.Customer != u.Customer || invoice.Status != "paid" || invoice.Currency != "usd" || invoice.AmountPaid != s.AmountTotal || invoice.AmountDue != s.AmountTotal || invoice.AmountRemaining != 0 || invoice.PaidOutOfBand || invoice.StartingBalance != 0 || invoice.EndingBalance == nil || *invoice.EndingBalance != 0 || invoice.PrePaymentCreditNotes != 0 || invoice.PostPaymentCreditNotes != 0 || invoice.StatusTransitions.PaidAt <= 0 || invoice.Lines.HasMore || len(invoice.Lines.Data) != 1 || invoice.Lines.Data[0].Amount != u.Amount || invoice.Lines.Data[0].Currency != "usd" || invoice.Lines.Data[0].Quantity != 1 {
		return "", nil, &proPaymentReviewError{reason: "upgrade invoice does not prove the quoted one-off payment"}
	}
	var method string
	var intent struct {
		ID, Customer, Currency, Status string
		AmountReceived                 int64             `json:"amount_received"`
		LatestCharge                   string            `json:"latest_charge"`
		PaymentMethod                  string            `json:"payment_method"`
		SetupFutureUsage               string            `json:"setup_future_usage"`
		Metadata                       map[string]string `json:"metadata"`
	}
	var charge json.RawMessage
	if s.AmountTotal > 0 {
		if s.PaymentIntentID == "" {
			return "", nil, &proPaymentReviewError{reason: "upgrade payment intent is missing"}
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/payment_intents/"+url.PathEscape(s.PaymentIntentID), nil, &intent, ""); err != nil {
			return "", nil, err
		}
		if intent.ID != s.PaymentIntentID || intent.Status != "succeeded" || intent.Customer != u.Customer || intent.Currency != "usd" || intent.AmountReceived != s.AmountTotal || intent.Metadata["pro_upgrade_id"] != u.ID.String() || intent.SetupFutureUsage != "off_session" {
			return "", nil, &proPaymentReviewError{reason: "upgrade payment intent differs"}
		}
		var err error
		charge, err = c.verifyProCharge(ctx, intent.LatestCharge, intent.ID, u.Customer, s.AmountTotal)
		if err != nil {
			return "", nil, err
		}
		method = intent.PaymentMethod
	} else {
		var customer struct {
			ID              string
			InvoiceSettings struct {
				DefaultPaymentMethod string `json:"default_payment_method"`
			} `json:"invoice_settings"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/customers/"+url.PathEscape(u.Customer), nil, &customer, ""); err != nil {
			return "", nil, err
		}
		if customer.ID != u.Customer {
			return "", nil, errors.New("upgrade customer differs")
		}
		method = customer.InvoiceSettings.DefaultPaymentMethod
	}
	if method != "" && verifyMethod {
		var pm struct{ ID, Customer, Type string }
		if err := c.doForm(ctx, http.MethodGet, "/v1/payment_methods/"+url.PathEscape(method), nil, &pm, ""); err != nil {
			return "", nil, err
		}
		if pm.ID != method || pm.Customer != u.Customer || pm.Type != "card" {
			return "", nil, errors.New("upgrade saved payment method differs")
		}
	}
	evidence, err := json.Marshal(struct {
		Session StripeRetrievedCheckoutSession
		Invoice proPaidInvoice
		Intent  any
		Charge  json.RawMessage
	}{s, invoice, intent, charge})
	return method, evidence, err
}

func (h *Handlers) issueProUpgradeCredit(ctx context.Context, conn *pgxpool.Conn, u *proUpgrade, c *stripeHTTPClient) error {
	credit := u.bridgeCreditAmount()
	expires, err := u.creditExpiry()
	if err != nil {
		return err
	}
	if credit == 0 {
		tag, err := conn.Exec(ctx, `UPDATE billing_pro_upgrade SET state='credited' WHERE id=$1 AND bridge_credit_cents=0 AND payment_evidence IS NOT NULL`, u.ID)
		if err == nil && tag.RowsAffected() != 1 {
			return errors.New("upgrade zero credit lacks accepted payment proof")
		}
		return err
	}
	grant := derefString(u.Grant)
	if grant == "" {
		var closing bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_period p JOIN billing_invoice_account a USING(team_id) WHERE p.team_id=$1 AND p.period_end<=clock_timestamp() AND p.period_end>a.enrolled_at AND NOT EXISTS(SELECT 1 FROM billing_invoice_close j WHERE j.team_id=p.team_id AND j.period_start=p.period_start AND j.period_end=p.period_end AND j.state='released'))`, u.Team).Scan(&closing); err != nil {
			return err
		}
		if closing {
			return errors.New("upgrade credit is waiting for the preceding invoice close")
		}
		if err := c.rejectCompetingCreditInvoice(ctx, u.Customer, "", h.nowUTC().Unix()); err != nil {
			return err
		}
	}
	if grant == "" {
		var inventory struct {
			Data    []entitlementGrant `json:"data"`
			HasMore bool               `json:"has_more"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/billing/credit_grants?"+url.Values{"customer": {u.Customer}, "limit": {"100"}}.Encode(), nil, &inventory, ""); err != nil {
			return err
		}
		if inventory.HasMore {
			return errors.New("upgrade credit inventory exceeds supported bound")
		}
		for _, g := range inventory.Data {
			if g.Metadata["pro_upgrade_id"] == u.ID.String() {
				if grant != "" {
					return errors.New("ambiguous upgrade credits")
				}
				grant = g.ID
			}
		}
		if grant == "" {
			if u.GrantAttempt != nil && h.nowUTC().Sub(*u.GrantAttempt) >= 23*time.Hour {
				return errors.New("upgrade credit request is outside safe replay retention; reconcile provider inventory")
			}
			if err := conn.QueryRow(ctx, `UPDATE billing_pro_upgrade SET grant_attempted_at=COALESCE(grant_attempted_at,clock_timestamp()) WHERE id=$1 RETURNING grant_attempted_at`, u.ID).Scan(&u.GrantAttempt); err != nil {
				return err
			}
			form := url.Values{"customer": {u.Customer}, "category": {"paid"}, "name": {"Prorated Pro usage credit"}, "amount[type]": {"monetary"}, "amount[monetary][currency]": {"usd"}, "amount[monetary][value]": {strconv.FormatInt(credit, 10)}, "priority": {"50"}, "applicability_config[scope][price_type]": {"metered"}, "metadata[pro_upgrade_id]": {u.ID.String()}}
			if expires != 0 {
				form.Set("name", "Pro monthly usage credit")
				form.Set("expires_at", strconv.FormatInt(expires, 10))
			}
			var created entitlementGrant
			if err := c.doForm(ctx, http.MethodPost, "/v1/billing/credit_grants", form, &created, "pro-upgrade-credit:"+u.ID.String()); err != nil {
				return err
			}
			grant = created.ID
		}
	}
	g, err := c.retrieveEntitlementGrant(ctx, grant)
	if err != nil {
		return err
	}
	if g.ID == "" || g.Customer != u.Customer || g.Category != "paid" || g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value != credit || g.ExpiresAt != expires || g.VoidedAt != 0 || g.Priority != 50 || g.Applicability.Scope.PriceType != "metered" || len(g.Applicability.Scope.Prices) != 0 || g.Metadata["pro_upgrade_id"] != u.ID.String() || g.EffectiveAt > h.nowUTC().Unix() {
		return errors.New("upgrade credit differs from accepted paid terms")
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO billing_provider_credit(customer_id,grant_id,evidence,effective_at,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(customer_id,grant_id) DO UPDATE SET evidence=EXCLUDED.evidence,observed_at=clock_timestamp()`, u.Customer, g.ID, raw, g.EffectiveAt, expires); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_pro_upgrade SET grant_id=$2,state='credited' WHERE id=$1`, u.ID, g.ID); err != nil {
		return err
	}
	u.Grant = &g.ID
	return tx.Commit(ctx)
}

func (h *Handlers) commitProUpgrade(ctx context.Context, conn *pgxpool.Conn, u *proUpgrade, sub invoiceSubscription, offer proOffer, method string, c *stripeHTTPClient, token uuid.UUID) error {
	hasBase := false
	for _, item := range sub.Items.Data {
		if item.Price.ID == offer.Price {
			hasBase = true
		}
	}
	matches := hasBase && sub.DefaultPaymentMethod == method && sub.PauseCollection != nil && sub.PauseCollection.Behavior == "keep_as_draft" && sub.PauseCollection.ResumesAt == 0 && len(sub.Discounts) == 0
	if !matches {
		if hasBase {
			return errors.New("upgrade base exists with unexpected payment or collection terms")
		}
		if u.RecurringAttempt != nil && h.nowUTC().Sub(*u.RecurringAttempt) >= 23*time.Hour {
			return errors.New("upgrade recurring mutation replay expired")
		}
		if err := conn.QueryRow(ctx, `UPDATE billing_pro_upgrade SET recurring_attempted_at=COALESCE(recurring_attempted_at,clock_timestamp()) WHERE id=$1 RETURNING recurring_attempted_at`, u.ID).Scan(&u.RecurringAttempt); err != nil {
			return err
		}
		form := url.Values{"default_payment_method": {method}, "proration_behavior": {"none"}, "billing_cycle_anchor": {"unchanged"}, "pause_collection[behavior]": {"keep_as_draft"}, "items[0][price]": {offer.Price}, "items[0][quantity]": {"1"}, "items[0][metadata][pro_upgrade_id]": {u.ID.String()}}
		var changed invoiceSubscription
		if err := c.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub.ID), form, &changed, "pro-upgrade-recurring:"+u.ID.String()); err != nil {
			return err
		}
	}
	sub, err := c.invoiceSubscription(ctx, sub.ID)
	if err != nil {
		return err
	}
	for _, item := range sub.Items.Data {
		if item.Price.ID == offer.Price {
			if item.Created <= 0 || item.Metadata["pro_upgrade_id"] != u.ID.String() {
				return errors.New("upgrade recurring item ownership or creation time is missing")
			}
			installed := time.Unix(item.Created, 0).UTC()
			if err = conn.QueryRow(ctx, `UPDATE billing_pro_upgrade SET base_created_at=COALESCE(base_created_at,$2) WHERE id=$1 AND (base_created_at IS NULL OR base_created_at=$2) RETURNING base_created_at`, u.ID, installed).Scan(&u.BaseCreated); err != nil {
				return err
			}
		}
	}
	resources, err := (invoiceBase{Price: offer.Price, Amount: offer.Amount, Months: 1}).stripSubscription(sub)
	if err != nil {
		return err
	}
	if sub.DefaultPaymentMethod != method || len(sub.Discounts) != 0 || sub.PauseCollection == nil || sub.PauseCollection.Behavior != "keep_as_draft" || sub.PauseCollection.ResumesAt != 0 {
		return errors.New("upgrade recurring subscription has incompatible collection terms")
	}
	if err = invoiceCalendarCompatible(u.Anchor, resources, ""); err != nil {
		var rounding string
		if e := conn.QueryRow(ctx, `SELECT COALESCE((SELECT adjustment_price_id FROM billing_invoice_account WHERE team_id=$1),'')`, u.Team).Scan(&rounding); e != nil {
			return e
		}
		if err = invoiceCalendarCompatible(u.Anchor, resources, rounding); err != nil {
			return err
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: u.Customer, Token: token}); err != nil {
		return err
	}
	a, err := q.LockTeamBillingAccount(ctx, u.Team)
	if err != nil {
		return err
	}
	if derefString(a.StripeCustomerID) != u.Customer || derefString(a.StripeSubscriptionID) != sub.ID || !a.CommercialBillingAnchor.Valid || !a.CommercialBillingAnchor.Time.Equal(u.Anchor) {
		return errors.New("upgrade billing association changed")
	}
	var accepted StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(u.Payload, &accepted); err != nil {
		return err
	}
	if accepted.FirstPaidProCycle {
		if err = validateFirstProCycleProviderCalendar(u.ID, u.Anchor, sub); err != nil {
			return err
		}
		if err = retireFirstProCycleReportingPeriods(ctx, tx, *u); err != nil {
			return err
		}
	}
	offer.PredecessorKnown = true
	offer.InitialAssignment = u.InitialAssignment
	contract, err := q.GetCurrentCommercialContract(ctx, u.Team)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		contract, err = q.CreateCommercialContract(ctx, db.CreateCommercialContractParams{TeamID: u.Team, OfferKey: u.Offer, StartsAt: u.End, CustomerID: u.Customer, SubscriptionID: sub.ID, BasePriceID: offer.Price, ChargeAmountCents: offer.Amount, ChargeIntervalMonths: 1, EntitlementKind: "metered_usage", EntitlementAmountCents: offer.Credit, EntitlementCadence: "monthly", EntitlementAnchor: u.Anchor})
		if err != nil {
			return err
		}
		if offer.Limits != nil {
			if err = freezeContractLimits(ctx, tx, contract.ID, *offer.Limits); err != nil {
				return err
			}
		}
	}
	if contract.CustomerID != u.Customer || contract.SubscriptionID != sub.ID || contract.BasePriceID != offer.Price || !contract.StartsAt.Equal(u.End) {
		return errors.New("upgrade contract differs")
	}
	if err = assignCheckoutPlan(ctx, tx, proChoice{Team: u.Team, Actor: u.Actor, Offer: u.Offer}, offer, contract.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_pro_upgrade SET contract_id=$2 WHERE id=$1 AND (grant_id IS NOT NULL OR bridge_credit_cents=0) AND payment_evidence IS NOT NULL`, u.ID, contract.ID); err != nil {
		return err
	}
	u.Contract = &contract.ID
	return tx.Commit(ctx)
}

func (h *Handlers) reconcileProUpgradeRenewals(ctx context.Context, u proUpgrade, o proOffer, c *stripeHTTPClient) (string, error) {
	if u.Subscription == nil || u.Contract == nil {
		return "", errors.New("upgrade renewal association is missing")
	}
	ids, _, err := c.proInvoices(ctx, u.Customer, *u.Subscription, "")
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		receipt, found, err := c.verifyProInvoice(ctx, id, o, u.Customer, *u.Subscription)
		if err != nil {
			return "", err
		}
		if !found || receipt.Start < u.End.Unix() {
			continue
		}
		tx, err := h.Pool.Begin(ctx)
		if err != nil {
			return "", err
		}
		q := h.DB.WithTx(tx)
		payment, err := q.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: u.Team, ContractID: *u.Contract, InvoiceID: id, PaymentReference: receipt.Reference, CustomerID: u.Customer, SubscriptionID: u.Subscription, BasePriceID: o.Price, ServicePeriodStart: time.Unix(receipt.Start, 0), ServicePeriodEnd: time.Unix(receipt.End, 0), BaseAmountPaidCents: o.Amount, InvoiceAmountPaidCents: receipt.Invoice.AmountPaid, Currency: "usd", PaidAt: time.Unix(receipt.Invoice.StatusTransitions.PaidAt, 0), Evidence: receipt.Raw})
		_ = payment
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = q.GetCommercialBasePayment(ctx, db.GetCommercialBasePaymentParams{TeamID: u.Team, ContractID: *u.Contract, InvoiceID: id})
		}
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO billing_pro_payment_verification(invoice_id,review_required,evidence) VALUES($1,false,$2) ON CONFLICT(invoice_id) DO UPDATE SET review_required=false,evidence=EXCLUDED.evidence,observed_at=clock_timestamp()`, id, receipt.Raw)
		}
		if err == nil {
			contract, e := q.GetCurrentCommercialContract(ctx, u.Team)
			err = e
			if err == nil && contract.ID == *u.Contract && contract.Status == "pending" && receipt.Start <= h.nowUTC().Unix() && receipt.End > h.nowUTC().Unix() {
				_, err = q.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: u.Team, ContractID: *u.Contract, ExpectedRevision: contract.Revision})
			}
		}
		if err != nil {
			tx.Rollback(ctx)
			return "", fmt.Errorf("record upgrade renewal: %w", err)
		}
		if err = tx.Commit(ctx); err != nil {
			return "", err
		}
	}
	return "active", nil
}
