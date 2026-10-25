package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

var errProResourcesPending = errors.New("paid purchase is awaiting monthly usage attachment")

var errProEnrollmentPending = errors.New("paid purchase is awaiting invoice enrollment")

type proPaidInvoice struct {
	Metadata map[string]string `json:"metadata"`
	StripeInvoiceAmounts
	AmountPaid        int64 `json:"amount_paid"`
	AmountRemaining   int64 `json:"amount_remaining"`
	PaidOutOfBand     bool  `json:"paid_out_of_band"`
	StatusTransitions struct {
		PaidAt int64 `json:"paid_at"`
	} `json:"status_transitions"`
}
type proPaymentEvidence struct {
	Invoice    proPaidInvoice
	Reference  string
	Start, End int64
	Raw        []byte
	Discount   *proInvoiceDiscount
}

// proInvoiceDiscount is a promotion code discount on a Pro checkout invoice.
type proInvoiceDiscount struct {
	ID              string  `json:"id"`
	PromotionCode   string  `json:"promotion_code"`
	Coupon          string  `json:"coupon"`
	Duration        string  `json:"duration"`
	AmountOffCents  *int64  `json:"amount_off_cents,omitempty"`
	PercentOff      float64 `json:"percent_off,omitempty"`
	DiscountedCents int64   `json:"discounted_cents"`
}

func (c *stripeHTTPClient) verifyProInvoice(ctx context.Context, id string, o proOffer, customer, subscription string) (proPaymentEvidence, bool, error) {
	var ev proPaymentEvidence
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(id), nil, &ev.Invoice, ""); err != nil {
		return ev, false, err
	}
	inv := ev.Invoice
	if inv.ID != id || inv.Customer != customer || inv.Parent.SubscriptionDetails == nil || inv.Parent.SubscriptionDetails.Subscription != subscription || inv.Lines.HasMore {
		return ev, false, &proPaymentReviewError{reason: "base invoice ownership or line evidence is incomplete"}
	}
	// A pricing v2 purchase may carry one promotion code on its checkout
	// invoice. Every later invoice is verified exactly as before.
	checkout := (o.PricingV2 || o.Promotion != nil) && inv.BillingReason == "subscription_create"
	var promotion string
	if checkout {
		ids := []string{}
		for _, d := range inv.Discounts {
			ids = append(ids, d.ID)
		}
		for _, d := range inv.DiscountAmounts {
			ids = append(ids, d.Discount)
		}
		for _, id := range ids {
			if id == "" || (promotion != "" && id != promotion) || (o.Promotion != nil && id != o.Promotion.ID) {
				return ev, false, &proPaymentReviewError{reason: "checkout invoice needs exactly one promotion code discount"}
			}
			promotion = id
		}
	}
	var found bool
	var discount int64
	for _, line := range inv.Lines.Data {
		if line.Pricing.PriceDetails == nil || line.Pricing.PriceDetails.Price != o.Price {
			continue
		}
		var credited bool
		discount, credited = checkoutLineDiscount(line, promotion)
		if found || line.Parent.SubscriptionItemDetails == nil || line.Parent.SubscriptionItemDetails.Subscription != subscription || line.Parent.SubscriptionItemDetails.Proration || line.Amount != o.Amount || line.Currency != "usd" || line.Quantity != 1 || credited || line.Period.End <= line.Period.Start {
			return ev, false, &proPaymentReviewError{reason: "base invoice line differs from expected offer"}
		}
		found = true
		ev.Start = line.Period.Start
		ev.End = line.Period.End
	}
	if inv.Status != "paid" {
		return ev, false, &proPaymentReviewError{reason: "paid invoice listing changed during verification"}
	}
	if !found {
		return ev, false, nil
	}
	if checkout {
		var invoiceDiscount int64
		for _, d := range inv.DiscountAmounts {
			invoiceDiscount += d.Amount
		}
		if invoiceDiscount != discount {
			return ev, false, &proPaymentReviewError{reason: "invoice discount is not limited to the licensed fee"}
		}
	}
	if inv.Currency != "usd" || inv.PaidOutOfBand || inv.AmountRemaining != 0 || inv.AmountPaid < o.Amount-discount || inv.AmountPaid != inv.AmountDue || inv.EndingBalance == nil || inv.StatusTransitions.PaidAt <= 0 || len(inv.Taxes) > 0 {
		return ev, false, &proPaymentReviewError{reason: "base invoice lacks supported cash settlement"}
	}
	switch {
	case promotion != "" && o.Promotion == nil:
		// Coupon details are read once, before the contract records them; a
		// coupon deleted later must not invalidate a paid invoice.
		d, err := c.proInvoiceDiscount(ctx, id, discount)
		if err != nil {
			return ev, false, err
		}
		if d.ID != promotion {
			return ev, false, &proPaymentReviewError{reason: "checkout invoice discount evidence changed"}
		}
		ev.Discount = &d
	case promotion != "":
		d := *o.Promotion
		d.DiscountedCents = discount
		ev.Discount = &d
	}
	if err := c.verifyProCreditNotes(ctx, inv, o.Price); err != nil {
		return ev, false, err
	}
	return c.verifyProInvoiceCash(ctx, ev)
}

func (c *stripeHTTPClient) verifyProInvoiceCash(ctx context.Context, ev proPaymentEvidence) (proPaymentEvidence, bool, error) {
	inv := ev.Invoice
	id, customer := inv.ID, inv.Customer
	cashTotal := new(big.Int).Add(big.NewInt(inv.Total), big.NewInt(inv.StartingBalance))
	cashTotal.Sub(cashTotal, big.NewInt(*inv.EndingBalance))
	if cashTotal.Cmp(big.NewInt(inv.AmountDue)) != 0 {
		return ev, false, &proPaymentReviewError{reason: "invoice cash balance does not reconcile"}
	}
	var payments struct {
		Data []struct {
			ID, Invoice, Status, Currency string
			AmountPaid                    int64 `json:"amount_paid"`
			Payment                       struct {
				Type   string `json:"type"`
				Intent string `json:"payment_intent"`
			} `json:"payment"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	}
	query := url.Values{"invoice": {id}, "status": {"paid"}, "limit": {"100"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoice_payments?"+query.Encode(), nil, &payments, ""); err != nil {
		return ev, false, err
	}
	if payments.HasMore {
		return ev, false, &proPaymentReviewError{reason: "invoice payment evidence exceeds supported bound"}
	}
	var paid int64
	seen := map[string]bool{}
	var references []string
	var intents []any
	var charges []json.RawMessage
	for _, p := range payments.Data {
		if p.Invoice != id || p.Status != "paid" || p.Currency != "usd" || p.AmountPaid <= 0 || p.Payment.Type != "payment_intent" || p.Payment.Intent == "" || seen[p.Payment.Intent] {
			return ev, false, &proPaymentReviewError{reason: "unsupported invoice cash payment"}
		}
		var intent struct {
			ID, Status, Customer, Currency string
			AmountReceived                 int64  `json:"amount_received"`
			LatestCharge                   string `json:"latest_charge"`
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/payment_intents/"+url.PathEscape(p.Payment.Intent), nil, &intent, ""); err != nil {
			return ev, false, err
		}
		if intent.ID != p.Payment.Intent || intent.Status != "succeeded" || intent.Customer != customer || intent.Currency != "usd" || intent.AmountReceived < p.AmountPaid || p.AmountPaid > inv.AmountPaid-paid {
			return ev, false, &proPaymentReviewError{reason: "invoice payment intent does not prove paid amount"}
		}
		charge, err := c.verifyProCharge(ctx, intent.LatestCharge, intent.ID, customer, p.AmountPaid)
		if err != nil {
			return ev, false, err
		}
		charges = append(charges, charge)
		seen[intent.ID] = true
		paid += p.AmountPaid
		references = append(references, intent.ID)
		intents = append(intents, intent)
	}
	if paid != inv.AmountPaid {
		return ev, false, &proPaymentReviewError{reason: "invoice cash payments do not cover its paid total"}
	}
	ev.Reference = fmt.Sprint(references)
	if len(references) == 0 {
		ev.Reference = "discounted:" + id
	}
	ev.Raw, _ = json.Marshal(struct {
		Invoice  proPaidInvoice      `json:"invoice"`
		Payments any                 `json:"payments"`
		Intents  any                 `json:"payment_intents"`
		Charges  []json.RawMessage   `json:"charges"`
		Discount *proInvoiceDiscount `json:"discount,omitempty"`
	}{inv, payments, intents, charges, ev.Discount})
	return ev, true, nil
}

// checkoutLineDiscount returns the promotion's reduction of a licensed fee
// line on a checkout invoice, and whether the line carries anything else that
// reduces the fee. Without a promotion this is exactly baseLineHasCredits.
func checkoutLineDiscount(line StripeInvoiceAmountLine, promotion string) (int64, bool) {
	if promotion == "" {
		return 0, baseLineHasCredits(line)
	}
	for _, raw := range line.Discounts {
		var id string
		if json.Unmarshal(raw, &id) != nil {
			var object struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(raw, &object) != nil {
				return 0, true
			}
			id = object.ID
		}
		if id != promotion {
			return 0, true
		}
	}
	var discount int64
	for _, credit := range line.PretaxCredits {
		switch {
		case credit.Type == "discount" && credit.Amount == 0:
		case credit.Type == "discount" && credit.Discount == promotion && credit.Amount > 0:
			discount += credit.Amount
		default:
			return 0, true
		}
	}
	return discount, discount > line.Amount
}

// proInvoiceDiscount reads the single promotion code discount that reduced a
// checkout invoice by discounted cents.
func (c *stripeHTTPClient) proInvoiceDiscount(ctx context.Context, invoice string, discounted int64) (proInvoiceDiscount, error) {
	var expanded struct {
		ID        string `json:"id"`
		Discounts []struct {
			ID            string `json:"id"`
			PromotionCode string `json:"promotion_code"`
			Source        struct {
				Coupon struct {
					ID         string   `json:"id"`
					Duration   string   `json:"duration"`
					AmountOff  *int64   `json:"amount_off"`
					PercentOff *float64 `json:"percent_off"`
					Currency   string   `json:"currency"`
				} `json:"coupon"`
			} `json:"source"`
		} `json:"discounts"`
	}
	q := url.Values{"expand[]": {"discounts.source.coupon"}}
	if err := c.doForm(ctx, http.MethodGet, "/v1/invoices/"+url.PathEscape(invoice)+"?"+q.Encode(), nil, &expanded, ""); err != nil {
		return proInvoiceDiscount{}, err
	}
	if expanded.ID != invoice || len(expanded.Discounts) != 1 {
		return proInvoiceDiscount{}, &proPaymentReviewError{reason: "checkout invoice needs exactly one promotion code discount"}
	}
	d := expanded.Discounts[0]
	coupon := d.Source.Coupon
	if d.ID == "" || d.PromotionCode == "" || coupon.ID == "" || (coupon.AmountOff == nil) == (coupon.PercentOff == nil) || (coupon.AmountOff != nil && coupon.Currency != "usd") {
		return proInvoiceDiscount{}, &proPaymentReviewError{reason: "checkout invoice discount is not a supported promotion code"}
	}
	out := proInvoiceDiscount{ID: d.ID, PromotionCode: d.PromotionCode, Coupon: coupon.ID, Duration: coupon.Duration, AmountOffCents: coupon.AmountOff, DiscountedCents: discounted}
	if coupon.PercentOff != nil {
		out.PercentOff = *coupon.PercentOff
	}
	return out, nil
}

// Each pass revisits the newest page and advances one historical page. This
// catches late payments without rescanning the customer's entire invoice history.
func (c *stripeHTTPClient) proInvoices(ctx context.Context, customer, sub, cursor string) ([]string, string, error) {
	var ids []string
	next := ""
	cursors := []string{""}
	if cursor != "" {
		cursors = append(cursors, cursor)
	}
	seen := map[string]bool{}
	for _, pageCursor := range cursors {
		var list struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			HasMore bool `json:"has_more"`
		}
		query := url.Values{"customer": {customer}, "subscription": {sub}, "limit": {"10"}, "status": {"paid"}}
		if pageCursor != "" {
			query.Set("starting_after", pageCursor)
		}
		if err := c.doForm(ctx, http.MethodGet, "/v1/invoices?"+query.Encode(), nil, &list, ""); err != nil {
			return nil, "", err
		}
		for _, i := range list.Data {
			if !seen[i.ID] {
				ids = append(ids, i.ID)
				seen[i.ID] = true
			}
		}
		next = ""
		if list.HasMore {
			if len(list.Data) == 0 || list.Data[len(list.Data)-1].ID == pageCursor {
				return nil, "", errors.New("invoice pagination did not advance")
			}
			next = list.Data[len(list.Data)-1].ID
		}
	}
	return ids, next, nil
}

func (h *Handlers) persistProPayments(ctx context.Context, choice proChoice, sub invoiceSubscription, receipts []proPaymentEvidence, terminalClosed, resourcesReady bool) error {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if _, err = q.LockStripeWebhookProcessingLease(ctx, db.LockStripeWebhookProcessingLeaseParams{CustomerID: sub.Customer, Token: choice.LeaseToken}); err != nil {
		return err
	}
	a, err := q.LockTeamBillingAccount(ctx, choice.Team)
	if err != nil {
		return err
	}
	current, err := scanProChoice(tx.QueryRow(ctx, `SELECT `+proChoiceColumns+` FROM billing_signup_choice WHERE team_id=$1 FOR UPDATE`, choice.Team))
	if err != nil {
		return err
	}
	if !current.Generation.Equal(choice.Generation) || current.Offer != choice.Offer || derefString(a.StripeCustomerID) != sub.Customer || (current.Subscription != nil && *current.Subscription != sub.ID) {
		return errors.New("Pro association changed during verification")
	}
	offer, err := choice.frozenOffer()
	if err != nil {
		return err
	}
	var start, end int64
	if resourcesReady {
		start, end, err = proMeteredPeriod(sub, offer)
	} else {
		_, err = (invoiceBase{Price: offer.Price, Amount: offer.Amount, Months: offer.Months}).stripSubscription(sub)
	}
	if err != nil {
		return err
	}
	// A subscription association alone must not create a commercial contract.
	if len(receipts) == 0 {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1)`, choice.Team).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			_, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET subscription_id=$2,revision=revision+1 WHERE team_id=$1`, choice.Team, sub.ID)
			if err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
	}
	anchor := sub.StartDate
	if anchor <= 0 {
		return errors.New("subscription start is missing")
	}
	if a.StripeSubscriptionID != nil && *a.StripeSubscriptionID != sub.ID {
		return errors.New("existing billing subscription conflicts with Pro")
	}
	if a.CommercialBillingAnchor.Valid && a.CommercialBillingAnchor.Time.Unix() != anchor {
		return errors.New("Pro anniversary changed")
	}
	var frozenParams StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(choice.Payload, &frozenParams); err != nil {
		return err
	}
	releaseValidated := false
	if frozenParams.ReleaseID != nil {
		var currentContract bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND status<>'ended')`, choice.Team).Scan(&currentContract); err != nil {
			return err
		}
		if !currentContract {
			if _, err = tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, choice.Team); err != nil {
				return err
			}
			release, e := proReleaseForReentry(ctx, tx, choice.Team, sub.Customer)
			if e != nil {
				return e
			}
			if release == nil || *release != *frozenParams.ReleaseID {
				return errors.New("paid release provenance changed")
			}
			releaseValidated = true
		}
	}
	_, err = tx.Exec(ctx, `UPDATE team_billing_account SET stripe_subscription_id=$2,stripe_subscription_status=$3,current_period_start=CASE WHEN $8 THEN $4 ELSE current_period_start END,current_period_end=CASE WHEN $8 THEN $5 ELSE current_period_end END,commercial_billing_anchor=COALESCE(commercial_billing_anchor,$6),cancel_at_period_end=$7 WHERE team_id=$1`, choice.Team, sub.ID, sub.Status, time.Unix(start, 0), time.Unix(end, 0), time.Unix(anchor, 0), sub.CancelAtPeriodEnd || sub.CancelAt > 0, resourcesReady)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET subscription_id=$2,revision=revision+1 WHERE team_id=$1`, choice.Team, sub.ID)
	if err != nil {
		return err
	}
	contract, err := q.GetCurrentCommercialContract(ctx, choice.Team)
	if errors.Is(err, pgx.ErrNoRows) {
		// Do not create another contract after an ended one for this signup decision.
		var ended bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1)`, choice.Team).Scan(&ended)
		if err != nil {
			return err
		}
		if ended && !releaseValidated {
			return tx.Commit(ctx)
		}
		contract, err = q.CreateCommercialContract(ctx, db.CreateCommercialContractParams{TeamID: choice.Team, OfferKey: choice.Offer, StartsAt: time.Unix(anchor, 0), CustomerID: sub.Customer, SubscriptionID: sub.ID, BasePriceID: choice.Price, ChargeAmountCents: offer.Amount, ChargeIntervalMonths: offer.Months, EntitlementKind: "metered_usage", EntitlementAmountCents: offer.Credit, EntitlementCadence: "monthly", EntitlementAnchor: time.Unix(anchor, 0)})
		if err == nil && offer.Limits != nil {
			err = freezeContractLimits(ctx, tx, contract.ID, *offer.Limits)
		}
	}
	if err != nil {
		return err
	}
	if contract.SubscriptionID != sub.ID || contract.BasePriceID != choice.Price || contract.OfferKey != choice.Offer {
		return errors.New("Pro contract differs from verified subscription")
	}
	var verifiedAt time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&verifiedAt); err != nil {
		return err
	}
	for _, receipt := range receipts {
		if err = recordPaymentPromotion(ctx, tx, choice.Team, contract.ID, receipt); err != nil {
			return err
		}
		_, err = q.RecordCommercialBasePayment(ctx, db.RecordCommercialBasePaymentParams{TeamID: choice.Team, ContractID: contract.ID, InvoiceID: receipt.Invoice.ID, PaymentReference: receipt.Reference, CustomerID: sub.Customer, SubscriptionID: &sub.ID, BasePriceID: choice.Price, ServicePeriodStart: time.Unix(receipt.Start, 0), ServicePeriodEnd: time.Unix(receipt.End, 0), BaseAmountPaidCents: offer.Amount, InvoiceAmountPaidCents: receipt.Invoice.AmountPaid, InvoiceAmountRemainingCents: 0, Currency: "usd", PaidAt: time.Unix(receipt.Invoice.StatusTransitions.PaidAt, 0), VerifiedAt: verifiedAt, Evidence: receipt.Raw})
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = q.GetCommercialBasePayment(ctx, db.GetCommercialBasePaymentParams{TeamID: choice.Team, ContractID: contract.ID, InvoiceID: receipt.Invoice.ID})
		}
		if err != nil {
			return err
		}
	}
	var covered, unexpired bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_contract_payment WHERE contract_id=$1 AND service_period_start<=clock_timestamp() AND service_period_end>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM billing_pro_payment_verification v WHERE v.invoice_id=billing_contract_payment.invoice_id AND v.review_required)),EXISTS(SELECT 1 FROM billing_contract_payment WHERE contract_id=$1 AND service_period_end>clock_timestamp())`, contract.ID).Scan(&covered, &unexpired)
	if err != nil {
		return err
	}
	terminal := sub.Status == "canceled" || sub.Status == "incomplete_expired"
	if sub.Status == "past_due" && contract.Status == "pending" {
		recoveryErr := errors.New("paid subscription is past due; waiting for active invoice enrollment")
		if _, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET last_error=$2,next_check_at=clock_timestamp()+interval '1 hour' WHERE team_id=$1`, choice.Team, recoveryErr.Error()); err != nil {
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		return recoveryErr
	}
	if terminal && contract.Status == "pending" {
		// Canceled subscriptions cannot enroll or bill new usage. Retain the paid
		// evidence and purchase fence without claiming usable Pro activation.
		recoveryErr := errors.New("paid subscription terminated before activation; billing recovery requires support")
		if _, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET last_error=$2,next_check_at=clock_timestamp()+interval '1 hour' WHERE team_id=$1`, choice.Team, recoveryErr.Error()); err != nil {
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		return recoveryErr
	}
	if !resourcesReady {
		if _, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET last_error=$2,next_check_at=clock_timestamp()+interval '2 minutes' WHERE team_id=$1`, choice.Team, errProResourcesPending.Error()); err != nil {
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
		return errProResourcesPending
	}
	if terminal && !unexpired && terminalClosed {
		_, err = q.EndCommercialContract(ctx, db.EndCommercialContractParams{TeamID: choice.Team, ContractID: contract.ID, ExpectedRevision: contract.Revision})
		if err != nil {
			return err
		}
	} else if covered && (sub.Status == "active" || sub.Status == "past_due" || terminal) {
		if contract.Status == "pending" {
			// Historical receipts preserve payment evidence, but first activation
			// requires coverage verified by this recovery pass.
			freshCoverage := false
			for _, receipt := range receipts {
				if receipt.Start <= verifiedAt.Unix() && receipt.End > verifiedAt.Unix() {
					freshCoverage = true
				}
			}
			if !freshCoverage {
				if err = tx.Commit(ctx); err != nil {
					return err
				}
				return errors.New("paid purchase is awaiting current payment verification")
			}
			// Enrollment must commit its provider hold and rounding item before
			// activation can end the trial or authorize paid entitlements.
			var roundingPrice string
			if err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT adjustment_price_id FROM billing_invoice_account WHERE team_id=$1 AND customer_id=$2 AND subscription_id=$3),'')`, choice.Team, sub.Customer, sub.ID).Scan(&roundingPrice); err != nil {
				return err
			}
			roundingItems := 0
			for _, item := range sub.Items.Data {
				if roundingPrice != "" && item.Price.ID == roundingPrice {
					roundingItems++
				}
			}
			if roundingItems != 1 || sub.PauseCollection == nil || sub.PauseCollection.Behavior != "keep_as_draft" || sub.PauseCollection.ResumesAt != 0 {
				if _, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET last_error=$2,next_check_at=clock_timestamp()+interval '2 minutes' WHERE team_id=$1`, choice.Team, errProEnrollmentPending.Error()); err != nil {
					return err
				}
				if err = tx.Commit(ctx); err != nil {
					return err
				}
				return errProEnrollmentPending
			}
			contract, err = q.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: choice.Team, ContractID: contract.ID, ExpectedRevision: contract.Revision})
			if err != nil {
				return err
			}
			if offer.PricingV2 {
				if err = assignCheckoutPlan(ctx, tx, choice, offer, contract.ID); err != nil {
					return err
				}
			}
		}
		// This shared SQL operation ends the trial without requesting a promotion.
		if err = q.ActivateTeamBilling(ctx, db.ActivateTeamBillingParams{TeamID: choice.Team, UserID: pgtype.UUID{}, StripeGrantID: ""}); err != nil {
			return err
		}
		if terminal {
			// An immediately canceled subscription can still have a verified paid term.
			if _, err = tx.Exec(ctx, `UPDATE team_billing_account SET trial_ended_at=COALESCE(trial_ended_at,clock_timestamp()),updated_at=clock_timestamp() WHERE team_id=$1`, choice.Team); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE team_credit_grant SET remaining_usd=0,updated_at=clock_timestamp() WHERE team_id=$1 AND reason='signup trial credit'`, choice.Team); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE billing_signup_choice SET state='committed',revision=revision+1 WHERE team_id=$1`, choice.Team)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func proMeteredPeriod(sub invoiceSubscription, offer proOffer) (int64, int64, error) {
	if sub.BillingMode.Type != "flexible" || sub.AutomaticTax.Enabled || (len(sub.Discounts) != 0 && !offer.PricingV2) || sub.Items.HasMore {
		return 0, 0, errors.New("unsupported Pro subscription configuration")
	}
	var start, end int64
	var base bool
	seen := map[string]bool{}
	for _, item := range sub.Items.Data {
		if seen[item.Price.ID] {
			return 0, 0, errors.New("duplicate subscription price")
		}
		seen[item.Price.ID] = true
		if item.Price.ID == offer.Price {
			interval := "month"
			if offer.Months == 12 {
				interval = "year"
			}
			if base || item.Price.BillingScheme != "per_unit" || item.Price.TransformQuantity != nil || item.Quantity != 1 || item.Price.Recurring.UsageType != "licensed" || item.Price.Recurring.Interval != interval || item.Price.Recurring.IntervalCount != 1 || item.Price.UnitAmountDecimal != fmt.Sprint(offer.Amount) || item.Price.Currency != "usd" {
				return 0, 0, errors.New("Pro base item mismatch")
			}
			base = true
			continue
		}
		if item.Price.Recurring.UsageType != "metered" || item.Price.Recurring.Interval != "month" || item.Price.Recurring.IntervalCount != 1 || item.Start <= 0 || item.End <= item.Start {
			return 0, 0, errors.New("Pro metered period is invalid")
		}
		if start != 0 && (start != item.Start || end != item.End) {
			return 0, 0, errors.New("Pro usage calendars differ")
		}
		start, end = item.Start, item.End
	}
	if !base || start == 0 {
		return 0, 0, errors.New("Pro subscription is missing base or usage items")
	}
	return start, end, nil
}

func assignCheckoutPlan(ctx context.Context, tx pgx.Tx, choice proChoice, offer proOffer, contract uuid.UUID) error {
	if _, err := tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, choice.Team); err != nil {
		return err
	}
	key := "checkout:" + contract.String()
	prior, err := scanTeamPlan(tx.QueryRow(ctx, `SELECT `+teamPlanColumns+` FROM team_plan_assignment WHERE team_id=$1 AND idempotency_key=$2`, choice.Team, key))
	if err == nil {
		if prior.Source != planSourceCheckout || prior.ContractID == nil || *prior.ContractID != contract || prior.PlanKey != choice.Offer || prior.Terms.VersionID != offer.VersionID {
			return errPlanAssignmentReused
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	current, assigned, err := currentTeamPlan(ctx, tx, choice.Team)
	if err != nil {
		return err
	}
	if offer.PredecessorKnown {
		if (offer.InitialAssignment == nil && assigned) || (offer.InitialAssignment != nil && (!assigned || current.ID != *offer.InitialAssignment)) {
			return errors.New("team plan changed after paid acceptance")
		}
	} else if assigned && !(current.Kind == planKindFree && current.Source == "signup" && !current.EffectiveFrom.After(choice.Generation)) {
		return errors.New("accepted purchase has no matching predecessor")
	}
	if offer.Limits == nil {
		return errors.New("accepted purchase limits are missing")
	}
	terms := planTerms{OfferKey: choice.Offer, DisplayName: offer.Name, FeeCents: offer.Amount, IntervalMonths: offer.Months, MonthlyCreditCents: offer.Credit,
		VersionID: offer.VersionID, Version: offer.Version, PricingVersion: "v2", Family: offer.Family, Kind: "subscription", Grants: offer.Grants, Allowance: offer.Allowance, Matching: offer.Matching, Limits: *offer.Limits}
	_, err = assignTeamPlan(ctx, tx, planAssignment{Team: choice.Team, Terms: terms, Source: planSourceCheckout, Actor: &choice.Actor, Reason: "paid checkout", ContractID: &contract, Key: "checkout:" + contract.String()})
	return err
}

// recordPaymentPromotion records the promotion a contract's checkout invoice
// carried, and how much of its licensed fee the promotion covered. It runs
// before the receipt, whose cash check reads it.
func recordPaymentPromotion(ctx context.Context, tx pgx.Tx, team, contract uuid.UUID, receipt proPaymentEvidence) error {
	d := receipt.Discount
	if d == nil {
		return nil
	}
	if receipt.Invoice.BillingReason != "subscription_create" {
		return errors.New("only a checkout invoice may carry a promotion")
	}
	var percent *float64
	if d.AmountOffCents == nil {
		percent = &d.PercentOff
	}
	tag, err := tx.Exec(ctx, `INSERT INTO billing_contract_promotion(contract_id,team_id,discount_id,promotion_code,coupon_id,coupon_duration,amount_off_cents,percent_off,checkout_invoice_id,discounted_cents) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (contract_id) DO NOTHING`, contract, team, d.ID, d.PromotionCode, d.Coupon, d.Duration, d.AmountOffCents, percent, receipt.Invoice.ID, d.DiscountedCents)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	var same bool
	if err = tx.QueryRow(ctx, `SELECT discount_id=$2 AND checkout_invoice_id=$3 AND discounted_cents=$4 FROM billing_contract_promotion WHERE contract_id=$1`, contract, d.ID, receipt.Invoice.ID, d.DiscountedCents).Scan(&same); err != nil {
		return err
	}
	if !same {
		return errors.New("contract already has a different promotion")
	}
	return nil
}

// contractPromotion returns the promotion recorded for a contract, if any.
func contractPromotion(ctx context.Context, q db.DBTX, contract uuid.UUID) (*proInvoiceDiscount, error) {
	return scanContractPromotion(q.QueryRow(ctx, `SELECT `+contractPromotionColumns+` FROM billing_contract_promotion WHERE contract_id=$1`, contract))
}

// subscriptionPromotion returns the promotion recorded for the newest contract
// on a subscription, for paths that know the subscription but not its contract.
func subscriptionPromotion(ctx context.Context, q db.DBTX, subscription string) (*proInvoiceDiscount, error) {
	return scanContractPromotion(q.QueryRow(ctx, `SELECT `+contractPromotionColumns+` FROM billing_contract_promotion p JOIN billing_commercial_contract c ON c.id=p.contract_id WHERE c.subscription_id=$1 ORDER BY c.created_at DESC LIMIT 1`, subscription))
}

const contractPromotionColumns = `discount_id,promotion_code,coupon_id,coupon_duration,amount_off_cents,percent_off::float8,discounted_cents`

func scanContractPromotion(row pgx.Row) (*proInvoiceDiscount, error) {
	var d proInvoiceDiscount
	var percent *float64
	err := row.Scan(&d.ID, &d.PromotionCode, &d.Coupon, &d.Duration, &d.AmountOffCents, &percent, &d.DiscountedCents)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if percent != nil {
		d.PercentOff = *percent
	}
	return &d, nil
}

// clearProCheckoutDiscount removes the checkout promotion from the
// subscription once the contract has recorded it, so renewals bill the full
// fee and invoice enrollment, which refuses discounted subscriptions, proceeds.
func (h *Handlers) clearProCheckoutDiscount(ctx context.Context, client *stripeHTTPClient, sub invoiceSubscription) (invoiceSubscription, error) {
	if len(sub.Discounts) == 0 {
		return sub, nil
	}
	promotion, err := subscriptionPromotion(ctx, h.Pool, sub.ID)
	if err != nil {
		return sub, err
	}
	if promotion == nil {
		return sub, errors.New("subscription has a discount but no recorded checkout promotion; operator review required if the checkout invoice is already recorded")
	}
	if len(sub.Discounts) != 1 || sub.Discounts[0] != promotion.ID {
		return sub, errors.New("subscription discount differs from the checkout promotion code; operator review required")
	}
	if err = client.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(sub.ID), url.Values{"discounts": {""}, "proration_behavior": {"none"}}, nil, ""); err != nil {
		return sub, err
	}
	return client.invoiceSubscription(ctx, sub.ID)
}
