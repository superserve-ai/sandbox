//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/billing"
)

type proUpgradeProviderFixture struct {
	t                                           *testing.T
	id, method, setupID                         string
	subscription, base, checkout, setupComplete bool
	quoted, baseCreated, recurringStart         int64
	grant                                       map[string]any
	grantCreates                                int
	holdWrites                                  int
	loseHoldResponse                            bool
	invalidCalendar, invalidResource            bool
}

func (f *proProviderFixture) serveUpgrade(w http.ResponseWriter, r *http.Request) bool {
	u := f.upgrade
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	fail := func(reason string) { u.t.Errorf("%s: %s %s", reason, r.Method, r.URL.Path); http.Error(w, reason, 500) }
	invoice := "in_upgrade" + strings.ReplaceAll(f.team.String(), "-", "")
	session := func() map[string]any {
		paid := "unpaid"
		if f.paid {
			paid = "paid"
			if f.discount == u.quoted {
				paid = "no_payment_required"
			}
		}
		var paymentIntent any = "pi_upgrade"
		if f.paid && f.discount == u.quoted {
			paymentIntent = nil
		}
		return map[string]any{"id": f.session, "url": "https://checkout.stripe.com/" + f.session, "mode": "payment", "status": f.status, "customer": f.customer, "client_reference_id": f.team.String(), "payment_status": paid, "currency": "usd", "amount_subtotal": u.quoted, "amount_total": u.quoted - f.discount, "total_details": map[string]any{"amount_discount": f.discount}, "invoice": invoice, "payment_intent": paymentIntent, "metadata": map[string]string{"pro_upgrade_id": u.id}}
	}
	setup := func() map[string]any {
		status := "open"
		if u.setupComplete {
			status = "complete"
		}
		return map[string]any{"id": "cs_setup" + strings.ReplaceAll(f.team.String(), "-", ""), "url": "https://checkout.stripe.com/setup", "mode": "setup", "status": status, "customer": f.customer, "client_reference_id": f.team.String(), "setup_intent": "seti_upgrade", "metadata": map[string]string{"pro_upgrade_id": u.id, "pro_upgrade_setup_id": u.setupID}}
	}
	switch {
	case r.URL.Path == "/v1/billing/credit_balance_summary":
		balance := map[string]any{"monetary": map[string]any{"currency": "usd", "value": u.quoted}}
		write(map[string]any{"balances": []any{map[string]any{"ledger_balance": balance, "available_balance": balance}}})
		return true
	case r.URL.Path == "/v1/invoices" && f.baseStart < u.recurringStart:
		write(map[string]any{"data": []any{}})
		return true
	case r.URL.Path == "/v1/subscriptions":
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			if r.Form.Has("pause_collection[behavior]") {
				fail("pause_collection is update-only")
				return true
			}
			for key := range r.Form {
				if strings.Contains(key, "discount") || strings.Contains(key, "coupon") || strings.Contains(key, "promotion") {
					fail("promotion leaked into recurring subscription")
					return true
				}
			}
			u.id = r.Form.Get("metadata[pro_upgrade_id]")
			if u.id == "" || r.Form.Get("billing_mode[type]") != "flexible" || r.Form.Get("proration_behavior") != "none" {
				fail("invalid upgrade subscription")
				return true
			}
			f.anchor, _ = strconv.ParseInt(r.Form.Get("backdate_start_date"), 10, 64)
			start, end, ok := billing.AnniversaryPeriod(time.Unix(f.anchor, 0), f.handlers.Now())
			if !ok {
				fail("invalid original calendar")
				return true
			}
			f.baseStart, f.baseEnd = start.Unix(), end.Unix()
			u.recurringStart = end.Unix()
			u.subscription = true
			f.held = false
			write(map[string]any{"id": f.sub})
			return true
		}
		data := []any{}
		if u.subscription {
			data = append(data, map[string]any{"id": f.sub, "status": "active", "metadata": map[string]string{"pro_upgrade_id": u.id}})
		}
		write(map[string]any{"data": data})
		return true
	case r.URL.Path == "/v1/subscriptions/"+f.sub:
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			for key := range r.Form {
				if strings.Contains(key, "discount") || strings.Contains(key, "coupon") || strings.Contains(key, "promotion") {
					fail("promotion leaked into recurring subscription update")
					return true
				}
			}
			if r.Form.Get("pause_collection[behavior]") == "keep_as_draft" && r.Form.Get("items[0][price]") == "" {
				if r.Header.Get("Idempotency-Key") != "pro-upgrade-prepare-hold:"+u.id {
					fail("collection hold lost operation identity")
					return true
				}
				u.holdWrites++
				f.held = true
				if u.loseHoldResponse {
					u.loseHoldResponse = false
					http.Error(w, "lost hold response", 500)
					return true
				}
				write(map[string]any{})
				return true
			}
			if r.Form.Get("items[0][price]") != "" {
				if r.Form.Get("items[0][price]") != f.price || r.Form.Get("proration_behavior") != "none" || r.Form.Get("billing_cycle_anchor") != "unchanged" || r.Form.Get("items[0][metadata][pro_upgrade_id]") != u.id {
					fail("upgrade recurring terms changed")
					return true
				}
				u.base = true
				u.baseCreated = f.handlers.Now().Unix()
				u.method = r.Form.Get("default_payment_method")
				f.held = true
				write(map[string]any{})
				return true
			}
			return false
		}
		items := []any{}
		if u.base {
			items = append(items, map[string]any{"id": "si_base", "quantity": 1, "created": u.baseCreated, "metadata": map[string]string{"pro_upgrade_id": u.id}, "price": map[string]any{"id": f.price, "currency": "usd", "unit_amount_decimal": fmt.Sprint(f.amount), "billing_scheme": "per_unit", "recurring": map[string]any{"usage_type": "licensed", "interval": "month", "interval_count": 1}}, "current_period_start": f.baseStart, "current_period_end": f.baseEnd})
		}
		prices := []string{"price_cpu", "price_memory", "price_storage"}
		if f.rounded {
			prices = append(prices, "price_round")
		}
		for _, p := range prices {
			rate := f.resourceRate(p)
			periodStart := f.baseStart
			if u.invalidCalendar {
				periodStart++
			}
			if u.invalidResource {
				rate = "999"
			}
			items = append(items, map[string]any{"id": "si_" + p, "price": map[string]any{"id": p, "active": true, "currency": "usd", "billing_scheme": "per_unit", "unit_amount_decimal": rate, "recurring": map[string]any{"usage_type": "metered", "interval": "month", "interval_count": 1, "meter": f.resourceMeter(p)}}, "current_period_start": periodStart, "current_period_end": f.baseEnd})
		}
		write(map[string]any{"id": f.sub, "customer": f.customer, "status": "active", "default_payment_method": u.method, "start_date": f.anchor, "billing_cycle_anchor": f.anchor, "billing_mode": map[string]any{"type": "flexible"}, "pause_collection": func() any {
			if f.held {
				return map[string]any{"behavior": "keep_as_draft"}
			}
			return nil
		}(), "items": map[string]any{"data": items}, "metadata": map[string]string{"pro_upgrade_id": u.id}})
		return true
	case r.URL.Path == "/v1/checkout/sessions":
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			if r.Form.Get("mode") == "setup" {
				if r.Form.Has("setup_intent_data[usage]") || r.Form.Get("payment_method_types[0]") != "card" || r.Form.Get("metadata[pro_upgrade_id]") != u.id || r.Form.Get("setup_intent_data[metadata][pro_upgrade_id]") != u.id || r.Form.Get("setup_intent_data[metadata][pro_upgrade_setup_id]") != r.Form.Get("metadata[pro_upgrade_setup_id]") {
					fail("invalid Checkout card setup form")
					return true
				}
				u.setupID = r.Form.Get("metadata[pro_upgrade_setup_id]")
				write(setup())
				return true
			}
			if !f.held {
				fail("checkout opened before collection hold")
				return true
			}
			if r.Form.Get("mode") != "payment" || r.Form.Get("invoice_creation[enabled]") != "true" || r.Form.Get("payment_intent_data[setup_future_usage]") != "off_session" || r.Form.Get("subscription_data[billing_mode][type]") != "" {
				fail("upgrade is not one-off payment")
				return true
			}
			u.quoted, _ = strconv.ParseInt(r.Form.Get("line_items[0][price_data][unit_amount]"), 10, 64)
			if u.quoted <= 0 || r.Form.Get("metadata[pro_upgrade_id]") != u.id {
				fail("invalid frozen upgrade amount")
				return true
			}
			f.creates++
			f.keys = append(f.keys, r.Header.Get("Idempotency-Key"))
			f.promotionCodes = r.Form.Get("allow_promotion_codes") == "true"
			u.checkout = true
			if f.failCreate {
				http.Error(w, "lost response", 500)
				return true
			}
			write(session())
			return true
		}
		data := []any{}
		if u.checkout {
			data = append(data, session())
		}
		if u.setupID != "" {
			data = append(data, setup())
		}
		write(map[string]any{"data": data})
		return true
	case r.URL.Path == "/v1/checkout/sessions/"+f.session:
		write(session())
		return true
	case r.URL.Path == "/v1/checkout/sessions/cs_setup"+strings.ReplaceAll(f.team.String(), "-", ""):
		write(setup())
		return true
	case r.URL.Path == "/v1/setup_intents/seti_upgrade":
		write(map[string]any{"id": "seti_upgrade", "customer": f.customer, "status": "succeeded", "usage": "off_session", "payment_method": "pm_upgrade", "metadata": map[string]string{"pro_upgrade_setup_id": u.setupID}})
		return true
	case r.URL.Path == "/v1/invoices/"+invoice:
		write(map[string]any{"id": invoice, "customer": f.customer, "status": "paid", "currency": "usd", "amount_paid": u.quoted - f.discount, "amount_due": u.quoted - f.discount, "amount_remaining": 0, "ending_balance": 0, "status_transitions": map[string]any{"paid_at": time.Now().Unix()}, "lines": map[string]any{"data": []any{map[string]any{"amount": u.quoted, "currency": "usd", "quantity": 1}}}})
		return true
	case r.URL.Path == "/v1/payment_intents/pi_upgrade":
		write(map[string]any{"id": "pi_upgrade", "customer": f.customer, "status": "succeeded", "currency": "usd", "amount_received": u.quoted - f.discount, "latest_charge": "ch_upgrade", "payment_method": "pm_upgrade", "setup_future_usage": "off_session", "metadata": map[string]string{"pro_upgrade_id": u.id}})
		return true
	case r.URL.Path == "/v1/charges/ch_upgrade":
		write(map[string]any{"id": "ch_upgrade", "customer": f.customer, "payment_intent": "pi_upgrade", "currency": "usd", "paid": true, "captured": true, "amount_captured": u.quoted - f.discount, "amount_refunded": f.refund})
		return true
	case r.URL.Path == "/v1/payment_methods/pm_upgrade":
		write(map[string]any{"id": "pm_upgrade", "customer": f.customer, "type": "card"})
		return true
	case r.URL.Path == "/v1/customers/"+f.customer:
		write(map[string]any{"id": f.customer, "invoice_settings": map[string]any{"default_payment_method": u.method}})
		return true
	case r.URL.Path == "/v1/billing/credit_grants":
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			if r.Form.Has("expires_at") || r.Form.Get("amount[monetary][value]") != fmt.Sprint(u.quoted) || r.Form.Get("category") != "paid" || r.Form.Get("applicability_config[scope][price_type]") != "metered" {
				fail("upgrade grant terms changed")
				return true
			}
			u.grantCreates++
			u.grant = map[string]any{"id": "cred_" + strings.ReplaceAll(f.team.String(), "-", ""), "customer": f.customer, "category": "paid", "priority": 50, "amount": map[string]any{"type": "monetary", "monetary": map[string]any{"currency": "usd", "value": u.quoted}}, "effective_at": f.handlers.Now().Unix(), "applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}}, "metadata": map[string]string{"pro_upgrade_id": u.id}}
			write(u.grant)
			return true
		}
		data := []any{}
		if u.grant != nil {
			data = append(data, u.grant)
		}
		write(map[string]any{"data": data})
		return true
	case strings.HasPrefix(r.URL.Path, "/v1/billing/credit_grants/") && u.grant != nil:
		write(u.grant)
		return true
	}
	return false
}
