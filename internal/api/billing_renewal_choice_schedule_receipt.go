package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type renewalScheduleObject struct {
	ID           string `json:"id"`
	Object       string `json:"object"`
	Customer     string `json:"customer"`
	Subscription string `json:"subscription"`
	Live         bool   `json:"livemode"`
	Status       string `json:"status"`
	EndBehavior  string `json:"end_behavior"`
	BillingMode  struct {
		Type string `json:"type"`
	} `json:"billing_mode"`
	RenewalInterval json.RawMessage `json:"renewal_interval"`
	Current         struct {
		Start int64 `json:"start_date"`
		End   int64 `json:"end_date"`
	} `json:"current_phase"`
	Phases   []json.RawMessage `json:"phases"`
	Defaults json.RawMessage   `json:"default_settings"`
	Pauses   []json.RawMessage `json:"pause_schedules"`
}

// Only the supported phase shape is writable. Unknown settings cannot be
// dropped silently by sending a replacement phases array.
func renewalSchedulePhaseForm(raw json.RawMessage, prefix string, collection string) (url.Values, error) {
	var phase map[string]json.RawMessage
	if json.Unmarshal(raw, &phase) != nil {
		return nil, errRenewalConflict
	}
	form := url.Values{}
	for name, value := range phase {
		switch name {
		case "start_date", "end_date":
			var n int64
			if json.Unmarshal(value, &n) != nil || n <= 0 {
				return nil, errRenewalConflict
			}
			form.Set(prefix+"["+name+"]", strconv.FormatInt(n, 10))
		case "collection_method":
			var v string
			if json.Unmarshal(value, &v) != nil || (v != "" && v != "charge_automatically") {
				return nil, errRenewalConflict
			}
			if v != "" {
				collection = v
			}
		case "proration_behavior":
			var v string
			if json.Unmarshal(value, &v) != nil || (v != "none" && v != "create_prorations" && v != "always_invoice") {
				return nil, errRenewalConflict
			}
			form.Set(prefix+"[proration_behavior]", v)
		case "currency":
			if string(value) != `"usd"` {
				return nil, errRenewalConflict
			}
		case "default_payment_method", "description":
			var v string
			if json.Unmarshal(value, &v) != nil {
				return nil, errRenewalConflict
			}
			if v != "" {
				form.Set(prefix+"["+name+"]", v)
			}
		case "items":
			var items []map[string]json.RawMessage
			if json.Unmarshal(value, &items) != nil || len(items) != 1 {
				return nil, errRenewalConflict
			}
			for field, itemValue := range items[0] {
				switch field {
				case "price", "plan":
					var price string
					if json.Unmarshal(itemValue, &price) != nil || !strings.HasPrefix(price, "price_") {
						return nil, errRenewalConflict
					}
					if old := form.Get(prefix + "[items][0][price]"); old != "" && old != price {
						return nil, errRenewalConflict
					}
					form.Set(prefix+"[items][0][price]", price)
				case "quantity":
					if string(itemValue) != "1" {
						return nil, errRenewalConflict
					}
					form.Set(prefix+"[items][0][quantity]", "1")
				case "billing_thresholds", "discounts", "metadata", "tax_rates":
					if !renewalEmptySetting(itemValue) {
						return nil, errRenewalConflict
					}
				default:
					return nil, errRenewalConflict
				}
			}
		case "discounts":
			var discounts []map[string]json.RawMessage
			if json.Unmarshal(value, &discounts) != nil || len(discounts) > 1 {
				return nil, errRenewalConflict
			}
			for i, discount := range discounts {
				found := false
				for kind, rawID := range discount {
					if kind != "coupon" && kind != "promotion_code" && kind != "discount" {
						return nil, errRenewalConflict
					}
					var id string
					if json.Unmarshal(rawID, &id) != nil {
						return nil, errRenewalConflict
					}
					if id != "" {
						if found {
							return nil, errRenewalConflict
						}
						found = true
						form.Set(fmt.Sprintf("%s[discounts][%d][%s]", prefix, i, kind), id)
					}
				}
				if !found {
					return nil, errRenewalConflict
				}
			}
		case "automatic_tax":
			var tax map[string]json.RawMessage
			if json.Unmarshal(value, &tax) != nil {
				return nil, errRenewalConflict
			}
			for field, taxValue := range tax {
				if field == "enabled" && string(taxValue) == "false" {
					continue
				}
				if (field != "disabled_reason" && field != "liability") || !renewalEmptySetting(taxValue) {
					return nil, errRenewalConflict
				}
			}
		case "add_invoice_items", "application_fee_percent", "billing_cycle_anchor", "billing_thresholds", "default_tax_rates", "invoice_settings", "metadata", "on_behalf_of", "transfer_data", "trial_end":
			if !renewalEmptySetting(value) {
				return nil, errRenewalConflict
			}
		default:
			return nil, errRenewalConflict
		}
	}
	if collection != "charge_automatically" || form.Get(prefix+"[start_date]") == "" || form.Get(prefix+"[end_date]") == "" || form.Get(prefix+"[items][0][price]") == "" || form.Get(prefix+"[items][0][quantity]") != "1" {
		return nil, errRenewalConflict
	}
	form.Set(prefix+"[collection_method]", collection)
	return form, nil
}

func renewalEmptySetting(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "null", "[]", "{}":
		return true
	}
	return false
}

func validateRenewalScheduleDefaults(raw json.RawMessage) error {
	var defaults map[string]json.RawMessage
	if json.Unmarshal(raw, &defaults) != nil || string(defaults["collection_method"]) != `"charge_automatically"` {
		return errRenewalConflict
	}
	for name, value := range defaults {
		switch name {
		case "collection_method":
		case "billing_cycle_anchor":
			if string(value) != `"automatic"` {
				return errRenewalConflict
			}
		case "default_payment_method", "default_source", "description":
			var text string
			if json.Unmarshal(value, &text) != nil {
				return errRenewalConflict
			}
		case "automatic_tax":
			var tax map[string]json.RawMessage
			if json.Unmarshal(value, &tax) != nil || string(tax["enabled"]) != "false" {
				return errRenewalConflict
			}
			for field, v := range tax {
				if field == "enabled" {
					continue
				}
				if (field != "disabled_reason" && field != "liability") || !renewalEmptySetting(v) {
					return errRenewalConflict
				}
			}
		case "invoice_settings":
			var settings map[string]json.RawMessage
			if json.Unmarshal(value, &settings) != nil {
				return errRenewalConflict
			}
			for field, v := range settings {
				switch field {
				case "issuer":
					var issuer map[string]string
					if json.Unmarshal(v, &issuer) != nil || len(issuer) != 1 || issuer["type"] != "self" {
						return errRenewalConflict
					}
				case "account_tax_ids", "custom_fields", "days_until_due", "description", "footer":
					if !renewalEmptySetting(v) {
						return errRenewalConflict
					}
				default:
					return errRenewalConflict
				}
			}
		case "application_fee_percent", "billing_thresholds", "on_behalf_of", "transfer_data":
			if !renewalEmptySetting(value) {
				return errRenewalConflict
			}
		default:
			return errRenewalConflict
		}
	}
	return nil
}

// Pure response verification belongs inside the one-POST callback. It must not
// query the database or make another provider request under the dispatch guard.
func verifyRenewalScheduleReceipt(k renewalChoiceKey, op renewalChoiceOperation, request renewalChoiceStepRequest, raw []byte, now time.Time) (renewalChoiceStepProof, error) {
	var result renewalChoiceStepProof
	var schedule renewalScheduleObject
	if !validRenewalKey(k) || !validRenewalBinding(op.Binding, k) || len(op.Steps) == 0 || renewalHash(op.Steps[len(op.Steps)-1].Request) != renewalHash(request) || request.BindingHash != renewalHash(op.Binding) || request.Version != renewalStripeVersion || json.Unmarshal(raw, &schedule) != nil {
		return result, errRenewalConflict
	}
	if !strings.HasPrefix(schedule.ID, "sub_sched_") || strings.ContainsAny(schedule.ID, "/?#") || schedule.Object != "subscription_schedule" || schedule.Customer != op.Binding.Customer || schedule.Subscription != op.Binding.Fee || schedule.Live != op.Binding.Live || schedule.Status != "active" || schedule.BillingMode.Type != "flexible" || (len(schedule.RenewalInterval) != 0 && !renewalEmptySetting(schedule.RenewalInterval)) || schedule.Current.Start != op.Binding.Anchor.Unix() || schedule.Current.End != k.Boundary.Unix() || len(schedule.Pauses) != 0 || !now.Before(k.Boundary) {
		return result, errRenewalPending
	}
	form, err := url.ParseQuery(request.Form)
	if err != nil {
		return result, errRenewalConflict
	}
	if request.Kind == "create_schedule" {
		if request.Schedule != "" || len(form) != 1 || form.Get("from_subscription") != op.Binding.Fee {
			return result, errRenewalConflict
		}
	} else if request.Kind == "update_schedule" {
		if request.Schedule != schedule.ID || schedule.EndBehavior != form.Get("end_behavior") || form.Get("proration_behavior") != "none" || validateRenewalScheduleDefaults(schedule.Defaults) != nil {
			return result, errRenewalConflict
		}
		count := 1
		if op.Request.Choice == "monthly" {
			if !renewalCalendarSupported(op.Request.Choice, op.Binding.Anchor, k.Boundary) {
				return result, errRenewalDisabled
			}
			count = 2
		}
		if len(schedule.Phases) != count {
			return result, errRenewalConflict
		}
		for index, phase := range schedule.Phases {
			prefix := fmt.Sprintf("phases[%d]", index)
			actual, err := renewalSchedulePhaseForm(phase, prefix, "charge_automatically")
			if err != nil {
				return result, err
			}
			want := url.Values{}
			for name, values := range form {
				if strings.HasPrefix(name, prefix+"[") {
					want[name] = values
				}
			}
			if index == 1 {
				if want.Get(prefix+"[duration][interval]") != "month" || want.Get(prefix+"[duration][interval_count]") != "1" {
					return result, errRenewalConflict
				}
				want.Del(prefix + "[duration][interval]")
				want.Del(prefix + "[duration][interval_count]")
				want.Del(prefix + "[discounts]")
				want.Set(prefix+"[end_date]", strconv.FormatInt(annualBoundary(k.Boundary, 1).Unix(), 10))
			}
			if actual.Encode() != want.Encode() {
				return result, errRenewalConflict
			}
		}
	} else {
		return result, errRenewalConflict
	}
	evidence, _ := json.Marshal(map[string]string{"source": "direct_schedule_response", "schedule": schedule.ID, "response_hash": renewalHash(json.RawMessage(raw)), "request_hash": renewalHash(request)})
	result = renewalChoiceStepProof{RequestHash: renewalHash(request), Outcome: "confirmed", Schedule: schedule.ID, BindingHash: renewalHash(op.Binding), VerifiedAt: now.UTC(), Evidence: evidence}
	if request.Kind == "update_schedule" {
		result.Choice = &renewalChoiceProof{Operation: op.ID, Boundary: k.Boundary, BindingHash: renewalHash(op.Binding), TermsHash: renewalHash(op.Terms), Outcome: "confirmed", Timing: "future_configuration", VerifiedAt: now.UTC(), Evidence: evidence}
	}
	return result, nil
}
