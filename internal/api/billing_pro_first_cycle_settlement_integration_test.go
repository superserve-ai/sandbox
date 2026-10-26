//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

// This joins the real quote producer, persisted payment/credit activation, and
// the invoice credit ledger. Only Stripe transport and elapsed time are fake.
func TestProFirstCycleQuotePaymentAndUsageSettlement(t *testing.T) {
	for _, tc := range []struct {
		paid    int64
		delayed bool
	}{{25000, false}, {12500, false}, {0, false}, {25000, true}} {
		paid := tc.paid
		t.Run(fmt.Sprintf("paid-%d-delayed-%v", paid, tc.delayed), func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			if tc.delayed {
				now = time.Date(2026, 10, 31, 23, 50, 0, 0, time.UTC)
			}
			h, team, offer, params := newProFirstCycleQuoteFixture(t, now)
			poolConfig := h.Pool.Config()
			poolConfig.MaxConns = 1
			pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			h.Pool, h.DB = pool, db.New(pool)
			params.ResourceTerms = []StripeCheckoutResourceTerms{{ResourceKey: "vcpu", PriceID: "price_cpu", UnitAmountDecimal: "1", MeterID: "mtr_cpu", EventName: "cpu"}}
			requestProFirstCycleQuote(t, h, team, offer, params, http.StatusAccepted)
			u, err := h.proUpgrade(t.Context(), team)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(u.Payload, &params); err != nil {
				t.Fatal(err)
			}
			if !params.FirstPaidProCycle || u.Amount != 25000 || u.bridgeCreditAmount() != 25000 {
				t.Fatalf("quote did not preserve full independent first-month terms: %+v", u)
			}
			freeUsageBefore := ""
			if tc.delayed {
				recoveredAt := now.Add(20 * time.Minute)
				freeStart, freeEnd := billing.CurrentBillingPeriod(recoveredAt)
				if _, err = h.DB.UpsertTeamBillingPeriod(t.Context(), db.UpsertTeamBillingPeriodParams{TeamID: team, PeriodStart: freeStart, PeriodEnd: freeEnd, Status: "open"}); err != nil {
					t.Fatal(err)
				}
				if _, err = h.Pool.Exec(t.Context(), `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds) SELECT team_id,period_start,period_end,42 FROM team_billing_period WHERE team_id=$1`, team); err != nil {
					t.Fatal(err)
				}
				if err = h.Pool.QueryRow(t.Context(), `SELECT jsonb_agg(to_jsonb(x) ORDER BY period_start)::text FROM team_billing_usage x WHERE team_id=$1`, team).Scan(&freeUsageBefore); err != nil {
					t.Fatal(err)
				}
				h.Now = func() time.Time { return recoveredAt }
				requestProFirstCycleQuote(t, h, team, offer, params, http.StatusAccepted)
				replay, e := h.proUpgrade(t.Context(), team)
				if e != nil || replay.ID != u.ID || !replay.Anchor.Equal(u.Anchor) || string(replay.Payload) != string(u.Payload) {
					t.Fatalf("cross-month recovery changed accepted quote: %+v %v", replay, e)
				}
			}
			paidAt := h.nowUTC().Truncate(time.Second)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, e := h.Pool.Exec(t.Context(), sql, args...); e != nil {
					t.Fatal(e)
				}
			}
			subID := "sub_" + uuid.NewString()
			u.Subscription = &subID
			session := StripeRetrievedCheckoutSession{ID: "cs_" + uuid.NewString(), Mode: "payment", CustomerID: u.Customer, ClientReferenceID: team.String(), Status: "complete", PaymentStatus: "paid", Currency: "usd", AmountSubtotal: u.Amount, AmountTotal: paid, InvoiceID: "in_fee_" + uuid.NewString(), PaymentIntentID: "pi_" + uuid.NewString(), Metadata: map[string]string{"pro_upgrade_id": u.ID.String()}}
			session.TotalDetails.Discount = u.Amount - paid
			if paid == 0 {
				session.PaymentStatus = "no_payment_required"
			}
			u.Session = &session.ID
			exec(`UPDATE team_billing_account SET stripe_subscription_id=$2,stripe_subscription_status='active',commercial_billing_anchor=$3 WHERE team_id=$1`, team, subID, u.Anchor)
			exec(`UPDATE billing_pro_upgrade SET subscription_id=$2,session_id=$3 WHERE id=$1`, u.ID, subID, session.ID)
			var sub invoiceSubscription
			sub.ID, sub.Customer, sub.Status, sub.DefaultPaymentMethod = subID, u.Customer, "active", "pm_first"
			sub.Metadata = map[string]string{"first_paid_pro_cycle": "true", "pro_upgrade_id": u.ID.String()}
			_ = json.Unmarshal([]byte(fmt.Sprintf(`{"day_of_month":%d,"hour":%d,"minute":%d,"second":%d}`, u.Anchor.UTC().Day(), u.Anchor.UTC().Hour(), u.Anchor.UTC().Minute(), u.Anchor.UTC().Second())), &sub.BillingCycleAnchorConfig)
			sub.BillingMode.Type = "flexible"
			sub.StartDate, sub.BillingCycleAnchor = u.Anchor.Unix(), u.End.Unix()
			_ = json.Unmarshal([]byte(`{"behavior":"keep_as_draft"}`), &sub.PauseCollection)
			base := invoiceSubscriptionItem{ID: "si_base", Created: paidAt.Unix(), Quantity: 1, Metadata: map[string]string{"pro_upgrade_id": u.ID.String()}}
			_ = json.Unmarshal([]byte(`{"id":"price_pro","currency":"usd","unit_amount_decimal":"25000","billing_scheme":"per_unit","recurring":{"usage_type":"licensed","interval":"month","interval_count":1}}`), &base.Price)
			resource := invoiceSubscriptionItem{ID: "si_cpu", Start: u.Start.Unix(), End: u.End.Unix()}
			if err = json.Unmarshal([]byte(`{"id":"price_cpu","active":true,"currency":"usd","unit_amount_decimal":"1","billing_scheme":"per_unit","recurring":{"usage_type":"metered","interval":"month","interval_count":1,"meter":"mtr_cpu"}}`), &resource.Price); err != nil {
				t.Fatal(err)
			}
			rounding := invoiceSubscriptionItem{ID: "si_round", Start: u.Start.Unix(), End: u.End.Unix()}
			if err = json.Unmarshal([]byte(`{"id":"price_round","active":true,"currency":"usd","unit_amount_decimal":"1","billing_scheme":"per_unit","recurring":{"usage_type":"metered","interval":"month","interval_count":1,"meter":"mtr_round"}}`), &rounding.Price); err != nil {
				t.Fatal(err)
			}
			sub.Items.Data = []invoiceSubscriptionItem{base, resource, rounding}
			var grant entitlementGrant
			grant.ID, grant.Customer, grant.Category, grant.Priority = "credgr_"+uuid.NewString(), u.Customer, "paid", 50
			grant.Amount.Type, grant.Amount.Monetary.Currency, grant.Amount.Monetary.Value = "monetary", "usd", offer.Credit
			grant.Metadata = map[string]string{"pro_upgrade_id": u.ID.String()}
			grant.Applicability.Scope.PriceType = "metered"
			grant.Created, grant.EffectiveAt, grant.ExpiresAt = paidAt.Unix(), paidAt.Unix(), u.End.Unix()+1
			balance, grantCreates := offer.Credit, 0
			grantPresent := false
			usageInvoice := "in_usage_" + uuid.NewString()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var out any
				switch r.URL.Path {
				case "/v1/invoices/" + session.InvoiceID:
					out = map[string]any{"id": session.InvoiceID, "customer": u.Customer, "status": "paid", "currency": "usd", "amount_paid": paid, "amount_due": paid, "amount_remaining": 0, "ending_balance": 0, "status_transitions": map[string]any{"paid_at": paidAt.Unix()}, "lines": map[string]any{"data": []any{map[string]any{"amount": u.Amount, "currency": "usd", "quantity": 1}}}}
				case "/v1/payment_intents/" + session.PaymentIntentID:
					out = map[string]any{"id": session.PaymentIntentID, "customer": u.Customer, "status": "succeeded", "currency": "usd", "amount_received": paid, "latest_charge": "ch_first", "payment_method": "pm_first", "setup_future_usage": "off_session", "metadata": map[string]string{"pro_upgrade_id": u.ID.String()}}
				case "/v1/charges/ch_first":
					out = map[string]any{"id": "ch_first", "customer": u.Customer, "payment_intent": session.PaymentIntentID, "currency": "usd", "paid": true, "captured": true, "amount_captured": paid}
				case "/v1/customers/" + u.Customer:
					out = map[string]any{"id": u.Customer, "invoice_settings": map[string]string{"default_payment_method": "pm_first"}}
				case "/v1/payment_methods/pm_first":
					out = map[string]any{"id": "pm_first", "customer": u.Customer, "type": "card"}
				case "/v1/subscriptions/" + subID:
					if r.Method != http.MethodGet {
						t.Errorf("unexpected recurring fee mutation: %s", r.Method)
					}
					out = sub
				case "/v1/subscriptions":
					out = map[string]any{"data": []any{sub}}
				case "/v1/prices/price_round":
					out = rounding.Price
				case "/v1/billing/meters":
					out = map[string]any{"data": []any{map[string]any{"id": "mtr_round", "event_name": "round", "default_aggregation": map[string]string{"formula": "sum"}, "customer_mapping": map[string]string{"event_payload_key": "stripe_customer_id"}, "value_settings": map[string]string{"event_payload_key": "value"}}}}
				case "/v1/invoices":
					out = map[string]any{"data": []any{}}
				case "/v1/billing/credit_grants":
					if r.Method == http.MethodPost {
						grantCreates++
						_ = r.ParseForm()
						if r.Form.Get("amount[monetary][value]") != strconv.FormatInt(offer.Credit, 10) || r.Form.Get("expires_at") != strconv.FormatInt(u.End.Unix()+1, 10) {
							t.Errorf("first-month grant is not full expiring independent credit: %v", r.Form)
						}
						grantPresent = true
						out = grant
					} else if grantPresent {
						out = map[string]any{"data": []any{grant}}
					} else {
						out = map[string]any{"data": []any{}}
					}
				case "/v1/billing/credit_grants/" + grant.ID:
					if !grantPresent {
						http.NotFound(w, r)
						return
					}
					out = grant
				case "/v1/billing/credit_balance_transactions":
					out = map[string]any{"data": []any{}}
				case "/v1/billing/credit_balance_summary":
					out = map[string]any{"balances": []any{map[string]any{"ledger_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": balance}}}}}
				case "/v1/billing/credit_balance_transactions/cbtxn_first":
					out = map[string]any{"id": "cbtxn_first", "credit_grant": grant.ID, "type": "debit", "debit": map[string]any{"type": "credits_applied", "amount": map[string]any{"type": "monetary", "monetary": map[string]any{"currency": "usd", "value": 100}}, "credits_applied": map[string]any{"invoice": usageInvoice, "invoice_line_item": "il_cpu"}}}
				default:
					t.Errorf("unexpected provider route %s %s", r.Method, r.URL)
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer srv.Close()
			client := &stripeHTTPClient{baseURL: srv.URL, httpClient: srv.Client(), apiVersion: "2026-07-29.dahlia"}
			h.Stripe = client
			token := uuid.New()
			if _, err = h.DB.ClaimStripeWebhookProcessingLease(t.Context(), db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: u.Customer, Token: token}); err != nil {
				t.Fatal(err)
			}
			conn, err := h.Pool.Acquire(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			method, evidence, err := h.verifyProUpgradePayment(t.Context(), conn, client, u, session, true)
			if err != nil || method != "pm_first" {
				conn.Release()
				t.Fatalf("payment proof: %s %v", method, err)
			}
			if _, err = conn.Exec(t.Context(), `UPDATE billing_pro_upgrade SET payment_evidence=$2,payment_method_id=$3 WHERE id=$1`, u.ID, evidence, method); err != nil {
				conn.Release()
				t.Fatal(err)
			}
			for range 2 {
				if err = h.issueProUpgradeCredit(t.Context(), conn, &u, client); err != nil {
					conn.Release()
					t.Fatal(err)
				}
			}
			for range 2 {
				if err = h.commitProUpgrade(t.Context(), conn, &u, sub, offer, method, client, token); err != nil {
					conn.Release()
					t.Fatal(err)
				}
			}
			a := invoiceAccount{Customer: u.Customer, Subscription: subID, Price: "price_round", EnrolledAt: u.Start, Base: invoiceBase{Price: offer.Price, Amount: offer.Amount, Months: 1}}
			// The enrollment caller holds the only pool connection. Preflight
			// must use its supplied reader instead of waiting for another one.
			preflightCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			tx, err := conn.Begin(preflightCtx)
			if err != nil {
				conn.Release()
				cancel()
				t.Fatal(err)
			}
			ready, preflightErr := h.preflightFirstProCycleCredits(preflightCtx, team, a, client, tx)
			_ = tx.Rollback(t.Context())
			cancel()
			if preflightErr != nil || !ready {
				conn.Release()
				t.Fatalf("single-connection first-cycle enrollment preflight: %v %v", ready, preflightErr)
			}
			conn.Release()
			exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, team)
			enrollmentCtx, cancelEnrollment := context.WithTimeout(t.Context(), 5*time.Second)
			if err = h.enrollInvoiceAccount(enrollmentCtx, team, &invoiceAccount{Price: "price_round", Event: "round", Meter: "mtr_round"}); err != nil {
				cancelEnrollment()
				t.Fatalf("full first-cycle invoice enrollment: %v", err)
			}
			cancelEnrollment()
			for _, changed := range []map[string]string{{"pro_upgrade_id": u.ID.String()}, {"first_paid_pro_cycle": "true", "pro_upgrade_id": uuid.NewString()}} {
				sub.Metadata = changed
				if err = h.enrollInvoiceAccount(t.Context(), team, &invoiceAccount{Price: "price_round", Event: "round", Meter: "mtr_round"}); err == nil {
					t.Fatal("existing enrollment silently accepted removed or changed first-cycle provider authority")
				}
			}
			sub.Metadata = map[string]string{"first_paid_pro_cycle": "true", "pro_upgrade_id": u.ID.String()}
			enrolledAccount, enrolled, err := h.invoiceAccount(t.Context(), team)
			if err != nil || !enrolled || enrolledAccount.Subscription != subID || enrolledAccount.Base.Price != offer.Price {
				t.Fatalf("first-cycle enrolled account %+v enrolled=%v err=%v", enrolledAccount, enrolled, err)
			}
			a = enrolledAccount
			if outcome, e := h.activateProUpgrade(t.Context(), u, params); e != nil || outcome != "active" {
				t.Fatalf("activation: %s %v", outcome, e)
			}
			if grantCreates != 1 {
				t.Fatalf("payment replay duplicated grant: %d", grantCreates)
			}
			if tc.delayed {
				var usageAfter string
				var retired int
				if err = h.Pool.QueryRow(t.Context(), `SELECT jsonb_agg(to_jsonb(x) ORDER BY period_start)::text FROM team_billing_usage x WHERE team_id=$1`, team).Scan(&usageAfter); err != nil {
					t.Fatal(err)
				}
				if err = h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM team_billing_period WHERE team_id=$1 AND finalized_at IS NOT NULL AND blocked_reason='reporting_only_calendar_period'`, team).Scan(&retired); err != nil || retired != 2 || usageAfter != freeUsageBefore {
					t.Fatalf("delayed Free accounting history not preserved: retired=%d unchanged=%v err=%v", retired, usageAfter == freeUsageBefore, err)
				}
			}
			var contractStart time.Time
			var monthlyFee, monthlyCredit int64
			var status string
			if err = h.Pool.QueryRow(t.Context(), `SELECT starts_at,charge_amount_cents,entitlement_amount_cents,status FROM billing_commercial_contract WHERE id=$1`, u.Contract).Scan(&contractStart, &monthlyFee, &monthlyCredit, &status); err != nil {
				t.Fatal(err)
			}
			if !contractStart.Equal(u.End) || monthlyFee != 25000 || monthlyCredit != 25000 || status != "pending" {
				t.Fatalf("first fee or coupon leaked into recurring contract: %s %d %d %s", contractStart, monthlyFee, monthlyCredit, status)
			}
			if err = h.loadInvoiceBase(t.Context(), team, &a); err != nil {
				t.Fatal(err)
			}
			if fee, _, _, e := a.Base.expectedFee(u.Start); e != nil || fee != 0 {
				t.Fatalf("first fee duplicated in invoice base: %d %v", fee, e)
			}
			fee, feeStart, feeEnd, err := a.Base.expectedFee(u.End)
			_, nextEnd, _ := billing.AnniversaryPeriod(u.Anchor, u.End)
			if err != nil || fee != 25000 || feeStart != u.End.Unix() || feeEnd != nextEnd.Unix() {
				t.Fatalf("renewal fee boundary: %d %d %d %v", fee, feeStart, feeEnd, err)
			}
			h.Now = func() time.Time { return u.End.Add(2 * time.Second) }
			if err = h.verifyOwnedEntitlementGrant(t.Context(), grant); err != nil {
				t.Fatalf("generic inventory rejected frozen first-month credit: %v", err)
			}
			for _, kind := range []string{"extended-expiry", "changed-amount", "changed-marker"} {
				changed := grant
				switch kind {
				case "extended-expiry":
					changed.ExpiresAt = u.End.AddDate(0, 1, 0).Unix()
				case "changed-amount":
					changed.Amount.Monetary.Value++
				case "changed-marker":
					changed.Metadata = map[string]string{"pro_upgrade_id": uuid.NewString()}
				}
				if e := h.verifyOwnedEntitlementGrant(t.Context(), changed); e == nil {
					t.Fatalf("generic inventory accepted %s first-month credit", kind)
				}
			}
			p := billing.ExportPeriod{TeamID: team, Start: u.Start, End: u.End}
			closePlan := func() billing.InvoiceClosePlan {
				return billing.InvoiceClosePlan{Customer: u.Customer, Subscription: subID, InvoiceStart: p.Start.Unix(), InvoiceEnd: p.End.Unix(), ExpectedCents: 100, BaseCents: fee, BasePeriodStart: feeStart, BasePeriodEnd: feeEnd, Resources: []billing.InvoiceCloseResource{{PriceID: "price_cpu"}}}
			}
			plan := closePlan()
			handled, err := h.prepareFirstProCycleCredits(t.Context(), p, a, usageInvoice, &plan, client)
			if err != nil || !handled || plan.CreditVersion != 1 || plan.CreditBeforeCents != 25000 || len(plan.CreditGrants) != 1 {
				t.Fatalf("first usage plan %+v handled=%v err=%v", plan, handled, err)
			}
			raw, _ := json.Marshal(plan)
			exec(`INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'exporting') ON CONFLICT(team_id,period_start,period_end) DO UPDATE SET status='exporting'`, team, p.Start, p.End)
			exec(`INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan) VALUES($1,$2,$3,$4,$5)`, team, p.Start, p.End, usageInvoice, raw)
			if tc.delayed {
				var before string
				if err = h.Pool.QueryRow(t.Context(), `SELECT jsonb_agg(to_jsonb(x) ORDER BY period_start)::text FROM team_billing_period x WHERE team_id=$1`, team).Scan(&before); err != nil {
					t.Fatal(err)
				}
				tx, e := h.Pool.Begin(t.Context())
				if e != nil {
					t.Fatal(e)
				}
				if _, e = h.DB.WithTx(tx).LockTeamBillingAccount(t.Context(), team); e == nil {
					e = retireFirstProCycleReportingPeriods(t.Context(), tx, u)
				}
				if e == nil {
					e = tx.Commit(t.Context())
				} else {
					_ = tx.Rollback(t.Context())
				}
				if e != nil {
					t.Fatalf("verified paid target cannot replay: %v", e)
				}
				var after string
				if err = h.Pool.QueryRow(t.Context(), `SELECT jsonb_agg(to_jsonb(x) ORDER BY period_start)::text FROM team_billing_period x WHERE team_id=$1`, team).Scan(&after); err != nil || before != after {
					t.Fatalf("replay modified verified paid target: %v", err)
				}
			}
			before, err := h.invoicePlanCredits(t.Context(), p, a, plan, nil, client)
			if err != nil || before != 25000 {
				t.Fatalf("first usage pre-finalization %d %v", before, err)
			}
			balance -= 100
			var invoice StripeInvoiceAmounts
			invoiceJSON := fmt.Sprintf(`{"id":%q,"customer":%q,"currency":"usd","status":"paid","subtotal":25100,"total":25000,"amount_due":25000,"amount_remaining":0,"starting_balance":0,"ending_balance":0,"total_pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":100,"credit_balance_transaction":"cbtxn_first"}],"lines":{"data":[{"id":"il_base","amount":25000,"currency":"usd","quantity":1,"pricing":{"unit_amount_decimal":"25000","price_details":{"price":"price_pro"}},"period":{"start":%d,"end":%d},"parent":{"subscription_item_details":{"subscription":%q}}},{"id":"il_cpu","pricing":{"price_details":{"price":"price_cpu"}},"pretax_credit_amounts":[{"type":"credit_balance_transaction","amount":100,"credit_balance_transaction":"cbtxn_first"}]}]}}`, usageInvoice, u.Customer, feeStart, feeEnd, subID)
			if err = json.Unmarshal([]byte(invoiceJSON), &invoice); err != nil {
				t.Fatal(err)
			}
			if err = a.Base.validateLine(invoice.Lines.Data[0], subID, feeStart, feeEnd); err != nil {
				t.Fatalf("renewal licensed fee line: %v", err)
			}
			after, err := h.invoicePlanCredits(t.Context(), p, a, plan, &invoice, client)
			if err != nil || after != 24900 {
				t.Fatalf("first usage credit consumption %d %v", after, err)
			}
			if err = verifyInvoicePlanSettlement(invoice, plan, before, after); err != nil {
				t.Fatal(err)
			}
			underpaid := invoice
			underpaid.Total--
			if err = verifyInvoicePlanSettlement(underpaid, plan, before, after); err == nil {
				t.Fatal("first-month credits consumed licensed renewal fee")
			}
			balance = 25000
			original := grant
			for _, mutation := range []string{"amount", "expiry", "voided", "missing"} {
				t.Run(mutation, func(t *testing.T) {
					grant = original
					grantPresent = true
					switch mutation {
					case "amount":
						grant.Amount.Monetary.Value--
					case "expiry":
						grant.ExpiresAt = u.End.Unix()
					case "voided":
						grant.VoidedAt = now.Unix()
					case "missing":
						grantPresent = false
					}
					exec(`DELETE FROM billing_invoice_credit_scan WHERE customer_id=$1`, u.Customer)
					changed := closePlan()
					if ok, e := h.prepareFirstProCycleCredits(t.Context(), p, a, usageInvoice, &changed, client); e == nil {
						t.Fatalf("altered promise allowed cash fallback: handled=%v plan=%+v", ok, changed)
					}
				})
			}
			grant = original
			grantPresent = true
			// Historical first-period authority survives a later downgrade and contract
			// ending; it must still settle earned usage without restarting benefits.
			if _, err = assignInTx(t, h, planAssignment{Team: team, Terms: testPlanTerms("free", "free", 2, nil), Source: "plan_change", Reason: "subsequent Free downgrade"}); err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE billing_commercial_contract SET status='ended',revision=revision+1 WHERE id=$1`, u.Contract)
			exec(`DELETE FROM billing_invoice_credit_scan WHERE customer_id=$1`, u.Customer)
			endedPlan := closePlan()
			if ok, e := h.prepareFirstProCycleCredits(t.Context(), p, a, usageInvoice, &endedPlan, client); e != nil || !ok {
				t.Fatalf("historical first-period promise lost on downgrade: %v %v", ok, e)
			}
			nextStart, nextEnd, _ := billing.AnniversaryPeriod(u.Anchor, u.End)
			next := billing.ExportPeriod{TeamID: team, Start: nextStart, End: nextEnd}
			nextPlan := billing.InvoiceClosePlan{}
			if ok, e := h.prepareFirstProCycleCredits(t.Context(), next, a, "in_next", &nextPlan, client); e != nil || ok {
				t.Fatalf("first-cycle promise reused on renewal: %v %v", ok, e)
			}
			if grantCreates != 1 {
				t.Fatalf("usage preparation issued another monthly allowance: %d", grantCreates)
			}
		})
	}
}
