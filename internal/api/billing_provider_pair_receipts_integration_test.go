//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestProviderPairWorkerDiscoversOngoingCash(t *testing.T) {
	for _, mode := range []string{"second_monthly", "skewed_monthly", "later_annual", "paid_after_unpaid_pagination", "missing_mapping", "changed_receipt", "revoked_during_discovery", "debt_during_discovery"} {
		t.Run(mode, func(t *testing.T) {
			monthly := mode != "later_annual"
			anchor := time.Now().UTC().AddDate(-1, -1, 0).Add(-time.Hour).Truncate(time.Second)
			if !monthly {
				anchor = anchor.AddDate(-1, 0, 0)
			}
			if mode == "skewed_monthly" {
				anchor = time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC)
			}
			tx, b, f, h := paidPairMappingFixture(t, anchor, monthly)
			start, end, _ := billing.AnniversaryPeriod(b.Anchor, time.Now())
			offset := (start.Year()-b.FeeAnchor.Year())*12 + int(start.Month()-b.FeeAnchor.Month())
			offset -= offset % int(b.Terms.FeeMonths)
			f.invoice.ID = "in_ongoing_" + uuid.NewString()
			f.p.WaiverInvoiceID = f.invoice.ID
			f.invoice.Lines.Data[0].Period.Start = annualBoundary(b.FeeAnchor, offset).Unix()
			f.invoice.Lines.Data[0].Period.End = annualBoundary(b.FeeAnchor, offset+int(b.Terms.FeeMonths)).Unix()
			f.invoice.Status, f.invoice.AmountPaid, f.invoice.AmountRemaining = "paid", b.Terms.FeeAmount, 0
			f.invoice.StatusTransitions.PaidAt = f.invoice.Lines.Data[0].Period.Start + 1
			if mode == "missing_mapping" || mode == "changed_receipt" {
				recordMonthlyPairCash(t, tx, b, f, offset)
				if mode == "changed_receipt" {
					f.invoice.StatusTransitions.PaidAt++
				}
			}
			// Seed a contract activated in an earlier paid period. Wall-clock SQL
			// activation checks otherwise require today's receipt, the gap under test.
			for _, stmt := range []struct {
				sql  string
				args []any
			}{
				{`ALTER TABLE billing_commercial_contract DISABLE TRIGGER billing_commercial_contract_guard`, nil},
				{`ALTER TABLE billing_commercial_contract DISABLE TRIGGER billing_pro_payment_activation_guard`, nil},
				{`UPDATE billing_commercial_contract SET status='active',revision=revision+1 WHERE id=$1`, []any{b.ContractID}},
				{`ALTER TABLE billing_commercial_contract ENABLE TRIGGER billing_commercial_contract_guard`, nil},
				{`ALTER TABLE billing_commercial_contract ENABLE TRIGGER billing_pro_payment_activation_guard`, nil},
				{`INSERT INTO billing_entitlement_work(contract_id) VALUES($1) ON CONFLICT DO NOTHING`, []any{b.ContractID}},
				{`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true)`, []any{b.Identity.TeamID}},
				{`INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{b.Identity.TeamID, b.CustomerID, b.UsageSubscriptionID, b.Terms.Rounding.PriceID, b.Terms.Rounding.EventName, b.Terms.Rounding.MeterID, start}},
			} {
				if _, err := tx.Exec(t.Context(), stmt.sql, stmt.args...); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			h.Config = &config.Config{BillingUsageEntitlementsEnabled: true}
			wf := &pairWorkerFixture{h: h, b: b, authority: &pairWorkerAuthority{h: h}}
			h.ProviderPairEntitlementAuthority = wf.authority
			configurePairWorkerProvider(t, wf, f)
			base := f.serve
			paid := mode != "paid_after_unpaid_pagination"
			pages := 0
			f.serve = func(w http.ResponseWriter, req *http.Request) bool {
				if req.URL.Path == "/v1/invoices" && req.URL.Query().Get("status") == "paid" {
					if req.URL.Query().Get("subscription") != b.FeeSubscriptionID || req.URL.Query().Get("customer") != b.CustomerID {
						t.Error("discovery lost fee ownership")
					}
					ids := []map[string]string{}
					more := false
					if paid {
						if mode == "paid_after_unpaid_pagination" && req.URL.Query().Get("starting_after") == "" {
							for i := range 10 {
								ids = append(ids, map[string]string{"id": fmt.Sprintf("in_history_%d", i)})
							}
							more = true
						} else {
							ids = append(ids, map[string]string{"id": f.invoice.ID})
						}
					}
					pages++
					json.NewEncoder(w).Encode(map[string]any{"data": ids, "has_more": more})
					return true
				}
				if strings.HasPrefix(req.URL.Path, "/v1/invoices/in_history_") {
					fmt.Fprint(w, `{"lines":{"data":[{"period":{"start":1,"end":2}}]}}`)
					return true
				}
				if req.URL.Path == "/v1/invoices/"+f.invoice.ID {
					if mode == "revoked_during_discovery" {
						wf.authority.invalid.Store(true)
					}
					if mode == "debt_during_discovery" {
						wf.debt.Store(true)
					}
				}
				return base(w, req)
			}
			run := func() error { _, err := h.reconcileUsageEntitlement(t.Context(), b.ContractID); return err }
			if mode == "paid_after_unpaid_pagination" {
				if err := run(); err != nil || wf.posts.Load() != 0 {
					t.Fatal("unpaid invoice authorized grant", err)
				}
				paid = true
				if err := run(); err != nil || wf.posts.Load() != 0 {
					t.Fatal("incomplete page authorized grant", err)
				}
				var cursor string
				if err := h.Pool.QueryRow(t.Context(), `SELECT paired_invoice_cursor FROM billing_entitlement_work WHERE contract_id=$1`, b.ContractID).Scan(&cursor); err != nil || cursor != "in_history_9" {
					t.Fatal("discovery lost progress", cursor, err)
				}
			}
			err := run()
			var receipts, mappings int
			if readErr := h.Pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM billing_contract_payment WHERE contract_id=$1),(SELECT count(*) FROM billing_provider_pair_monthly_payment WHERE contract_id=$1)`, b.ContractID).Scan(&receipts, &mappings); readErr != nil {
				t.Fatal(readErr)
			}
			if mode == "revoked_during_discovery" || mode == "debt_during_discovery" {
				if receipts != 0 || mappings != 0 || wf.posts.Load() != 0 || (mode == "revoked_during_discovery" && err == nil) {
					t.Fatal("invalid authority adopted cash or grant", receipts, mappings, err)
				}
				return
			}
			if mode == "changed_receipt" {
				if err == nil || receipts != 1 || mappings != 0 || wf.posts.Load() != 0 {
					t.Fatal("changed cash receipt acquired new authority", receipts, mappings, err)
				}
				return
			}
			if err != nil || receipts != 1 || (monthly && mappings != 1) || wf.posts.Load() != 1 {
				t.Fatal("ongoing payment not adopted once", receipts, mappings, err)
			}
			e, err := h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: b.Identity.TeamID, Kind: "metered_usage"})
			if err != nil || !e.PeriodStart.Equal(start) || !e.PeriodEnd.Equal(end) || e.State != "issued" {
				t.Fatal("wrong allowance", e, err)
			}
			before := pages
			if err = run(); err != nil || wf.posts.Load() != 1 || pages != before {
				t.Fatal("replay duplicated discovery or grant", err)
			}
		})
	}
}
