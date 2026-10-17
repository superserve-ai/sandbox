//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
)

func seedCollection(t *testing.T, state string, first *time.Time, collectionMethods ...string) api.StripeInvoiceAmounts {
	t.Helper()
	_, p := seedIncrementalPeriod(t)
	inv := api.StripeInvoiceAmounts{CollectionMethod: "charge_automatically", ID: "in_" + p.TeamID.String(), Customer: "cus_" + p.TeamID.String(), Currency: "usd", Status: "open", AmountDue: 500, Total: 500, Subtotal: 500}
	if len(collectionMethods) > 0 {
		inv.CollectionMethod = collectionMethods[0]
	}
	raw := `{"parent":{"subscription_details":{"subscription":"sub_example"}},"amount_remaining":500,"ending_balance":0}`
	if err := json.Unmarshal([]byte(raw), &inv); err != nil {
		t.Fatal(err)
	}
	correctionExec(t, `INSERT INTO billing_invoice_close(team_id,period_start,period_end,invoice_id,plan) VALUES($1,$2,$3,$4,'{}')`, p.TeamID, p.Start, p.End, inv.ID)
	correctionExec(t, `INSERT INTO billing_invoice_collection(invoice_id,customer_id,subscription_id,livemode,settlement_hash,idempotency_key,payment_authorized,state,first_attempt_at) VALUES($1,$2,'sub_example',false,$3,$4,true,$5,$6)`, inv.ID, inv.Customer, api.InvoiceCollectionHashForTest(inv), "billing-invoice-pay:v1:"+inv.ID, state, first)
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE billing_invoice_collection SET next_attempt_at=now()+interval '10 years' WHERE invoice_id=$1`, inv.ID)
	})
	return inv
}

func collectionHandler(server *httptest.Server) *api.Handlers {
	return &api.Handlers{Pool: testPool, DB: testQueries, Stripe: api.NewStripeBillingClient(&config.Config{StripeSecretKey: "sk_test_example", StripeAPIVersion: "2026-05-27.dahlia", StripeAPIBaseURL: server.URL})}
}

func TestIntegration_InvoiceCollectionRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, initial, pi, want string
		hours                   int
		payStatus               int
	}{
		{"lost response", "unknown", "requires_confirmation", "unknown", 1, 500},
		{"key expired", "unknown", "requires_confirmation", "review_required", 24, 0},
		{"processing", "unknown", "processing", "processing", 1, 0},
		{"authentication", "unknown", "requires_action", "requires_action", 1, 0},
		{"decline", "unknown", "requires_payment_method", "requires_payment_method", 1, 0},
		{"initial method resolution", "pending", "requires_payment_method", "unknown", 0, 200},
		{"uncertain before method resolution", "unknown", "requires_payment_method", "unknown", 1, 200},
		{"declined outside worker", "pending", "requires_payment_method", "requires_payment_method", 0, 0},
		{"decline error cleared", "requires_payment_method", "requires_payment_method", "review_required", 1, 0},
		{"expired before method resolution", "unknown", "requires_payment_method", "review_required", 24, 0},
		{"do not retry decline", "requires_payment_method", "requires_confirmation", "review_required", 1, 0},
		{"reconcile paid", "unknown", "", "paid", 24, 0},
		{"uncollectible then paid", "uncollectible", "", "paid", 24, 0},
		{"changed settlement", "pending", "", "review_required", 0, 0},
		{"manual invoice", "pending", "requires_confirmation", "review_required", 0, 0},
		{"missing invoice method", "pending", "requires_confirmation", "review_required", 0, 0},
		{"manual subscription", "pending", "requires_confirmation", "review_required", 0, 0},
		{"missing subscription method", "pending", "requires_confirmation", "review_required", 0, 0},
		{"disabled auto advance after release", "pending", "requires_confirmation", "unknown", 0, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var first *time.Time
			if tc.hours > 0 {
				v := time.Now().Add(-time.Duration(tc.hours) * time.Hour)
				first = &v
			}
			invoiceMethod := "charge_automatically"
			if tc.name == "manual invoice" {
				invoiceMethod = "send_invoice"
			}
			if tc.name == "missing invoice method" {
				invoiceMethod = ""
			}
			inv := seedCollection(t, tc.initial, first, invoiceMethod)
			method := "charge_automatically"
			if tc.name == "manual subscription" {
				method = "send_invoice"
			}
			if tc.name == "missing subscription method" {
				method = ""
			}
			if tc.name == "reconcile paid" || tc.name == "uncollectible then paid" {
				inv.Status = "paid"
				*inv.AmountRemaining = 0
			}
			if tc.name == "changed settlement" {
				inv.Total++
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/invoices/"+inv.ID:
					_ = json.NewEncoder(w).Encode(inv)
				case r.URL.Path == "/v1/invoice_payments":
					pi := map[string]any{"id": "pi_example", "customer": inv.Customer, "currency": "usd", "status": tc.pi}
					if tc.name == "decline" || tc.name == "declined outside worker" {
						pi["last_payment_error"] = map[string]any{"code": "card_declined"}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"has_more": false, "data": []any{map[string]any{"invoice": inv.ID, "currency": "usd", "status": "open", "payment": map[string]any{"type": "payment_intent", "payment_intent": pi}}}})
				case r.URL.Path == "/v1/subscriptions/sub_example":
					_ = json.NewEncoder(w).Encode(map[string]any{"collection_method": method, "id": "sub_example", "customer": inv.Customer, "default_payment_method": "pm_example", "status": "active", "pause_collection": map[string]any{"behavior": "keep_as_draft"}, "items": map[string]any{"data": []any{map[string]any{"id": "si_example"}}}})
				case strings.HasSuffix(r.URL.Path, "/pay"):
					calls++
					if r.Header.Get("Idempotency-Key") != "billing-invoice-pay:v1:"+inv.ID {
						t.Error("recovery changed key")
					}
					var recorded bool
					if err := testPool.QueryRow(r.Context(), `SELECT first_attempt_at IS NOT NULL AND state='unknown' FROM billing_invoice_collection WHERE invoice_id=$1`, inv.ID).Scan(&recorded); err != nil || !recorded {
						t.Error("side effect preceded durable intent", err)
					}
					w.WriteHeader(tc.payStatus)
					_, _ = w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected request %s", r.URL)
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			if worked, err := collectionHandler(server).InvoiceCollectionTickForTest(t.Context()); !worked || err != nil {
				t.Fatalf("worked=%v err=%v", worked, err)
			}
			var state string
			if err := testPool.QueryRow(t.Context(), `SELECT state FROM billing_invoice_collection WHERE invoice_id=$1`, inv.ID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != tc.want || (calls == 1) != (tc.payStatus > 0) || calls > 1 {
				t.Fatalf("state=%s calls=%d", state, calls)
			}
			if first != nil {
				var same bool
				if err := testPool.QueryRow(t.Context(), `SELECT first_attempt_at=$2 FROM billing_invoice_collection WHERE invoice_id=$1`, inv.ID, first).Scan(&same); err != nil || !same {
					t.Fatal("attempt age was reset", err)
				}
			}
		})
	}
}

func TestIntegration_InvoiceCollectionFleetLease(t *testing.T) {
	// Hold four separate jobs in provider I/O; the fifth must stay queued.
	invoices := map[string]api.StripeInvoiceAmounts{}
	for i := 0; i < 5; i++ {
		inv := seedCollection(t, "review_required", nil)
		invoices["/v1/invoices/"+inv.ID] = inv
	}
	entered := make(chan struct{}, 5)
	release := make(chan struct{})
	var active, maxActive atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maxActive.Load(); n > old; old = maxActive.Load() {
			if maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		inv := invoices[r.URL.Path]
		inv.Status = "paid"
		*inv.AmountRemaining = 0
		_ = json.NewEncoder(w).Encode(inv)
	}))
	defer server.Close()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			_, err := collectionHandler(server).InvoiceCollectionTickForTest(t.Context())
			if err != nil {
				t.Error(err)
			}
		})
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			wg.Wait()
			t.Fatal("worker not claimed")
		}
	}
	worked, err := collectionHandler(server).InvoiceCollectionTickForTest(t.Context())
	close(release)
	wg.Wait()
	if worked || err != nil || maxActive.Load() != 4 {
		t.Fatalf("fleet cap failed: worked=%v err=%v active=%d", worked, err, maxActive.Load())
	}
}

func TestIntegration_InvoiceCollectionWebhookWakeup(t *testing.T) {
	inv := seedCollection(t, "uncollectible", nil)
	router := newBillingRouterWithPool(t, &fakeStripeClient{}, testPool)
	for _, kind := range []string{"invoice.updated", "invoice.payment_action_required", "invoice.paid"} {
		correctionExec(t, `UPDATE billing_invoice_collection SET next_attempt_at=now()+interval '1 hour' WHERE invoice_id=$1`, inv.ID)
		now := time.Now().UTC()
		payload, err := json.Marshal(map[string]any{"id": "evt_" + kind + inv.ID, "type": kind, "created": now.Unix(), "data": map[string]any{"object": map[string]any{"id": inv.ID, "customer": inv.Customer, "status": "paid"}}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Stripe-Signature", stripeSignature(t, payload, now))
		if w := doRequest(router, req); w.Code != 200 {
			t.Fatalf("webhook %s: %d %s", kind, w.Code, w.Body.String())
		}
		var due bool
		var state string
		if err := testPool.QueryRow(t.Context(), `SELECT next_attempt_at<=now(),state FROM billing_invoice_collection WHERE invoice_id=$1`, inv.ID).Scan(&due, &state); err != nil || !due || state != "uncollectible" {
			t.Fatalf("webhook must wake but not assert payment: due=%v state=%s err=%v", due, state, err)
		}
	}
}

func TestIntegration_InvoiceCollectionExpiredLeaseCannotPay(t *testing.T) {
	inv := seedCollection(t, "pending", nil)
	var payments atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/invoices/"+inv.ID:
			_ = json.NewEncoder(w).Encode(inv)
		case r.URL.Path == "/v1/invoice_payments":
			_, _ = w.Write([]byte(`{"data":[],"has_more":false}`))
		case r.URL.Path == "/v1/subscriptions/sub_example":
			// Simulate lease expiry and acquisition by another replica while
			// the old worker is still fetching provider evidence.
			correctionExec(t, `UPDATE billing_invoice_collection SET lease_token=gen_random_uuid(),lease_until=now()+interval '2 minutes' WHERE invoice_id=$1`, inv.ID)
			_ = json.NewEncoder(w).Encode(map[string]any{"collection_method": "charge_automatically", "id": "sub_example", "customer": inv.Customer, "status": "active", "pause_collection": map[string]any{"behavior": "keep_as_draft"}, "items": map[string]any{"data": []any{map[string]any{"id": "si_example"}}}})
		case strings.HasSuffix(r.URL.Path, "/pay"):
			payments.Add(1)
		}
	}))
	defer server.Close()
	worked, err := collectionHandler(server).InvoiceCollectionTickForTest(t.Context())
	if !worked || err == nil || payments.Load() != 0 {
		t.Fatalf("stale worker paid: worked=%v err=%v payments=%d", worked, err, payments.Load())
	}
}
