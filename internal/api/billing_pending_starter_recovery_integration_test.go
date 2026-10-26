//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestPrepaidPendingStarterRecovery(t *testing.T) {
	for _, scenario := range []string{"resume", "cancel", "expired", "paid", "lost_ack", "timeout", "mismatch", "changed_generation", "wrong_actor", "wrong_request", "failed_fence", "closed_entry", "wrong_team", "expired_webhook_race", "paid_during_expire", "timeout_after_expire", "mismatch_after_expire", "wrong_generation", "legacy_resume", "legacy_cancel", "legacy_closed_entry", "expired_with_invoice", "expired_with_payment_intent", "expired_with_subscription", "established_subscription_resume"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPrepaidFixture(t)
			actor := uuid.New()
			r := prepaidOperationRouter(t, f, f.team, actor)
			f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
			f.exec(`UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL WHERE team_id=$1`, f.team)
			f.exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, f.team)
			req := prepaidCheckoutBody{OperationID: uuid.New(), AmountCents: 2500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
			if strings.HasPrefix(scenario, "legacy_") {
				req.OperationID = uuid.Nil
			}
			rec := prepaidOperationPost(r, req)
			var created prepaidOperationResponse
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &created) != nil || created.ID == "" {
				t.Fatalf("create %d %s", rec.Code, rec.Body)
			}
			p, err := f.h.loadPendingStarter(t.Context(), f.team, actor)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "failed_fence" {
				f.exec(`UPDATE billing_prepaid_purchase SET payment_state='failed',failure_reason='Prior checkout failure' WHERE id=$1`, p.Purchase)
			}
			if scenario == "closed_entry" || scenario == "legacy_closed_entry" {
				f.exec(`UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, f.team)
				f.h.Config.AppAllowedOrigins = []string{"https://different.example.com"}
			}
			cancelCalls, gets := 0, 0
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if strings.HasPrefix(request.URL.Path, "/v1/checkout/sessions/") {
					if strings.HasSuffix(request.URL.Path, "/expire") {
						cancelCalls++
						if scenario == "lost_ack" {
							f.mu.Lock()
							f.sessions[created.ID]["status"] = "expired"
							f.mu.Unlock()
							w.WriteHeader(502)
							return
						}
						f.mu.Lock()
						f.sessions[created.ID]["status"] = "expired"
						f.mu.Unlock()
						if scenario == "expired_webhook_race" {
							raw, _ := json.Marshal(map[string]any{"id": created.ID, "customer": f.customer, "client_reference_id": f.team.String(), "metadata": map[string]string{"checkout_generation": p.Account.CheckoutInitializingAt.Time.UTC().Format(time.RFC3339Nano)}})
							event := stripeEventEnvelope{ID: "evt_" + uuid.NewString(), Type: "checkout.session.expired", Data: stripeEventEnvelopeData{Object: raw}}
							payload, _ := json.Marshal(event)
							f.exec(`INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES($1,$2,$3)`, event.ID, event.Type, payload)
							// Lease ensures concurrent webhook cannot mutate while this operation owns it;
							// leave replay verification until the cancellation releases its lease.
						}
						if scenario == "changed_generation" {
							f.exec(`UPDATE team_billing_account SET checkout_initializing_at=checkout_initializing_at+interval '1 second' WHERE team_id=$1`, f.team)
						}
					}
					gets++
					if scenario == "established_subscription_resume" {
						f.exec(`UPDATE team_billing_account SET stripe_subscription_id=$2,stripe_subscription_status='active' WHERE team_id=$1`, f.team, f.sub)
					}
					if scenario == "timeout" || (scenario == "timeout_after_expire" && cancelCalls > 0) {
						w.WriteHeader(504)
						return
					}
					f.mu.Lock()
					data := map[string]any{}
					for k, v := range f.sessions[created.ID] {
						data[k] = v
					}
					f.mu.Unlock()
					data["payment_status"] = "unpaid"
					if scenario == "expired" || strings.HasPrefix(scenario, "expired_with_") {
						data["status"] = "expired"
					}
					if scenario == "expired_with_invoice" {
						data["invoice"] = "in_pending"
					}
					if scenario == "expired_with_payment_intent" {
						data["payment_intent"] = "pi_pending"
					}
					if scenario == "expired_with_subscription" {
						data["subscription"] = "sub_pending"
					}
					if scenario == "paid" || (scenario == "paid_during_expire" && cancelCalls > 0) {
						data["status"] = "complete"
						data["payment_status"] = "paid"
						data["subscription"] = "sub_completed"
					}
					if scenario == "mismatch" || (scenario == "mismatch_after_expire" && cancelCalls > 0) {
						data["customer"] = "cus_wrong"
					}
					json.NewEncoder(w).Encode(data)
					return
				}
				f.serve(w, request)
			}))
			defer provider.Close()
			f.client.baseURL = provider.URL
			f.client.httpClient = provider.Client()
			currentActor := actor
			if scenario == "wrong_actor" {
				currentActor = uuid.New()
			}
			r.POST("/billing/prepaid/checkout/recover", func(c *gin.Context) {
				team := f.team
				if scenario == "wrong_team" {
					team = uuid.New()
				}
				c.Set("team_id", team.String())
				c.Set("actor_id", currentActor)
				f.h.RecoverPendingStarterCheckout(c)
			})
			// The alternate actor has billing access but cannot recover somebody else's session.
			if scenario == "wrong_actor" {
				prepaidOperationRouter(t, f, f.team, currentActor)
			}
			post := func(input pendingStarterRequest) *httptest.ResponseRecorder {
				b, _ := json.Marshal(input)
				out := httptest.NewRecorder()
				r.ServeHTTP(out, httptest.NewRequest("POST", "/billing/prepaid/checkout/recover", strings.NewReader(string(b))))
				return out
			}
			discover := post(pendingStarterRequest{})
			if scenario == "wrong_team" {
				if discover.Code != 403 {
					t.Fatalf("wrong team %d %s", discover.Code, discover.Body)
				}
				return
			}
			if scenario == "wrong_actor" {
				if !strings.Contains(discover.Body.String(), "no_pending_starter_checkout") || gets != 0 {
					t.Fatalf("actor exposure %d %s", discover.Code, discover.Body)
				}
				return
			}
			if discover.Code != 200 || !strings.Contains(discover.Body.String(), "pending_starter_checkout") || strings.Contains(discover.Body.String(), "https:") {
				t.Fatalf("discovery %d %s", discover.Code, discover.Body)
			}
			input := pendingStarterRequest{PurchaseID: p.Purchase, Generation: &p.Account.CheckoutInitializingAt.Time, Cancel: scenario != "resume" && scenario != "closed_entry" && scenario != "expired" && scenario != "legacy_resume" && scenario != "legacy_closed_entry" && scenario != "established_subscription_resume"}
			if scenario == "wrong_generation" {
				g := input.Generation.Add(time.Second)
				input.Generation = &g
			}
			if scenario == "wrong_request" {
				input.PurchaseID = uuid.New()
			}
			got := post(input)
			var fence bool
			var payment string
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT a.checkout_initializing_at IS NOT NULL,p.payment_state FROM team_billing_account a JOIN billing_prepaid_purchase p USING(team_id) WHERE p.id=$1`, p.Purchase).Scan(&fence, &payment); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "resume", "closed_entry", "legacy_resume", "legacy_closed_entry":
				if got.Code != 200 || !strings.Contains(got.Body.String(), "recovered") || cancelCalls != 0 || !fence {
					t.Fatalf("resume %d %s fence%v", got.Code, got.Body, fence)
				}
			case "cancel", "expired", "failed_fence", "expired_webhook_race", "legacy_cancel":
				if got.Code != 200 || !strings.Contains(got.Body.String(), "retryable") || fence || payment != "failed" {
					t.Fatalf("release %d %s fence%v %s", got.Code, got.Body, fence, payment)
				}
				if scenario == "expired" {
					var reason string
					if err := f.h.Pool.QueryRow(t.Context(), `SELECT failure_reason FROM billing_prepaid_purchase WHERE id=$1`, p.Purchase).Scan(&reason); err != nil || reason != "The unpaid checkout expired" {
						t.Fatalf("natural expiry attribution %q %v", reason, err)
					}
				}
				var evidence bool
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM stripe_checkout_expiration_evidence WHERE team_id=$1)`, f.team).Scan(&evidence); err != nil || !evidence {
					t.Fatalf("expiration %v %v", evidence, err)
				}
			case "established_subscription_resume":
				if !fence || cancelCalls != 0 || strings.Contains(got.Body.String(), "https:") || !strings.Contains(got.Body.String(), "payment_confirmation_pending") {
					t.Fatalf("payable session exposed for established subscription: %d %s", got.Code, got.Body)
				}
			case "wrong_request", "wrong_generation":
				if got.Code != 409 || gets != 0 || !fence {
					t.Fatalf("wrong target %d %s", got.Code, got.Body)
				}
			default:
				if !fence || cancelCalls > 1 || !strings.Contains(got.Body.String(), "payment_confirmation_pending") {
					t.Fatalf("unsafe uncertain release %s %d %s fence%v", scenario, got.Code, got.Body, fence)
				}
			}
			if scenario == "lost_ack" {
				retry := post(input)
				if retry.Code != 200 || !strings.Contains(retry.Body.String(), "retryable") || cancelCalls != 1 {
					t.Fatalf("lost ack retry %d %s", retry.Code, retry.Body)
				}
			}
			if scenario == "cancel" {
				replay := post(input)
				if replay.Code != 200 || !strings.Contains(replay.Body.String(), "no_pending_starter_checkout") || cancelCalls != 1 {
					t.Fatalf("cancel replay %d %s", replay.Code, replay.Body)
				}
			}
			if scenario == "expired_webhook_race" {
				var raw []byte
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT payload FROM stripe_webhook_event WHERE payload->'data'->'object'->>'id'=$1`, created.ID).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var event stripeEventEnvelope
				_ = json.Unmarshal(raw, &event)
				if err := f.h.processRecordedStripeWebhook(t.Context(), event); err != nil {
					t.Fatal(err)
				}
			}
			var count int
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 1 {
				t.Fatalf("duplicated purchase %d %v", count, err)
			}
		})
	}
}

func TestPrepaidPendingStarterRecoveryRejectsInvalidAction(t *testing.T) {
	f := newPrepaidFixture(t)
	actor := uuid.New()
	r := prepaidOperationRouter(t, f, f.team, actor)
	r.POST("/billing/prepaid/checkout/recover", func(c *gin.Context) {
		c.Set("team_id", f.team.String())
		c.Set("actor_id", actor)
		f.h.RecoverPendingStarterCheckout(c)
	})
	for _, body := range []string{`null`, `[]`, `{"cancel":true}`, `{"purchase_id":"` + uuid.NewString() + `"}`, `{"checkout_generation":"2026-10-26T12:00:00Z"}`, `{"unknown":true}`, `{} {}`, `{"purchase_id":"invalid"}`, `{"checkout_generation":"invalid","purchase_id":"` + uuid.NewString() + `"}`} {
		t.Run(body, func(t *testing.T) {
			out := httptest.NewRecorder()
			r.ServeHTTP(out, httptest.NewRequest("POST", "/billing/prepaid/checkout/recover", strings.NewReader(body)))
			if out.Code != 400 {
				t.Fatalf("invalid action %d %s", out.Code, out.Body)
			}
		})
	}
}
