//go:build integration

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func prepaidOperationRouter(t *testing.T, f *prepaidFixture, team, actor uuid.UUID) *gin.Engine {
	t.Helper()
	f.exec(`INSERT INTO profile(id,email,provider,provider_id) VALUES($1,$2,'google',$1::uuid::text) ON CONFLICT(id) DO NOTHING`, actor, actor.String()+"@example.com")
	f.exec(`INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active') ON CONFLICT DO NOTHING`, team, actor)
	f.exec(`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, actor, team)
	f.h.Config.AppAllowedOrigins = []string{"https://console.example.com"}
	r := gin.New()
	r.GET("/billing/prepaid", func(c *gin.Context) {
		c.Set("team_id", team.String())
		c.Set("actor_id", actor)
		f.h.GetPrepaidCredit(c)
	})
	r.POST("/billing/prepaid/checkout", func(c *gin.Context) {
		c.Set("team_id", team.String())
		c.Set("actor_id", actor)
		f.h.CreatePrepaidCheckout(c)
	})
	return r
}

func managePrepaidFixtureTeam(t *testing.T, f *prepaidFixture) func() {
	t.Helper()
	authority, org := uuid.New(), uuid.New()
	namespace := "qa-" + uuid.NewString()
	f.exec(`INSERT INTO qm_team_service_authority(namespace,authority_id,home_region) VALUES($1,$2,'use')`, namespace, authority)
	f.exec(`INSERT INTO qm_organization_teams(namespace,qm_org_id,idempotency_key,authority_id,team_id,home_region) VALUES($1,$2,$3,$4,$5,'use')`, namespace, org, "qm-org:v1:"+org.String(), authority, f.team)
	return func() {
		f.exec(`UPDATE qm_organization_teams SET deleted_at=clock_timestamp() WHERE namespace=$1 AND qm_org_id=$2`, namespace, org)
	}
}

func prepaidOperationPost(r *gin.Engine, req prepaidCheckoutBody) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/billing/prepaid/checkout", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, request)
	return rec
}

func TestPrepaidOperationConcurrentRetryAndBinding(t *testing.T) {
	f := newPrepaidFixture(t)
	actor := uuid.New()
	r := prepaidOperationRouter(t, f, f.team, actor)
	capability := httptest.NewRecorder()
	r.ServeHTTP(capability, httptest.NewRequest(http.MethodGet, "/billing/prepaid", nil))
	var summary struct {
		Supported bool `json:"checkout_idempotency_supported"`
	}
	if capability.Code != 200 || json.Unmarshal(capability.Body.Bytes(), &summary) != nil || !summary.Supported {
		t.Fatalf("checkout capability unavailable: %d %s", capability.Code, capability.Body)
	}
	req := prepaidCheckoutBody{OperationID: uuid.New(), AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
	done := make(chan *httptest.ResponseRecorder, 4)
	for range 4 {
		go func() { done <- prepaidOperationPost(r, req) }()
	}
	var session string
	for range 4 {
		rec := <-done
		var got prepaidOperationResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.PurchaseID != req.OperationID || got.ID == "" || got.State != "pending" {
			t.Fatalf("checkout replay: %d %s", rec.Code, rec.Body)
		}
		if session != "" && session != got.ID {
			t.Fatalf("created two sessions %s %s", session, got.ID)
		}
		session = got.ID
	}
	var count int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_purchase WHERE team_id=$1`, f.team).Scan(&count); err != nil || count != 1 {
		t.Fatalf("purchase count %d: %v", count, err)
	}
	f.mu.Lock()
	sessions := len(f.sessions)
	f.mu.Unlock()
	if sessions != 1 {
		t.Fatalf("provider sessions %d", sessions)
	}
	for _, change := range []func(*prepaidCheckoutBody){
		func(p *prepaidCheckoutBody) { p.AmountCents = 1000 },
		func(p *prepaidCheckoutBody) { p.SuccessURL += "?other=1" },
		func(p *prepaidCheckoutBody) { p.CancelURL += "?other=1" },
	} {
		bad := req
		change(&bad)
		if rec := prepaidOperationPost(r, bad); rec.Code != 409 {
			t.Fatalf("mismatch accepted: %d %s", rec.Code, rec.Body)
		}
	}
	f.h.Config.AppAllowedOrigins = []string{"https://replacement.example.com"}
	fresh := req
	fresh.OperationID = uuid.New()
	if rec := prepaidOperationPost(r, fresh); rec.Code != 400 {
		t.Fatalf("fresh removed origin accepted: %d %s", rec.Code, rec.Body)
	}
	if err := f.h.bindPrepaidCheckoutOperation(t.Context(), f.team, actor, fresh); err != nil {
		t.Fatal(err)
	}
	if rec := prepaidOperationPost(r, fresh); rec.Code != 400 {
		t.Fatalf("unused binding bypassed policy: %d %s", rec.Code, rec.Body)
	}
	changed := req
	changed.SuccessURL = "https://replacement.example.com/ok"
	if rec := prepaidOperationPost(r, changed); rec.Code != 409 {
		t.Fatalf("accepted binding changed returns: %d %s", rec.Code, rec.Body)
	}
	other, err := f.h.DB.CreateTeam(t.Context(), "operation-other-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	otherRouter := prepaidOperationRouter(t, f, other.ID, actor)
	if rec := prepaidOperationPost(otherRouter, req); rec.Code != 409 {
		t.Fatalf("cross-team operation accepted: %d %s", rec.Code, rec.Body)
	}
	otherActorRouter := prepaidOperationRouter(t, f, f.team, uuid.New())
	if rec := prepaidOperationPost(otherActorRouter, req); rec.Code != 409 {
		t.Fatalf("cross-actor operation accepted: %d %s", rec.Code, rec.Body)
	}
	f.h.Config.AppAllowedOrigins = []string{"https://replacement.example.com"}
	setPricingVersion(t, f.h, "legacy")
	if rec := prepaidOperationPost(r, req); rec.Code != 200 {
		t.Fatalf("accepted checkout lost after switch: %d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	f.sessions[session]["status"] = "expired"
	f.mu.Unlock()
	rec := prepaidOperationPost(r, req)
	var closed prepaidOperationResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &closed) != nil || closed.State != "failed" || closed.URL != "" {
		t.Fatalf("expired operation: %d %s", rec.Code, rec.Body)
	}
	rec = prepaidOperationPost(r, req)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &closed) != nil || closed.State != "failed" {
		t.Fatalf("closed replay: %d %s", rec.Code, rec.Body)
	}
}

func TestPrepaidOperationRecoversLostProviderReply(t *testing.T) {
	f := newPrepaidFixture(t)
	var dropped atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/checkout/sessions" && r.Method == http.MethodPost && !dropped.Swap(true) {
			rec := httptest.NewRecorder()
			f.serve(rec, r)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		f.serve(w, r)
	}))
	defer srv.Close()
	f.client.baseURL = srv.URL
	f.client.httpClient = srv.Client()
	r := prepaidOperationRouter(t, f, f.team, uuid.New())
	req := prepaidCheckoutBody{OperationID: uuid.New(), AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
	first := prepaidOperationPost(r, req)
	if first.Code != http.StatusBadGateway {
		t.Fatalf("expected lost reply, got %d %s", first.Code, first.Body)
	}
	defer managePrepaidFixtureTeam(t, f)()
	retry := prepaidOperationPost(r, req)
	var got prepaidOperationResponse
	if retry.Code != 200 || json.Unmarshal(retry.Body.Bytes(), &got) != nil || got.ID == "" || got.PurchaseID != req.OperationID {
		t.Fatalf("lost reply recovery: %d %s", retry.Code, retry.Body)
	}
	f.mu.Lock()
	count := len(f.sessions)
	f.mu.Unlock()
	if count != 1 {
		t.Fatalf("recovery duplicated provider session: %d", count)
	}
	f.mu.Lock()
	pi := prepaidPaymentIntent{ID: "pi_" + uuid.NewString(), Status: "succeeded", Amount: 500, AmountReceived: 500, Currency: "usd", Customer: f.customer, Metadata: map[string]string{"prepaid_purchase_id": req.OperationID.String()}}
	f.intents[pi.ID] = pi
	f.sessions[got.ID]["status"], f.sessions[got.ID]["payment_intent"] = "complete", pi.ID
	f.mu.Unlock()
	for range 2 {
		if err := f.h.settlePrepaidPurchase(t.Context(), f.client, req.OperationID); err != nil {
			t.Fatalf("managed accepted later purchase fulfillment: %v", err)
		}
	}
	rec := prepaidOperationPost(r, req)
	var credited prepaidOperationResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &credited) != nil || credited.State != "credited" || credited.URL != "" {
		t.Fatalf("managed later credit replay: %d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	grants := len(f.grantPosts)
	f.mu.Unlock()
	if grants != 1 {
		t.Fatalf("managed later purchase grant count: %d", grants)
	}

}

func TestPrepaidOperationFirstCheckoutUsesCallerPurchaseIdentity(t *testing.T) {
	f := newPrepaidFixture(t)
	actor := uuid.New()
	r := prepaidOperationRouter(t, f, f.team, actor)
	f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
	f.exec(`UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL WHERE team_id=$1`, f.team)
	f.exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, f.team)
	req := prepaidCheckoutBody{OperationID: uuid.New(), AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
	rec := prepaidOperationPost(r, req)
	var got prepaidOperationResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.ID == "" || got.PurchaseID != req.OperationID {
		t.Fatalf("first checkout identity: %d %s", rec.Code, rec.Body)
	}
	var purchase uuid.UUID
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_prepaid_purchase WHERE team_id=$1 AND checkout_session_id=$2`, f.team, got.ID).Scan(&purchase); err != nil || purchase != req.OperationID {
		t.Fatalf("first purchase binding %s: %v", purchase, err)
	}
	retry := prepaidOperationPost(r, req)
	var replay prepaidOperationResponse
	if retry.Code != 200 || json.Unmarshal(retry.Body.Bytes(), &replay) != nil || replay.ID != got.ID {
		t.Fatalf("first checkout retry: %d %s", retry.Code, retry.Body)
	}
}

func TestPrepaidOperationFirstCheckoutLostReplyRestoresAssociation(t *testing.T) {
	for _, managedAt := range []string{"paid", "credited"} {
		t.Run(managedAt, func(t *testing.T) { testPrepaidFirstCheckoutAssociation(t, managedAt) })
	}
}

func testPrepaidFirstCheckoutAssociation(t *testing.T, managedAt string) {
	f, _ := prepaidPlanFixture(t)
	actor := uuid.New()
	r := prepaidOperationRouter(t, f, f.team, actor)
	f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
	f.exec(`UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL WHERE team_id=$1`, f.team)
	f.exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, f.team)
	var dropped atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/checkout/sessions" && r.Method == http.MethodPost && !dropped.Swap(true) {
			rec := httptest.NewRecorder()
			f.serve(rec, r)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		f.serve(w, r)
	}))
	defer srv.Close()
	f.client.baseURL = srv.URL
	f.client.httpClient = srv.Client()
	req := prepaidCheckoutBody{OperationID: uuid.New(), AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
	if rec := prepaidOperationPost(r, req); rec.Code != 502 {
		t.Fatalf("first lost reply: %d %s", rec.Code, rec.Body)
	}
	var initial bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT a.checkout_session_id IS NULL AND p.checkout_session_id IS NULL AND a.checkout_initializing_at IS NOT NULL FROM team_billing_account a JOIN billing_prepaid_purchase p USING(team_id) WHERE p.id=$1`, req.OperationID).Scan(&initial); err != nil || !initial {
		t.Fatalf("lost-response precondition: %v %v", initial, err)
	}
	f.h.Config.AppAllowedOrigins = []string{"https://replacement.example.com"}
	done := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { done <- prepaidOperationPost(r, req) }()
	}
	var session string
	for range 2 {
		rec := <-done
		var got prepaidOperationResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.ID == "" || got.PurchaseID != req.OperationID {
			t.Fatalf("first recovery: %d %s", rec.Code, rec.Body)
		}
		if session != "" && session != got.ID {
			t.Fatal("first recovery duplicated session")
		}
		session = got.ID
	}
	var bound bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT a.checkout_session_id=$2 AND p.checkout_session_id=$2 AND a.checkout_may_exist FROM team_billing_account a JOIN billing_prepaid_purchase p USING(team_id) WHERE p.id=$1`, req.OperationID, session).Scan(&bound); err != nil || !bound {
		t.Fatalf("both associations not restored: %v %v", bound, err)
	}
	f.mu.Lock()
	metadata := f.sessions[session]["metadata"].(map[string]string)
	generation := metadata["checkout_generation"]
	f.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	event := func(kind string, obj any) stripeEventEnvelope {
		raw, _ := json.Marshal(obj)
		e := stripeEventEnvelope{ID: "evt_" + uuid.NewString(), Type: kind, Created: stripeEventTimestamp(now.Unix()), Data: stripeEventEnvelopeData{Object: raw}}
		payload, _ := json.Marshal(e)
		f.exec(`INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES($1,$2,$3)`, e.ID, e.Type, payload)
		return e
	}
	sub := event("customer.subscription.created", map[string]any{"id": f.sub, "customer": f.customer, "status": "active", "current_period_start": now.Unix(), "current_period_end": now.AddDate(0, 1, 0).Unix(), "metadata": map[string]string{"activation_user_id": actor.String(), "checkout_generation": generation}})
	if err := f.h.processRecordedStripeWebhook(t.Context(), sub); !errors.Is(err, errStripeCheckoutAssociationPending) {
		t.Fatalf("first subscription event should await completion: %v", err)
	}
	invoice := "in_" + uuid.NewString()
	zero := int64(0)
	inv := StripeInvoiceAmounts{ID: invoice, Customer: f.customer, Status: "paid", AmountRemaining: &zero, Currency: "usd"}
	inv.Lines.Data = []StripeInvoiceAmountLine{usageLine("price_cpu", 0), usageLine("price_credit", 500)}
	inv.Lines.Data[0].Parent.SubscriptionItemDetails = &struct {
		Subscription     string `json:"subscription"`
		SubscriptionItem string `json:"subscription_item"`
		Proration        bool   `json:"proration"`
	}{Subscription: f.sub}
	inv.Lines.Data[0].Pricing.PriceDetails.Product = "prod_cpu"
	inv.Lines.Data[1].Pricing.PriceDetails.Product = "prod_credit"
	f.mu.Lock()
	f.invoices[invoice] = inv
	f.products["prod_credit"] = map[string]string{"prepaid_purchase_id": req.OperationID.String()}
	f.sessions[session]["status"] = "complete"
	f.sessions[session]["subscription"] = f.sub
	f.sessions[session]["invoice"] = invoice
	f.mu.Unlock()
	completed := event("checkout.session.completed", map[string]any{"id": session, "customer": f.customer, "subscription": f.sub, "client_reference_id": f.team.String()})
	managedTested := false
	assertSettledWithoutProvider := func(want string) {
		t.Helper()
		if want == managedAt && !managedTested {
			defer managePrepaidFixtureTeam(t, f)()
			managedTested = true
		}
		var requests atomic.Int32
		unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			http.Error(w, "provider unavailable", 503)
		}))
		defer unavailable.Close()
		previousURL, previousClient := f.client.baseURL, f.client.httpClient
		f.client.baseURL, f.client.httpClient = unavailable.URL, unavailable.Client()
		defer func() { f.client.baseURL, f.client.httpClient = previousURL, previousClient }()
		rec := prepaidOperationPost(r, req)
		var got prepaidOperationResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.State != want || got.PurchaseID != req.OperationID || got.URL != "" {
			t.Fatalf("durable %s replay: %d %s", want, rec.Code, rec.Body)
		}
		if requests.Load() != 0 {
			t.Fatalf("settled replay depended on provider: %d requests", requests.Load())
		}
	}
	if err := f.h.processRecordedStripeWebhook(t.Context(), completed); err != nil {
		t.Fatal(err)
	}
	if err := f.h.settleCheckoutPurchase(t.Context(), f.client, req.OperationID); err != nil {
		t.Fatal(err)
	}
	assertSettledWithoutProvider("paid")
	for range 2 {
		if err := f.h.processRecordedStripeWebhook(t.Context(), completed); err != nil {
			t.Fatal("checkout completed reconciliation", err)
		}
		if err := f.h.processRecordedStripeWebhook(t.Context(), sub); err != nil {
			t.Fatal("subscription reconciliation", err)
		}
		if err := f.h.settlePrepaidPurchase(t.Context(), f.client, req.OperationID); err != nil {
			t.Fatal("first purchase settlement", err)
		}
	}
	var settled bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT a.stripe_subscription_id=$2 AND a.checkout_subscription_id=$2 AND a.stripe_subscription_status='active' AND a.stripe_subscription_event_at IS NOT NULL AND a.checkout_initializing_at IS NULL AND a.checkout_session_id IS NULL AND p.payment_state='succeeded' AND p.credit_state='issued' FROM team_billing_account a JOIN billing_prepaid_purchase p USING(team_id) WHERE p.id=$1`, req.OperationID, f.sub).Scan(&settled); err != nil || !settled {
		t.Fatalf("first checkout did not fully settle association/lease/credit: %v %v", settled, err)
	}
	f.mu.Lock()
	sessions, grants := len(f.sessions), len(f.grantPosts)
	f.mu.Unlock()
	if sessions != 1 || grants != 1 {
		t.Fatalf("replay duplicated financial effects: sessions=%d credits=%d", sessions, grants)
	}
	current, ok, err := currentTeamPlan(t.Context(), f.h.Pool, f.team)
	if err != nil || !ok || current.Kind != planKindPrepaid || current.Source != planSourceCreditPurchase {
		t.Fatalf("verified first payment did not assign Starter: %+v %v", current, err)
	}
	assertSettledWithoutProvider("credited")
	replacement := "sub_later_" + uuid.NewString()
	f.exec(`UPDATE team_billing_account SET stripe_subscription_id=$2,checkout_subscription_id=$2 WHERE team_id=$1`, f.team, replacement)
	assertSettledWithoutProvider("credited")
	var retained bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT stripe_subscription_id=$2 AND checkout_subscription_id=$2 AND checkout_initializing_at IS NULL FROM team_billing_account WHERE team_id=$1`, f.team, replacement).Scan(&retained); err != nil || !retained {
		t.Fatalf("settled replay changed later valid association: %v %v", retained, err)
	}
}

func TestPrepaidOperationRecoveryDoesNotOverwriteChangedCheckout(t *testing.T) {
	for _, name := range []string{"newer generation", "other customer", "other actor", "other operation", "newer session", "conflicting purchase session", "expired generation"} {
		t.Run(name, func(t *testing.T) {
			f := newPrepaidFixture(t)
			actor, purchase := uuid.New(), uuid.New()
			generation := time.Now().UTC().Truncate(time.Microsecond)
			_ = prepaidOperationRouter(t, f, f.team, actor)
			boundSession := ""
			if name == "conflicting purchase session" {
				boundSession = "cs_different_" + purchase.String()
			}
			if err := f.h.recordCheckoutPurchase(t.Context(), purchase, f.team, f.customer, actor, 500, boundSession); err != nil {
				t.Fatal(err)
			}
			f.exec(`UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL,checkout_initializing_at=$2,checkout_session_id=NULL,checkout_subscription_id=NULL,checkout_request_key=$3,stripe_checkout_actor_id=$4 WHERE team_id=$1`, f.team, generation, "checkout:original:prepaid-operation:"+purchase.String(), actor)
			switch name {
			case "newer generation":
				f.exec(`UPDATE team_billing_account SET checkout_initializing_at=$2 WHERE team_id=$1`, f.team, generation.Add(time.Minute))
			case "other customer":
				f.exec(`UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, f.team, "cus_changed_"+uuid.NewString())
			case "other actor":
				other := uuid.New()
				_ = prepaidOperationRouter(t, f, f.team, other)
				f.exec(`UPDATE team_billing_account SET stripe_checkout_actor_id=$2,checkout_initializing_at=$3 WHERE team_id=$1`, f.team, other, generation.Add(time.Minute))
			case "other operation":
				f.exec(`UPDATE team_billing_account SET checkout_request_key=$2 WHERE team_id=$1`, f.team, "checkout:other:prepaid-operation:"+uuid.NewString())
			case "newer session":
				f.exec(`UPDATE team_billing_account SET checkout_session_id=$2 WHERE team_id=$1`, f.team, "cs_newer_"+uuid.NewString())
			case "expired generation":
				f.exec(`INSERT INTO stripe_checkout_expiration_evidence(team_id,stripe_customer_id,checkout_generation,checkout_session_id) VALUES($1,$2,$3,'cs_original')`, f.team, f.customer, generation)
			}
			snapshot := func() string {
				t.Helper()
				var raw []byte
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_object('account',to_jsonb(a),'purchase',to_jsonb(p)) FROM team_billing_account a JOIN billing_prepaid_purchase p USING(team_id) WHERE p.id=$1`, purchase).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				return string(raw)
			}
			before := snapshot()
			saved := prepaidCheckoutSession{ID: "cs_original", Mode: "subscription", Status: "open", Customer: f.customer, ClientReferenceID: f.team.String(), Metadata: map[string]string{"activation_user_id": actor.String(), "checkout_generation": generation.Format(time.RFC3339Nano), "prepaid_purchase_id": purchase.String()}}
			if err := f.h.restorePrepaidSubscriptionCheckout(t.Context(), f.team, actor, purchase, f.customer, saved, false); err == nil {
				t.Fatal("changed checkout accepted")
			}
			if after := snapshot(); after != before {
				t.Fatal("recovery changed another checkout or partially published the association")
			}
		})
	}
}

func TestPrepaidSettledOperationRepairsOnlyUnpublishedOriginalLease(t *testing.T) {
	f := newPrepaidFixture(t)
	actor := uuid.New()
	r := prepaidOperationRouter(t, f, f.team, actor)
	req := prepaidCheckoutBody{OperationID: uuid.New(), AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
	generation := time.Now().UTC().Truncate(time.Microsecond)
	saved := prepaidCheckoutSession{ID: "cs_" + uuid.NewString(), Mode: "subscription", Status: "complete", Customer: f.customer, ClientReferenceID: f.team.String(), Subscription: f.sub, Metadata: map[string]string{"activation_user_id": actor.String(), "checkout_generation": generation.Format(time.RFC3339Nano), "prepaid_purchase_id": req.OperationID.String()}}
	if err := f.h.recordCheckoutPurchase(t.Context(), req.OperationID, f.team, f.customer, actor, 500, saved.ID); err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(map[string]any{"amount_cents": 500, "customer": f.customer, "checkout_session": saved})
	f.exec(`UPDATE billing_prepaid_purchase SET payment_state='succeeded',paid_at=clock_timestamp(),payment_evidence=$2 WHERE id=$1`, req.OperationID, proof)
	f.exec(`UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL,checkout_initializing_at=$2,checkout_session_id=NULL,checkout_subscription_id=NULL,checkout_request_key=$3,stripe_checkout_actor_id=$4 WHERE team_id=$1`, f.team, generation, "checkout:original:prepaid-operation:"+req.OperationID.String(), actor)
	var requests atomic.Int32
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "provider unavailable", 503)
	}))
	defer unavailable.Close()
	f.client.baseURL, f.client.httpClient = unavailable.URL, unavailable.Client()
	assertPaid := func() {
		t.Helper()
		rec := prepaidOperationPost(r, req)
		var got prepaidOperationResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.State != "paid" || got.PurchaseID != req.OperationID || got.URL != "" {
			t.Fatalf("settled unpublished association: %d %s", rec.Code, rec.Body)
		}
	}
	assertPaid()
	var repaired bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT checkout_session_id=$2 AND checkout_initializing_at=$3 FROM team_billing_account WHERE team_id=$1`, f.team, saved.ID, generation).Scan(&repaired); err != nil || !repaired {
		t.Fatalf("original unpublished lease was not repaired from durable proof: %v %v", repaired, err)
	}
	newerSession := "cs_newer_" + uuid.NewString()
	f.exec(`UPDATE team_billing_account SET checkout_session_id=$2,checkout_initializing_at=$3,checkout_request_key=$4 WHERE team_id=$1`, f.team, newerSession, generation.Add(time.Minute), "checkout:newer:prepaid-operation:"+uuid.NewString())
	assertPaid()
	var retained bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT checkout_session_id=$2 AND checkout_initializing_at=$3 FROM team_billing_account WHERE team_id=$1`, f.team, newerSession, generation.Add(time.Minute)).Scan(&retained); err != nil || !retained {
		t.Fatalf("settled replay overwrote newer lease: %v %v", retained, err)
	}
	if requests.Load() != 0 {
		t.Fatalf("settled association recovery called unavailable provider %d times", requests.Load())
	}
}

func TestPrepaidOperationManagedAdmissionPreservesAcceptedRecovery(t *testing.T) {
	for _, tc := range []struct {
		name               string
		first, unpublished bool
	}{{"later", false, false}, {"first", true, false}, {"unpublished-first", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPrepaidFixture(t)
			actor := uuid.New()
			r := prepaidOperationRouter(t, f, f.team, actor)
			if tc.first {
				f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
				f.exec(`UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL WHERE team_id=$1`, f.team)
				f.exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, f.team)
			}
			req := prepaidCheckoutBody{OperationID: uuid.New(), AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
			var posts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/v1/checkout/sessions" && request.Method == http.MethodPost && posts.Add(1) == 1 && tc.unpublished {
					f.serve(httptest.NewRecorder(), request)
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				f.serve(w, request)
			}))
			defer srv.Close()
			f.client.baseURL, f.client.httpClient = srv.URL, srv.Client()
			opened := prepaidOperationPost(r, req)
			var original prepaidOperationResponse
			if tc.unpublished {
				if opened.Code != 502 {
					t.Fatalf("lost initial reply: %d %s", opened.Code, opened.Body)
				}
				f.mu.Lock()
				for id := range f.sessions {
					original.ID = id
				}
				f.mu.Unlock()
			} else if opened.Code != 200 || json.Unmarshal(opened.Body.Bytes(), &original) != nil || original.URL == "" {
				t.Fatalf("open: %d %s", opened.Code, opened.Body)
			}
			defer managePrepaidFixtureTeam(t, f)()
			f.h.Config.AppAllowedOrigins = nil
			expected := 200
			if tc.first {
				expected = 202
			}
			if rec := prepaidOperationPost(r, req); rec.Code != expected {
				t.Fatalf("managed accepted replay: %d %s", rec.Code, rec.Body)
			}
			if tc.unpublished {
				var preserved bool
				if err := f.h.Pool.QueryRow(t.Context(), `SELECT a.checkout_initializing_at IS NOT NULL AND a.checkout_session_id IS NULL AND p.checkout_session_id IS NULL AND p.payment_state='uncertain' AND p.credit_state='none' FROM team_billing_account a JOIN billing_prepaid_purchase p USING(team_id) WHERE p.id=$1`, req.OperationID).Scan(&preserved); err != nil || !preserved {
					t.Fatalf("unpublished managed checkout changed: %v %v", preserved, err)
				}
			}
			if posts.Load() != 1 {
				t.Fatalf("managed recovery dispatched another session: %d", posts.Load())
			}
			bad := req
			bad.AmountCents = 1000
			if rec := prepaidOperationPost(r, bad); rec.Code != 409 {
				t.Fatalf("managed mismatch: %d %s", rec.Code, rec.Body)
			}
			otherActor := prepaidOperationRouter(t, f, f.team, uuid.New())
			if rec := prepaidOperationPost(otherActor, req); rec.Code != 409 {
				t.Fatalf("managed actor mismatch: %d %s", rec.Code, rec.Body)
			}
			otherTeam, err := f.h.DB.CreateTeam(t.Context(), "managed-replay-"+uuid.NewString())
			if err != nil {
				t.Fatal(err)
			}
			otherRouter := prepaidOperationRouter(t, f, otherTeam.ID, actor)
			if rec := prepaidOperationPost(otherRouter, req); rec.Code != 409 {
				t.Fatalf("managed team mismatch: %d %s", rec.Code, rec.Body)
			}
			f.h.Config.AppAllowedOrigins = nil
			bad = req
			bad.OperationID = uuid.New()
			if rec := prepaidOperationPost(r, bad); rec.Code != 403 {
				t.Fatalf("managed fresh purchase: %d %s", rec.Code, rec.Body)
			}
			if err := f.h.bindPrepaidCheckoutOperation(t.Context(), f.team, actor, bad); err != nil {
				t.Fatal(err)
			}
			if rec := prepaidOperationPost(r, bad); rec.Code != 403 {
				t.Fatalf("managed unused binding: %d %s", rec.Code, rec.Body)
			}
			provider := f.h.Stripe
			f.h.Stripe = nil
			if rec := prepaidOperationPost(r, req); rec.Code != 202 {
				t.Fatalf("provider disabled pending: %d %s", rec.Code, rec.Body)
			}
			f.h.Stripe = provider
			f.mu.Lock()
			f.sessions[original.ID]["status"] = "expired"
			f.mu.Unlock()
			var closed prepaidOperationResponse
			rec := prepaidOperationPost(r, req)
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &closed) != nil || closed.State != "failed" || closed.URL != "" {
				t.Fatalf("managed terminal: %d %s", rec.Code, rec.Body)
			}
			f.h.Stripe = nil
			if rec := prepaidOperationPost(r, req); rec.Code != 200 {
				t.Fatalf("terminal provider disabled: %d %s", rec.Code, rec.Body)
			}
			f.exec(`DELETE FROM user_role_assignments WHERE user_id=$1 AND team_id=$2`, actor, f.team)
			f.h.authzService().InvalidateTeam(f.team)
			if rec := prepaidOperationPost(r, req); rec.Code != 403 {
				t.Fatalf("replay bypassed permission: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestPrepaidManagedFirstSubscriptionPreservesPaidHoldingBoundary(t *testing.T) {
	f, _ := prepaidPlanFixture(t)
	actor := uuid.New()
	r := prepaidOperationRouter(t, f, f.team, actor)
	f.h.Config.StripeCheckoutPriceIDs = []string{"price_cpu", "price_memory"}
	f.exec(`UPDATE team_billing_account SET stripe_subscription_id=NULL,stripe_subscription_status=NULL WHERE team_id=$1`, f.team)
	f.exec(`INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, f.team)
	req := prepaidCheckoutBody{OperationID: uuid.New(), AmountCents: 500, SuccessURL: "https://console.example.com/ok", CancelURL: "https://console.example.com/cancel"}
	opened := prepaidOperationPost(r, req)
	var original prepaidOperationResponse
	if opened.Code != 200 || json.Unmarshal(opened.Body.Bytes(), &original) != nil || original.URL == "" {
		t.Fatalf("initial checkout: %d %s", opened.Code, opened.Body)
	}
	snapshot := func() string {
		t.Helper()
		var state []byte
		if err := f.h.Pool.QueryRow(t.Context(), `SELECT jsonb_build_object('account',to_jsonb(a),'assignments',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.id) FROM team_plan_assignment p WHERE p.team_id=a.team_id)) FROM team_billing_account a WHERE a.team_id=$1`, f.team).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return string(state)
	}
	before := snapshot()
	defer managePrepaidFixtureTeam(t, f)()
	replay := prepaidOperationPost(r, req)
	var pending prepaidOperationResponse
	if replay.Code != 202 || json.Unmarshal(replay.Body.Bytes(), &pending) != nil || pending.State != "pending" || pending.URL != "" || pending.ID != "" {
		t.Fatalf("managed first checkout exposed payment: %d %s", replay.Code, replay.Body)
	}
	f.mu.Lock()
	generation := f.sessions[original.ID]["metadata"].(map[string]string)["checkout_generation"]
	f.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	event := func(kind string, obj any) stripeEventEnvelope {
		raw, _ := json.Marshal(obj)
		e := stripeEventEnvelope{ID: "evt_" + uuid.NewString(), Type: kind, Created: stripeEventTimestamp(now.Unix()), Data: stripeEventEnvelopeData{Object: raw}}
		payload, _ := json.Marshal(e)
		f.exec(`INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES($1,$2,$3)`, e.ID, e.Type, payload)
		return e
	}
	sub := event("customer.subscription.created", map[string]any{"id": f.sub, "customer": f.customer, "status": "active", "current_period_start": now.Unix(), "current_period_end": now.AddDate(0, 1, 0).Unix(), "metadata": map[string]string{"activation_user_id": actor.String(), "checkout_generation": generation}})
	invoice := "in_" + uuid.NewString()
	zero := int64(0)
	inv := StripeInvoiceAmounts{ID: invoice, Customer: f.customer, Status: "paid", AmountRemaining: &zero, Currency: "usd"}
	inv.Lines.Data = []StripeInvoiceAmountLine{usageLine("price_cpu", 0), usageLine("price_credit", 500)}
	inv.Lines.Data[0].Parent.SubscriptionItemDetails = &struct {
		Subscription     string `json:"subscription"`
		SubscriptionItem string `json:"subscription_item"`
		Proration        bool   `json:"proration"`
	}{Subscription: f.sub}
	inv.Lines.Data[0].Pricing.PriceDetails.Product = "prod_cpu"
	inv.Lines.Data[1].Pricing.PriceDetails.Product = "prod_credit"
	f.mu.Lock()
	f.invoices[invoice] = inv
	f.products["prod_credit"] = map[string]string{"prepaid_purchase_id": req.OperationID.String()}
	f.sessions[original.ID]["status"] = "complete"
	f.sessions[original.ID]["subscription"] = f.sub
	f.sessions[original.ID]["invoice"] = invoice
	f.mu.Unlock()
	completed := event("checkout.session.completed", map[string]any{"id": original.ID, "customer": f.customer, "subscription": f.sub, "client_reference_id": f.team.String()})
	for range 2 {
		if err := f.h.processRecordedStripeWebhook(t.Context(), sub); !errors.Is(err, errStripeCheckoutAssociationPending) {
			t.Fatalf("subscription must remain retryable before association: %v", err)
		}
		if err := f.h.processRecordedStripeWebhook(t.Context(), completed); err == nil || !strings.Contains(err.Error(), "managed teams do not enroll individual subscriptions") {
			t.Fatalf("completion did not retain production managed fence: %v", err)
		}
		if err := f.h.settlePrepaidPurchase(t.Context(), f.client, req.OperationID); !errors.Is(err, errPrepaidPaymentPending) {
			t.Fatalf("paid first purchase did not hold before fulfillment: %v", err)
		}
		var retained bool
		if err := f.h.Pool.QueryRow(t.Context(), `SELECT payment_state='succeeded' AND credit_state='none' AND failure_reason IS NULL AND invoice_id=$2 AND paid_at IS NOT NULL AND payment_evidence->'checkout_session'->>'id'=$3 AND payment_evidence->'invoice'->>'status'='paid' AND plan_snapshot IS NOT NULL FROM billing_prepaid_purchase WHERE id=$1`, req.OperationID, invoice, original.ID).Scan(&retained); err != nil || !retained {
			t.Fatalf("verified cash proof not retained at holding boundary: %v %v", retained, err)
		}
		var events int
		if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM stripe_webhook_event WHERE event_id=ANY($1::text[]) AND processed_at IS NULL AND payload IS NOT NULL`, []string{sub.ID, completed.ID}).Scan(&events); err != nil || events != 2 {
			t.Fatalf("association events lost retryable evidence: %d %v", events, err)
		}
		if after := snapshot(); before != after {
			t.Fatalf("managed paid recovery changed account/lease/assignment: before%s after%s", before, after)
		}
		rec := prepaidOperationPost(r, req)
		var paid prepaidOperationResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &paid) != nil || paid.State != "paid" || paid.URL != "" {
			t.Fatalf("durable cash proof not reportable: %d %s", rec.Code, rec.Body)
		}
	}
	f.mu.Lock()
	sessions, grants := len(f.sessions), len(f.grantPosts)
	f.mu.Unlock()
	if sessions != 1 || grants != 0 {
		t.Fatalf("held checkout produced new effects: sessions=%d grants=%d", sessions, grants)
	}
}
