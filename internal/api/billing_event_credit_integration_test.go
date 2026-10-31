//go:build integration

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestEventPromotionCreditIsQueuedOnceAndIssuedOnce(t *testing.T) {
	f := newEntitlementFixture(t)
	h, ctx := f.h, t.Context()
	team, contract, customer := f.c.TeamID, f.c.ID, f.c.CustomerID
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	active, label := "promo_"+suffix, "event-"+suffix[:12]
	exec(`INSERT INTO billing_event_promotion(promotion_code,label,credit_cents) VALUES($1,$2,8000)`, active, label)
	queue := func(code string) {
		t.Helper()
		tx, err := h.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err = recordEventCredit(ctx, tx, team, contract, customer, code); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	queued := func() (n int) {
		t.Helper()
		if err := h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_event_credit WHERE team_id=$1`, team).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, code := range []string{"", "promo_unknown"} {
		if queue(code); queued() != 0 {
			t.Fatalf("code %q queued credit", code)
		}
	}
	queue(active)
	queue(active)
	if queued() != 1 {
		t.Fatalf("queued %d credits, want 1", queued())
	}

	// The key matches event_credit.py: sha256 of json.dumps([team, label]).
	sum := sha256.Sum256([]byte(`["` + team.String() + `", "` + label + `"]`))
	wantKey := "event-credit-" + hex.EncodeToString(sum[:])
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/billing/credit_grants" {
			data := []any{}
			if posts.Load() > 0 {
				data = append(data, map[string]any{"id": "credgr_event", "customer": customer, "category": "promotional", "priority": 50,
					"amount":               map[string]any{"type": "monetary", "monetary": map[string]any{"currency": "usd", "value": 8000}},
					"applicability_config": map[string]any{"scope": map[string]any{"price_type": "metered"}},
					"metadata":             map[string]string{"event_label": label, "team_id": team.String()}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "has_more": false})
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/billing/credit_grants" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		posts.Add(1)
		_ = r.ParseForm()
		want := map[string]string{"customer": customer, "category": "promotional", "amount[monetary][value]": "8000", "amount[monetary][currency]": "usd",
			"priority": "50", "applicability_config[scope][price_type]": "metered", "metadata[event_label]": label, "metadata[team_id]": team.String()}
		for k, v := range want {
			if r.Form.Get(k) != v {
				t.Errorf("grant %s=%q, want %q", k, r.Form.Get(k), v)
			}
		}
		if r.Form.Get("expires_at") != "" || r.Header.Get("Idempotency-Key") != wantKey {
			t.Errorf("grant expiry %q or key %q", r.Form.Get("expires_at"), r.Header.Get("Idempotency-Key"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "credgr_event", "customer": customer, "category": "promotional"})
	}))
	defer srv.Close()
	client := &stripeHTTPClient{baseURL: srv.URL, apiVersion: "2026-07-29.dahlia", httpClient: srv.Client()}

	for range 2 {
		if err := h.issueDueEventCredits(ctx, client); err != nil {
			t.Fatal(err)
		}
	}
	var state, grant string
	if err := h.Pool.QueryRow(ctx, `SELECT state,stripe_credit_grant_id FROM billing_event_credit WHERE contract_id=$1`, contract).Scan(&state, &grant); err != nil {
		t.Fatal(err)
	}
	if state != "issued" || grant != "credgr_event" || posts.Load() != 1 {
		t.Fatalf("state=%s grant=%s posts=%d", state, grant, posts.Load())
	}
}
