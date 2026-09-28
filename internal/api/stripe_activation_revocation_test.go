package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

func activationRevocationGrant(teamID uuid.UUID) billing.StripeActivationGrant {
	var g billing.StripeActivationGrant
	g.ID, g.Customer, g.Category = "cred/grant", "cus_example", "promotional"
	g.Amount.Type, g.Amount.Monetary.Currency, g.Amount.Monetary.Value = "monetary", "usd", 9500
	g.ApplicabilityConfig.Scope.PriceType = "metered"
	g.Metadata = map[string]string{"activation_identity": "stripe-activation-credit-" + teamID.String()}
	return g
}

func TestStripeActivationRevocationTransport(t *testing.T) {
	for _, name := range []string{"usable", "consumed", "expired", "voided", "reserved", "transient", "ambiguous", "partial", "missing_balance", "wrong_customer", "wrong_amount", "wrong_category", "wrong_currency", "wrong_scope", "conflicting_identity", "wrong_id"} {
		t.Run(name, func(t *testing.T) {
			teamID := uuid.New()
			grant := activationRevocationGrant(teamID)
			stamp := time.Now().Add(-time.Hour).Unix()
			available, ledger := int64(9500), int64(9500)
			switch name {
			case "consumed":
				available, ledger = 0, 0
			case "reserved":
				available = 0
			case "partial":
				available, ledger = 5000, 5000
			case "expired":
				grant.ExpiresAt = &stamp
			case "voided":
				grant.VoidedAt = &stamp
			case "wrong_customer":
				grant.Customer = "cus_other"
			case "wrong_amount":
				grant.Amount.Monetary.Value = 500
			case "wrong_category":
				grant.Category = "paid"
			case "wrong_currency":
				grant.Amount.Monetary.Currency = "eur"
			case "wrong_scope":
				grant.ApplicabilityConfig.Scope.PriceType = "licensed"
			case "conflicting_identity":
				grant.Metadata["activation_identity"] = "other-promotion"
			case "wrong_id":
				grant.ID = "cred_other"
			}
			voids := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer sk_test_example" || r.Header.Get("Stripe-Version") != "2025-06-30" {
					t.Error("missing authenticated version-pinned request")
				}
				switch {
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "credit_grants/"):
					if r.URL.EscapedPath() != "/v1/billing/credit_grants/cred%2Fgrant" {
						t.Errorf("unescaped grant path: %s", r.URL.EscapedPath())
					}
					_ = json.NewEncoder(w).Encode(grant)
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "credit_balance_summary"):
					if r.URL.Query().Get("customer") != "cus_example" || r.URL.Query().Get("filter[type]") != "credit_grant" || r.URL.Query().Get("filter[credit_grant]") != "cred/grant" {
						t.Errorf("unscoped balance read: %s", r.URL)
					}
					if name == "missing_balance" {
						_, _ = w.Write([]byte(`{"customer":"cus_example","balances":[]}`))
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"customer": "cus_example", "balances": []any{map[string]any{
						"available_balance": map[string]any{"monetary": map[string]any{"currency": "usd", "value": available}},
						"ledger_balance":    map[string]any{"monetary": map[string]any{"currency": "usd", "value": ledger}},
					}}})
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/void"):
					voids++
					if r.URL.EscapedPath() != "/v1/billing/credit_grants/cred%2Fgrant/void" || !strings.HasPrefix(r.Header.Get("Idempotency-Key"), "stripe-activation-void-") {
						t.Error("incorrect void identity")
					}
					if name == "transient" {
						http.Error(w, "temporary failure", 503)
						return
					}
					if name == "partial" {
						http.Error(w, "credit grant has been applied to an invoice", 400)
						return
					}
					grant.VoidedAt = &stamp
					if name == "ambiguous" {
						http.Error(w, "response lost after success", 500)
						return
					}
					_ = json.NewEncoder(w).Encode(grant)
				default:
					t.Errorf("unexpected Stripe request: %s %s", r.Method, r.URL)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := &stripeHTTPClient{baseURL: server.URL, secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: server.Client()}
			got, err := client.RevokeActivationCredit(context.Background(), teamID, "cus_example", "cred/grant")
			wantErr := strings.HasPrefix(name, "wrong_") || name == "conflicting_identity" || name == "transient" || name == "partial" || name == "missing_balance"
			if (err != nil) != wantErr {
				t.Fatalf("grant=%q err=%v wantErr=%v", got, err, wantErr)
			}
			if !wantErr && got != "cred/grant" {
				t.Fatalf("grant identity = %q", got)
			}
			wantVoids := 0
			switch name {
			case "usable", "reserved", "transient", "ambiguous", "partial":
				wantVoids = 1
			}
			if voids != wantVoids {
				t.Fatalf("voids=%d want=%d", voids, wantVoids)
			}
		})
	}
}

func TestStripeActivationRevocationIdentityPagination(t *testing.T) {
	for _, scenario := range []string{"unique", "multiple", "missing", "conflict", "incomplete_page"} {
		t.Run(scenario, func(t *testing.T) {
			teamID := uuid.New()
			grant := activationRevocationGrant(teamID)
			var pages int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/billing/credit_grants" {
					t.Errorf("unexpected mutation or request: %s %s", r.Method, r.URL)
					http.NotFound(w, r)
					return
				}
				pages++
				if r.URL.Query().Get("customer") != "cus_example" {
					t.Error("missing customer scope")
				}
				if pages == 1 {
					unrelated := grant
					unrelated.ID, unrelated.Metadata = "cred_manual", nil
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{unrelated}, "has_more": true})
					return
				}
				if r.URL.Query().Get("starting_after") != "cred_manual" {
					t.Error("missing pagination cursor")
				}
				grants := []billing.StripeActivationGrant{grant}
				if scenario == "multiple" {
					other := grant
					other.ID = "cred_second"
					grants = append(grants, other)
				}
				if scenario == "missing" || scenario == "incomplete_page" {
					grants = nil
				}
				if scenario == "conflict" {
					grants[0].Amount.Monetary.Value = 1000
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": grants, "has_more": scenario == "incomplete_page"})
			}))
			defer server.Close()
			client := &stripeHTTPClient{baseURL: server.URL, secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: server.Client()}
			got, err := billing.FindStripeActivationGrant(t.Context(), client.doForm, teamID, "cus_example", "")
			if (err == nil) != (scenario == "unique") {
				t.Fatalf("grant=%v err=%v", got, err)
			}
			if pages != 2 {
				t.Fatalf("pages=%d", pages)
			}
		})
	}
}

func TestStripeCancellationWinsEqualTimestamp(t *testing.T) {
	sub, status, grant := "sub_example", "active", "cred_example"
	at := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	account := db.TeamBillingAccount{StripeSubscriptionID: &sub, StripeSubscriptionStatus: &status, StripeActivationCreditGrantID: &grant, StripeActivationCreditGrantedAt: at, TrialEndedAt: at}
	if shouldSkipEqualTimestampStripeSubscription(account, sub, status, true) {
		t.Fatal("new cancellation was suppressed")
	}
	account.CancelAtPeriodEnd = true
	if !shouldSkipEqualTimestampStripeSubscription(account, sub, status, false) {
		t.Fatal("same-second reversal erased cancellation")
	}
}
