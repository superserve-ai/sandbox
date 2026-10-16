package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestYCClaimCredentialsAreSeparated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	capture := strings.Repeat("c", 32)
	console := strings.Repeat("s", 32)
	t.Setenv("YC_CLAIM_CAPTURE_TOKEN", capture)
	t.Setenv("YC_CLAIM_CONSOLE_TOKEN", console)
	route := gin.New()
	route.POST("/capture", YCClaimAuth("YC_CLAIM_CAPTURE_TOKEN"), func(c *gin.Context) { c.Status(204) })
	for _, tc := range []struct {
		header string
		want   int
	}{{"Bearer " + capture, 204}, {capture, 401}, {"Bearer " + console, 401}, {"", 401}} {
		r := httptest.NewRequest("POST", "/capture", nil)
		r.Header.Set("Authorization", tc.header)
		w := httptest.NewRecorder()
		route.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("status %d want %d", w.Code, tc.want)
		}
	}
	t.Setenv("YC_CLAIM_CONSOLE_TOKEN", capture)
	r := httptest.NewRequest("POST", "/capture", nil)
	r.Header.Set("Authorization", "Bearer "+capture)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("shared credentials accepted")
	}
}
func TestYCEmailBindsRecipientAndIdempotency(t *testing.T) {
	j := ycMailJob{ClaimID: uuid.New(), MessageID: uuid.New(), Email: "founder@example.test", Token: strings.Repeat("a", 43)}
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		var body struct {
			To   []string `json:"to"`
			Text string   `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.To) != 1 || body.To[0] != j.Email {
			t.Error("recipient changed")
		}
		if !strings.Contains(body.Text, "https://console.example.test/yc/confirm#claim="+j.ClaimID.String()+"&token="+j.Token) {
			t.Error("bound fragment missing")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	for range 2 {
		if err := sendYCClaimMail(context.Background(), server.Client(), server.URL, "https://console.example.test", "synthetic-key", "hello@example.test", j); err != nil {
			t.Fatal(err)
		}
	}
	if len(keys) != 2 || keys[0] != keys[1] || keys[0] == "" {
		t.Fatal("email retry key changed")
	}
}

func TestYCClaimStatusPaymentGate(t *testing.T) {
	for _, tc := range []struct {
		state                                 string
		ready, revoked, failed, payment, term bool
		want                                  string
	}{
		{"approved", false, false, true, true, false, "awaiting_payment_method"},
		{"enrolling", false, false, true, true, false, "awaiting_payment_method"},
		{"active", false, false, false, false, true, "awaiting_payment_method"},
		{"active", true, false, false, false, true, "active"},
		{"active", true, false, true, false, true, "requires_review"},
		{"active", false, false, true, false, true, "requires_review"},
		{"renewed", false, false, true, false, true, "requires_review"},
		{"renewed", true, false, false, false, false, "renewed"},
		{"active", true, false, false, false, false, "activation_pending"},
		{"active", true, true, true, true, true, "requires_review"},
		{"approved", false, false, false, false, false, "activation_pending"},
	} {
		if got := ycClaimDisplayStatus(tc.state, tc.ready, tc.revoked, tc.failed, tc.payment, tc.term); got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
}
