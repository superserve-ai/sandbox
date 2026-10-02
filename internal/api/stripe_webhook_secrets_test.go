package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/superserve-ai/sandbox/internal/config"
)

func TestVerifyStripeWebhookSignatureWithSecretsAcceptsEitherDestination(t *testing.T) {
	now := time.Date(2026, 8, 19, 16, 0, 0, 0, time.UTC)
	payload := []byte(`{"id":"evt_test","type":"customer.subscription.updated"}`)
	const snapshotSecret = "whsec_snapshot"
	const thinSecret = "whsec_thin"

	for name, test := range map[string]struct {
		secret  string
		secrets []string
	}{
		"snapshot-only": {secret: snapshotSecret, secrets: []string{snapshotSecret, ""}},
		"thin-only":     {secret: thinSecret, secrets: []string{"", thinSecret}},
	} {
		t.Run(name, func(t *testing.T) {
			signature := stripeWebhookTestSignature(payload, now, test.secret)
			if err := verifyStripeWebhookSignatureWithSecrets(payload, signature, now, test.secrets...); err != nil {
				t.Fatalf("verify dual webhook signature: %v", err)
			}
		})
	}
}

func TestVerifyStripeWebhookSignatureWithSecretsRejectsUnknownSecret(t *testing.T) {
	now := time.Date(2026, 8, 19, 16, 0, 0, 0, time.UTC)
	payload := []byte(`{"id":"evt_test","type":"v1.billing.meter.error_report_triggered"}`)
	signature := stripeWebhookTestSignature(payload, now, "whsec_unknown")

	if err := verifyStripeWebhookSignatureWithSecrets(payload, signature, now, "whsec_snapshot", "whsec_thin"); err == nil {
		t.Fatal("expected signature signed by neither configured destination to be rejected")
	}
}

func TestVerifyStripeWebhookSignatureWithSecretsRequiresConfiguration(t *testing.T) {
	now := time.Date(2026, 8, 19, 16, 0, 0, 0, time.UTC)
	if err := verifyStripeWebhookSignatureWithSecrets([]byte(`{}`), "", now, "", "  "); err == nil {
		t.Fatal("expected missing webhook secrets to fail closed")
	}
}

func TestHandleStripeWebhookAuthenticatesEitherConfiguredSecret(t *testing.T) {
	now := time.Date(2026, 8, 19, 16, 0, 0, 0, time.UTC)
	payload := []byte(`{"id":"evt_handler_auth","type":"customer.subscription.updated"}`)
	const snapshotSecret = "whsec_snapshot"
	const thinSecret = "whsec_thin"

	h := &Handlers{
		Config: &config.Config{
			StripeWebhookSecret:           snapshotSecret,
			StripeMeterErrorWebhookSecret: thinSecret,
		},
		Now: func() time.Time { return now },
	}
	r := gin.New()
	r.POST("/stripe/webhook", h.HandleStripeWebhook)

	for name, secret := range map[string]string{"snapshot": snapshotSecret, "thin": thinSecret} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
			req.Header.Set("Stripe-Signature", stripeWebhookTestSignature(payload, now, secret))
			resp := httptest.NewRecorder()
			r.ServeHTTP(resp, req)
			if resp.Code != http.StatusServiceUnavailable {
				t.Fatalf("configured %s signature: status = %d, want %d", name, resp.Code, http.StatusServiceUnavailable)
			}
		})
	}

	t.Run("unknown", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/stripe/webhook", strings.NewReader(string(payload)))
		req.Header.Set("Stripe-Signature", stripeWebhookTestSignature(payload, now, "whsec_unknown"))
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("unknown signature: status = %d, want %d", resp.Code, http.StatusUnauthorized)
		}
	})
}

func stripeWebhookTestSignature(payload []byte, ts time.Time, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.", ts.Unix())))
	mac.Write(payload)
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(mac.Sum(nil)))
}
