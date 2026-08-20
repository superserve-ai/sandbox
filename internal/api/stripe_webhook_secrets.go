package api

import (
	"errors"
	"strings"
	"time"
)

var errStripeWebhookSecretsNotConfigured = errors.New("Stripe webhook signing secrets are not configured")

// verifyStripeWebhookSignatureWithSecrets verifies a webhook request against
// each configured Stripe destination secret. Stripe assigns a distinct whsec
// value to every event destination, so the shared /stripe/webhook endpoint must
// accept both the snapshot lifecycle destination and the thin meter-error
// destination without conflating or persisting those secrets.
func verifyStripeWebhookSignatureWithSecrets(payload []byte, signature string, now time.Time, secrets ...string) error {
	configured := 0
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		configured++
		if err := verifyStripeWebhookSignature(payload, signature, secret, now); err == nil {
			return nil
		}
	}
	if configured == 0 {
		return errStripeWebhookSecretsNotConfigured
	}
	return errors.New("invalid Stripe webhook signature")
}
