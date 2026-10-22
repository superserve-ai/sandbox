package billing

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
)

// VerifyUnusedStripeActivationGrant excludes credits reserved by draft invoices
// as well as consumed credits. A restored balance is still subject to Stripe's
// void eligibility check; recovery must never fall back to expiration.
func VerifyUnusedStripeActivationGrant(ctx context.Context, request StripeCreditRequest, grant StripeActivationGrant) error {
	if grant.VoidedAt != nil && *grant.VoidedAt > 0 {
		return errors.New("activation grant was already voided before recovery approval")
	}
	available, ledger, err := stripeActivationGrantBalance(ctx, request, grant)
	if err != nil {
		return err
	}
	if available != 9500 || ledger != 9500 {
		return errors.New("activation grant is not fully unused and available; explicit financial reconciliation required")
	}
	return nil
}

// VoidUnusedStripeActivationGrant is called only after durable recovery intent
// and unused evidence have been saved. A terminal read recovers a lost response.
func VoidUnusedStripeActivationGrant(ctx context.Context, request StripeCreditRequest, team uuid.UUID, customer, grantID string) (StripeActivationGrant, error) {
	grant, err := FindStripeActivationGrant(ctx, request, team, customer, grantID)
	if err != nil {
		return grant, err
	}
	if grant.VoidedAt != nil && *grant.VoidedAt > 0 {
		return grant, nil
	}
	if err = VerifyUnusedStripeActivationGrant(ctx, request, grant); err != nil {
		return grant, err
	}
	var result StripeActivationGrant
	err = request(ctx, http.MethodPost, "/v1/billing/credit_grants/"+url.PathEscape(grant.ID)+"/void", url.Values{}, &result, "sponsored-activation-void-"+uuid.NewString())
	if err != nil {
		current, readErr := FindStripeActivationGrant(ctx, request, team, customer, grant.ID)
		if readErr == nil && current.VoidedAt != nil && *current.VoidedAt > 0 {
			return current, nil
		}
		return result, err
	}
	if err = result.verify(team, customer, grant.ID); err != nil {
		return result, err
	}
	if result.VoidedAt == nil || *result.VoidedAt <= 0 {
		return result, errors.New("Stripe did not confirm unused activation grant voiding")
	}
	return result, nil
}
