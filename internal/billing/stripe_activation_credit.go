package billing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// StripeCreditRequest uses the caller's authenticated, version-pinned transport.
type StripeCreditRequest func(context.Context, string, string, url.Values, any, string) error

type StripeActivationGrant struct {
	ID       string `json:"id"`
	Customer string `json:"customer"`
	Category string `json:"category"`
	Amount   struct {
		Type     string `json:"type"`
		Monetary struct {
			Currency string `json:"currency"`
			Value    int64  `json:"value"`
		} `json:"monetary"`
	} `json:"amount"`
	ApplicabilityConfig struct {
		Scope struct {
			PriceType string `json:"price_type"`
		} `json:"scope"`
	} `json:"applicability_config"`
	Metadata  map[string]string `json:"metadata"`
	ExpiresAt *int64            `json:"expires_at"`
	VoidedAt  *int64            `json:"voided_at"`
}

func (g StripeActivationGrant) verify(teamID uuid.UUID, customerID, grantID string) error {
	identity := "stripe-activation-credit-" + teamID.String()
	metadata := strings.TrimSpace(g.Metadata["activation_identity"])
	if g.ID == "" || g.Customer != customerID || g.Category != "promotional" ||
		g.Amount.Type != "monetary" || g.Amount.Monetary.Currency != "usd" || g.Amount.Monetary.Value != 9500 ||
		g.ApplicabilityConfig.Scope.PriceType != "metered" ||
		(grantID != "" && g.ID != grantID) || (grantID == "" && metadata != identity) ||
		(metadata != "" && metadata != identity) {
		return errors.New("Stripe activation grant identity, customer, or applicability is unverified")
	}
	return nil
}

// FindStripeActivationGrant never falls back to an amount-only match. Historical
// grants without metadata require their persisted ID; missing IDs require a
// unique identity match across every page, including expired and voided grants.
func FindStripeActivationGrant(ctx context.Context, request StripeCreditRequest, teamID uuid.UUID, customerID, grantID string) (StripeActivationGrant, error) {
	if teamID == uuid.Nil || strings.TrimSpace(customerID) == "" {
		return StripeActivationGrant{}, errors.New("Stripe activation ownership is missing")
	}
	if grantID != "" {
		var grant StripeActivationGrant
		if err := request(ctx, http.MethodGet, "/v1/billing/credit_grants/"+url.PathEscape(grantID), nil, &grant, ""); err != nil {
			return grant, err
		}
		return grant, grant.verify(teamID, customerID, grantID)
	}
	var match StripeActivationGrant
	seen := map[string]bool{}
	cursor := ""
	for {
		path := "/v1/billing/credit_grants?customer=" + url.QueryEscape(customerID) + "&limit=100"
		if cursor != "" {
			path += "&starting_after=" + url.QueryEscape(cursor)
		}
		var page struct {
			Data    []StripeActivationGrant `json:"data"`
			HasMore bool                    `json:"has_more"`
		}
		if err := request(ctx, http.MethodGet, path, nil, &page, ""); err != nil {
			return match, err
		}
		for _, grant := range page.Data {
			if grant.Metadata["activation_identity"] != "stripe-activation-credit-"+teamID.String() {
				continue
			}
			if err := grant.verify(teamID, customerID, ""); err != nil {
				return match, err
			}
			if match.ID != "" {
				return match, errors.New("multiple Stripe activation identity grants")
			}
			match = grant
		}
		if !page.HasMore {
			break
		}
		if len(page.Data) == 0 {
			return match, errors.New("Stripe grant pagination is incomplete")
		}
		cursor = page.Data[len(page.Data)-1].ID
		if cursor == "" || seen[cursor] {
			return match, errors.New("Stripe grant pagination did not advance")
		}
		seen[cursor] = true
	}
	if match.ID == "" {
		return match, errors.New("Stripe activation grant identity is missing")
	}
	return match, nil
}

func stripeActivationGrantReconciled(ctx context.Context, request StripeCreditRequest, grant StripeActivationGrant) (bool, error) {
	if grant.VoidedAt != nil && *grant.VoidedAt > 0 || grant.ExpiresAt != nil && *grant.ExpiresAt <= time.Now().Unix() {
		return true, nil
	}
	return false, nil
}

func stripeActivationGrantBalance(ctx context.Context, request StripeCreditRequest, grant StripeActivationGrant) (available, ledger int64, err error) {
	var summary struct {
		Customer string `json:"customer"`
		Balances []struct {
			Available struct {
				Monetary *struct {
					Currency string `json:"currency"`
					Value    int64  `json:"value"`
				} `json:"monetary"`
			} `json:"available_balance"`
			Ledger struct {
				Monetary *struct {
					Currency string `json:"currency"`
					Value    int64  `json:"value"`
				} `json:"monetary"`
			} `json:"ledger_balance"`
		} `json:"balances"`
	}
	path := "/v1/billing/credit_balance_summary?customer=" + url.QueryEscape(grant.Customer) + "&filter[type]=credit_grant&filter[credit_grant]=" + url.QueryEscape(grant.ID)
	if err := request(ctx, http.MethodGet, path, nil, &summary, ""); err != nil {
		return 0, 0, err
	}
	if summary.Customer != grant.Customer || len(summary.Balances) != 1 {
		return 0, 0, errors.New("Stripe grant balance is unavailable")
	}
	balance := summary.Balances[0]
	if balance.Available.Monetary == nil || balance.Ledger.Monetary == nil || balance.Available.Monetary.Currency != "usd" || balance.Ledger.Monetary.Currency != "usd" {
		return 0, 0, errors.New("Stripe grant balance is unrepresentable")
	}
	// Available zero alone can mean credits reserved by a draft invoice;
	// ledger is the authoritative remaining grant balance.
	return balance.Available.Monetary.Value, balance.Ledger.Monetary.Value, nil
}

func RevokeStripeActivationGrant(ctx context.Context, request StripeCreditRequest, teamID uuid.UUID, customerID, grantID string) (string, error) {
	grant, err := FindStripeActivationGrant(ctx, request, teamID, customerID, grantID)
	if err != nil {
		return "", err
	}
	reconciled, err := stripeActivationGrantReconciled(ctx, request, grant)
	if err != nil {
		return "", err
	}
	if reconciled {
		return grant.ID, nil
	}
	_, ledger, err := stripeActivationGrantBalance(ctx, request, grant)
	if err != nil {
		return "", err
	}
	if ledger < grant.Amount.Monetary.Value {
		return expireStripeActivationGrant(ctx, request, teamID, customerID, grant)
	}
	var voided StripeActivationGrant
	// Stripe caches failed idempotent responses too. A fresh attempt key lets a
	// later webhook retry recover; the terminal grant state prevents re-voiding.
	err = request(ctx, http.MethodPost, "/v1/billing/credit_grants/"+url.PathEscape(grant.ID)+"/void", url.Values{}, &voided, "stripe-activation-void-"+uuid.NewString())
	if err == nil {
		if verifyErr := voided.verify(teamID, customerID, grant.ID); verifyErr != nil {
			return "", verifyErr
		}
		if voided.VoidedAt == nil || *voided.VoidedAt <= 0 {
			return "", errors.New("Stripe did not confirm activation grant voiding")
		}
		return grant.ID, nil
	}
	// A timeout or concurrent void may have succeeded. Only authoritative
	// terminal/consumed evidence can convert that failure into completion.
	current, readErr := FindStripeActivationGrant(ctx, request, teamID, customerID, grant.ID)
	if readErr == nil {
		if done, checkErr := stripeActivationGrantReconciled(ctx, request, current); checkErr == nil && done {
			return grant.ID, nil
		}
		// A grant that was applied to an invoice cannot be voided. Stripe may
		// restore its full balance when that invoice is voided; expiration is
		// the terminal operation that prevents the restored credit from being
		// spendable again.
		if strings.Contains(strings.ToLower(err.Error()), "invoice") || strings.Contains(strings.ToLower(err.Error()), "applied") {
			if expiredID, expireErr := expireStripeActivationGrant(ctx, request, teamID, customerID, current); expireErr == nil {
				return expiredID, nil
			}
		}
	}
	return "", fmt.Errorf("void Stripe activation grant: %w", err)
}

func expireStripeActivationGrant(ctx context.Context, request StripeCreditRequest, teamID uuid.UUID, customerID string, grant StripeActivationGrant) (string, error) {
	var expired StripeActivationGrant
	err := request(ctx, http.MethodPost, "/v1/billing/credit_grants/"+url.PathEscape(grant.ID)+"/expire", url.Values{}, &expired, "stripe-activation-expire-"+uuid.NewString())
	if err == nil {
		if verifyErr := expired.verify(teamID, customerID, grant.ID); verifyErr != nil {
			return "", verifyErr
		}
		if expired.ExpiresAt == nil || *expired.ExpiresAt <= 0 {
			return "", errors.New("Stripe did not confirm activation grant expiration")
		}
		available, ledger, checkErr := stripeActivationGrantBalance(ctx, request, expired)
		if checkErr != nil {
			return "", checkErr
		}
		if available != 0 || ledger != 0 {
			return "", errors.New("Stripe activation grant retains a spendable balance after expiration")
		}
		return grant.ID, nil
	}
	current, readErr := FindStripeActivationGrant(ctx, request, teamID, customerID, grant.ID)
	if readErr == nil {
		if done, checkErr := stripeActivationGrantReconciled(ctx, request, current); checkErr == nil && done {
			return grant.ID, nil
		}
	}
	return "", fmt.Errorf("expire Stripe activation grant: %w", err)
}
