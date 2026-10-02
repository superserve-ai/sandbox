package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var ErrStripeCheckoutSessionNotFound = errors.New("stripe checkout session was not found")

type StripeRetrievedCheckoutSession struct {
	ID                string            `json:"id"`
	URL               string            `json:"url"`
	CustomerID        string            `json:"customer"`
	ClientReferenceID string            `json:"client_reference_id"`
	Status            string            `json:"status"`
	Mode              string            `json:"mode"`
	ExpiresAt         int64             `json:"expires_at"`
	Metadata          map[string]string `json:"metadata"`
}

type stripeCheckoutSessionRetriever interface {
	RetrieveCheckoutSession(context.Context, string) (StripeRetrievedCheckoutSession, error)
}

func (c *stripeHTTPClient) RetrieveCheckoutSession(ctx context.Context, sessionID string) (StripeRetrievedCheckoutSession, error) {
	if !strings.HasPrefix(sessionID, "cs_") || len(sessionID) <= len("cs_") {
		return StripeRetrievedCheckoutSession{}, fmt.Errorf("invalid Stripe checkout session ID")
	}
	for _, ch := range sessionID {
		if ch != '_' && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
			return StripeRetrievedCheckoutSession{}, fmt.Errorf("invalid Stripe checkout session ID")
		}
	}
	if c == nil || c.httpClient == nil {
		return StripeRetrievedCheckoutSession{}, fmt.Errorf("stripe billing client is not configured")
	}
	if c.apiVersion == "" {
		return StripeRetrievedCheckoutSession{}, fmt.Errorf("stripe API version is not configured")
	}

	path := "/v1/checkout/sessions/" + sessionID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return StripeRetrievedCheckoutSession{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("Stripe-Version", c.apiVersion)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return StripeRetrievedCheckoutSession{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return StripeRetrievedCheckoutSession{}, ErrStripeCheckoutSessionNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StripeRetrievedCheckoutSession{}, fmt.Errorf("stripe GET checkout session returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return StripeRetrievedCheckoutSession{}, err
	}
	var session StripeRetrievedCheckoutSession
	if err := json.Unmarshal(body, &session); err != nil {
		return StripeRetrievedCheckoutSession{}, fmt.Errorf("decode Stripe checkout session: %w", err)
	}
	if session.ID == "" {
		return StripeRetrievedCheckoutSession{}, fmt.Errorf("Stripe checkout session response has no ID")
	}
	return session, nil
}
