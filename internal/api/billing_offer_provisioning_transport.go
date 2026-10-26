package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

var offerUsageHoldPath = regexp.MustCompile(`^/v1/subscriptions/sub_[A-Za-z0-9]+$`)

// sendOfferProviderRequest sends one saved request after successful preflight
// and dispatch-marker commit, using the current acceptance guard context. The
// adapter must validate and project the untrusted response before saving a receipt.
func (c *stripeHTTPClient) sendOfferProviderRequest(ctx context.Context, r provisioning.SavedRequest) (json.RawMessage, error) {
	if r.State != "dispatched" || r.DispatchedAt == nil {
		return nil, provisioning.ErrConflict
	}
	if err := c.validateOfferProviderRequest(r); err != nil {
		return nil, err
	}
	return c.offerProviderHTTP(ctx, r.Request.Method, r.Request.Path, r.Request.Payload, r.Key, r.Offer.APIVersion)
}

func (c *stripeHTTPClient) validateOfferProviderRequest(r provisioning.SavedRequest) error {
	if c == nil || c.secretKey == "" || c.httpClient == nil {
		return provisioning.ErrUnavailable
	}
	validPath := false
	switch r.Step {
	case provisioning.Customer:
		validPath = r.Request.Path == "/v1/customers"
	case provisioning.Waiver:
		validPath = r.Request.Path == "/v1/coupons"
	case provisioning.Fee, provisioning.Usage:
		validPath = r.Request.Path == "/v1/subscriptions"
	case provisioning.UsageHold:
		validPath = offerUsageHoldPath.MatchString(r.Request.Path)
	}
	if !validPath || r.OperationID == uuid.Nil || r.Offer.AcceptanceID == uuid.Nil || r.Key != fmt.Sprintf("offer-provisioning/%s/%s/v1", r.OperationID, r.Step) || r.Request.Method != http.MethodPost || r.Request.Payload == "" || len(r.Request.Payload) > 128*1024 || r.Request.SHA256 != provisioning.NewRequest(r.Request.Path, r.Request.Payload).SHA256 || r.Offer.Merchant == "" || r.Offer.APIVersion == "" || c.apiVersion != r.Offer.APIVersion {
		return provisioning.ErrConflict
	}
	return nil
}

// preflightOfferProviderRequest is retryable and runs before the dispatch marker.
// The adapter retains this immutable client through the subsequent single POST.
func (c *stripeHTTPClient) preflightOfferProviderRequest(ctx context.Context, r provisioning.SavedRequest) error {
	if r.State != "prepared" || r.DispatchedAt != nil {
		return provisioning.ErrConflict
	}
	if err := c.validateOfferProviderRequest(r); err != nil {
		return err
	}
	// Account and mode belong to the frozen operation, not the current key's
	// ambient defaults. Check both using this exact client's credentials.
	account, err := c.offerProviderHTTP(ctx, http.MethodGet, "/v1/account", "", "", r.Offer.APIVersion)
	if err != nil {
		return err
	}
	var identity struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(account, &identity) != nil || identity.ID != r.Offer.Merchant {
		return provisioning.ErrConflict
	}
	balance, err := c.offerProviderHTTP(ctx, http.MethodGet, "/v1/balance", "", "", r.Offer.APIVersion)
	if err != nil {
		return err
	}
	var mode struct {
		Live *bool `json:"livemode"`
	}
	if json.Unmarshal(balance, &mode) != nil || mode.Live == nil || *mode.Live != r.Offer.Live {
		return provisioning.ErrConflict
	}
	return nil
}

func (c *stripeHTTPClient) offerProviderHTTP(ctx context.Context, method, path, body, key, version string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, strings.NewReader(body))
	if err != nil {
		return nil, provisioning.ErrConflict
	}
	// Even with an idempotency header, net/http must not replay a POST after a
	// reused connection fails. A nonempty saved body and nil GetBody forbid that.
	req.GetBody = nil
	req.SetBasicAuth(c.secretKey, "")
	req.Header.Set("Stripe-Version", version)
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Idempotency-Key", key)
	}
	client := *c.httpClient
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		// Do not leak provider bodies, URLs, keys or transport error text.
		return nil, provisioning.ErrUnknown
	}
	defer response.Body.Close()
	const maxResponse = 1024 * 1024
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, provisioning.ErrUnknown
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, provisioning.ErrUnknown
	}
	return raw, nil
}
