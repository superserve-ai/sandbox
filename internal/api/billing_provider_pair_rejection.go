package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

type stripeGrantRejection struct {
	Status         int    `json:"status"`
	Type           string `json:"type"`
	Code           string `json:"code"`
	RequestID      string `json:"request_id"`
	IdempotencyKey string `json:"idempotency_key"`
	form           string
}

// Only documented validation failures before execution prove no grant exists.
// Status alone, cached errors and idempotency conflicts cannot resolve an attempt.
func classifyStripeGrantRejection(req *http.Request, resp *http.Response, body []byte, form, key string) *stripeGrantRejection {
	if req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Host != "api.stripe.com" || req.URL.Path != "/v1/billing/credit_grants" || key == "" || req.Header.Get("Idempotency-Key") != key ||
		resp.Request == nil || resp.Request.Method != req.Method || resp.Request.URL.String() != req.URL.String() ||
		resp.Request.Header.Get("Idempotency-Key") != key ||
		resp.TLS == nil || !resp.TLS.HandshakeComplete || len(resp.TLS.VerifiedChains) == 0 ||
		resp.StatusCode != http.StatusBadRequest || !strings.HasPrefix(resp.Header.Get("Request-Id"), "req_") || len(resp.Header.Get("Request-Id")) <= 4 {
		return nil
	}
	if replayed := resp.Header.Get("Idempotent-Replayed"); replayed != "" && replayed != "false" {
		return nil
	}
	var payload struct {
		Error struct{ Type, Code string } `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Error.Type != "invalid_request_error" {
		return nil
	}
	switch payload.Error.Code {
	case "parameter_missing", "parameter_unknown", "parameter_invalid_integer":
		return &stripeGrantRejection{Status: resp.StatusCode, Type: payload.Error.Type, Code: payload.Error.Code, RequestID: resp.Header.Get("Request-Id"), IdempotencyKey: key, form: form}
	default:
		return nil
	}
}
