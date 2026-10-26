package api

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
)

func TestStripeGrantRejectionRequiresValidationProof(t *testing.T) {
	for _, mode := range []string{"validation", "raw_status", "idempotency", "in_progress", "server", "auth", "replayed", "proxy", "redirect", "missing_request_id", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/billing/credit_grants", nil)
			req.Header.Set("Idempotency-Key", "grant-key")
			resp := &http.Response{StatusCode: 400, Request: req, Header: http.Header{"Request-Id": {"req_validation"}}, TLS: &tls.ConnectionState{HandshakeComplete: true, VerifiedChains: [][]*x509.Certificate{{{}}}}}
			body := []byte(`{"error":{"type":"invalid_request_error","code":"parameter_unknown"}}`)
			switch mode {
			case "raw_status":
				body = []byte(`{"error":{"message":"bad request"}}`)
			case "idempotency":
				body = []byte(`{"error":{"type":"idempotency_error","code":"parameter_unknown"}}`)
			case "in_progress":
				resp.StatusCode = 409
			case "server":
				resp.StatusCode = 503
			case "auth":
				resp.StatusCode = 401
			case "replayed":
				resp.Header.Set("Idempotent-Replayed", "true")
			case "proxy":
				resp.TLS = nil
			case "redirect":
				redirected := req.Clone(t.Context())
				redirected.URL.Host = "example.test"
				resp.Request = redirected
			case "missing_request_id":
				resp.Header.Del("Request-Id")
			case "malformed":
				body = []byte("{")
			}
			proof := classifyStripeGrantRejection(req, resp, body, "amount=1", "grant-key")
			if (proof != nil) != (mode == "validation") {
				t.Fatal("incorrect no-effect classification", proof)
			}
		})
	}
}
