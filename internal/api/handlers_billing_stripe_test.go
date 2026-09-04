package api

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStripeMeterErrorDetailsExtractsThinEventRequest(t *testing.T) {
	payload := json.RawMessage(`{"developer_message_summary":"There is 1 invalid event","reason":{"error_types":[{"sample_errors":[{"error_message":"invalid customer","request":{"idempotency_key":"meter-event:test"}}]}]}}`)
	identifier, eventName, customerID, requestKey, message, err := stripeMeterErrorDetails(payload)
	if err != nil {
		t.Fatal(err)
	}
	if identifier != "" || eventName != "" || customerID != "" {
		t.Fatalf("unexpected direct fields: %q %q %q", identifier, eventName, customerID)
	}
	if requestKey != "meter-event:test" {
		t.Fatalf("request key = %q", requestKey)
	}
	if message != "There is 1 invalid event" {
		t.Fatalf("message = %q", message)
	}
}

func TestStripeEventTimestampAcceptsSnapshotAndThinFormats(t *testing.T) {
	for _, input := range []string{`1724910852`, `"2024-08-28T20:54:12.051Z"`} {
		var timestamp stripeEventTimestamp
		if err := json.Unmarshal([]byte(input), &timestamp); err != nil {
			t.Fatalf("unmarshal %s: %v", input, err)
		}
		if timestamp == 0 {
			t.Fatalf("timestamp %s was zero", input)
		}
	}
}

func TestStripeMeterErrorSamplePayloadsIncludesEveryRequest(t *testing.T) {
	payload := json.RawMessage(`{"reason":{"error_types":[{"sample_errors":[{"error_message":"first","request":{"idempotency_key":"meter-event:first"}},{"error_message":"second","request":{"idempotency_key":"meter-event:second"}}]}]}}`)
	samples := stripeMeterErrorSamplePayloads(payload)
	if len(samples) != 2 {
		t.Fatalf("sample count = %d, want 2", len(samples))
	}
	for _, want := range []string{"meter-event:first", "meter-event:second"} {
		found := false
		for _, sample := range samples {
			_, _, _, key, _, err := stripeMeterErrorDetails(sample)
			if err == nil && key == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing sample %q", want)
		}
	}
}

type stripeMeterEventRoundTripper struct {
	identifier     string
	idempotencyKey string
}

func (r *stripeMeterEventRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	r.identifier = form.Get("identifier")
	r.idempotencyKey = req.Header.Get("Idempotency-Key")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

type stripeCheckoutSessionRoundTripper struct {
	backdateStartDate string
	clientReferenceID string
}

type stripeCreditBalanceRoundTripper struct {
	status int
	body   string
}

func (r *stripeCreditBalanceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/v1/billing/credit_balance_summary" || req.URL.Query().Get("customer") != "cus_example" || req.URL.Query().Get("filter[type]") != "applicability_scope" || req.URL.Query().Get("filter[applicability_scope][price_type]") != "metered" {
		return nil, fmt.Errorf("unexpected credit balance request: %s", req.URL.String())
	}
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(r.body)), Header: make(http.Header), Request: req}, nil
}

func TestStripeCreditBalanceAggregatesApplicableGrants(t *testing.T) {
	transport := &stripeCreditBalanceRoundTripper{body: `{"balances":[{"available_balance":{"monetary":{"currency":"usd","value":2000}}},{"available_balance":{"monetary":{"currency":"usd","value":1200000}}},{"available_balance":{"monetary":{"currency":"eur","value":9000}}}]}`}
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	got, err := client.GetCustomerCreditBalance(t.Context(), "cus_example")
	if err != nil {
		t.Fatalf("get credit balance: %v", err)
	}
	if got.AvailableUSD != 12020 {
		t.Fatalf("available credit = %v, want 12020", got.AvailableUSD)
	}
	if got.ObservedAt.IsZero() {
		t.Fatal("expected observation timestamp")
	}
	if got.IncludesCurrentPeriodUsage {
		t.Fatal("credit balance summary must not claim active-period usage is reflected")
	}
}

func TestStripeCreditBalancePreservesKnownZero(t *testing.T) {
	transport := &stripeCreditBalanceRoundTripper{body: `{"balances":[{"available_balance":{"monetary":{"currency":"usd","value":0}}}]}`}
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	got, err := client.GetCustomerCreditBalance(t.Context(), "cus_example")
	if err != nil {
		t.Fatalf("get credit balance: %v", err)
	}
	if got.AvailableUSD != 0 {
		t.Fatalf("available credit = %v, want 0", got.AvailableUSD)
	}
}

func TestStripeCreditBalanceDoesNotTruncateAggregateBalances(t *testing.T) {
	var balances strings.Builder
	balances.WriteString(`{"balances":[`)
	for i := 0; i < 101; i++ {
		if i > 0 {
			balances.WriteByte(',')
		}
		balances.WriteString(`{"available_balance":{"monetary":{"currency":"usd","value":100}}}`)
	}
	balances.WriteString(`]}`)
	transport := &stripeCreditBalanceRoundTripper{body: balances.String()}
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	got, err := client.GetCustomerCreditBalance(t.Context(), "cus_example")
	if err != nil {
		t.Fatalf("get credit balance: %v", err)
	}
	if got.AvailableUSD != 101 {
		t.Fatalf("available credit = %v, want 101", got.AvailableUSD)
	}
}

func TestStripeCreditBalancePropagatesFetchFailure(t *testing.T) {
	transport := &stripeCreditBalanceRoundTripper{status: http.StatusBadGateway, body: `{"error":"unavailable"}`}
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	if _, err := client.GetCustomerCreditBalance(t.Context(), "cus_example"); err == nil {
		t.Fatal("expected fetch failure")
	}
}

func TestStripeCreditBalanceRejectsMissingMonetaryBalance(t *testing.T) {
	transport := &stripeCreditBalanceRoundTripper{body: `{"balances":[{"available_balance":{}}]}`}
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	if _, err := client.GetCustomerCreditBalance(t.Context(), "cus_example"); err == nil {
		t.Fatal("expected malformed balance response to be unavailable")
	}
}

func TestStripeCreditBalanceRejectsPartiallyMalformedBalances(t *testing.T) {
	transport := &stripeCreditBalanceRoundTripper{body: `{"balances":[{"available_balance":{"monetary":{"currency":"usd","value":2000}}},{"available_balance":{}}]}`}
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	if _, err := client.GetCustomerCreditBalance(t.Context(), "cus_example"); err == nil {
		t.Fatal("expected partially malformed balance response to be unavailable")
	}
}

func (r *stripeCheckoutSessionRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	r.backdateStartDate = form.Get("subscription_data[backdate_start_date]")
	r.clientReferenceID = form.Get("client_reference_id")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"id":"cs_test_123","url":"https://checkout.stripe.test/session"}`)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestValidateBillingExportItemsRejectsNegativeValue(t *testing.T) {
	err := validateBillingExportItems([]billingExportPreviewItem{
		{ResourceType: "cpu", Value: 1},
		{ResourceType: "memory", Value: -0.25},
	})
	if err == nil {
		t.Fatal("expected negative billing export quantity to be rejected")
	}
}

func TestStripeMeterEventIdempotencyKeySeparatesPayloadFromIdentifier(t *testing.T) {
	identifier := "team:example:period:1,2:meter:memory"
	first := stripeMeterEventIdempotencyKey(identifier, "memory_gib_hours", "cus_example", "1.000000000000", 2)
	if got := stripeMeterEventIdempotencyKey(identifier, "memory_gib_hours", "cus_example", "1.000000000000", 2); got != first {
		t.Fatalf("same payload idempotency key = %q, want %q", got, first)
	}
	if got := stripeMeterEventIdempotencyKey(identifier, "memory_gib_hours", "cus_example", "2.000000000000", 2); got == first {
		t.Fatal("changed payload reused the same idempotency key")
	}
	if got := stripeMeterEventIdempotencyKey(identifier, "memory_gib_hours_v2", "cus_example", "1.000000000000", 2); got == first {
		t.Fatal("changed event name reused the same idempotency key")
	}
	if got := stripeMeterEventIdempotencyKey(identifier, "memory_gib_hours", "cus_other", "1.000000000000", 2); got == first {
		t.Fatal("changed customer reused the same idempotency key")
	}
	if got := stripeMeterEventIdempotencyKey(identifier, "memory_gib_hours", "cus_example", "1.000000000000", 3); got == first {
		t.Fatal("changed timestamp reused the same idempotency key")
	}
}

func TestMeterIdentifierForPayloadKeepsLogicalPrefixAndSeparatesPayloads(t *testing.T) {
	teamID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	start := time.Unix(100, 0).UTC()
	end := time.Unix(200, 0).UTC()
	cpu := meterIdentifierForPayload(teamID, start, end, "cpu", "cpu_hours", "cus_example", 1)
	same := meterIdentifierForPayload(teamID, start, end, "cpu", "cpu_hours", "cus_example", 1)
	changed := meterIdentifierForPayload(teamID, start, end, "cpu", "cpu_hours", "cus_example", 2)
	memory := meterIdentifierForPayload(teamID, start, end, "memory", "memory_gib_hours", "cus_example", 1)
	prefix := meterIdentifier(teamID, start, end, "cpu") + ":"

	if cpu != same {
		t.Fatalf("same payload identifiers differ: %q != %q", cpu, same)
	}
	if cpu == changed {
		t.Fatalf("changed payload reused identifier %q", cpu)
	}
	if !strings.HasPrefix(cpu, prefix) {
		t.Fatalf("identifier %q does not preserve logical meter prefix", cpu)
	}
	if cpu == memory {
		t.Fatalf("different resource types reused identifier %q", cpu)
	}
	if _, _, _, _, err := parseMeterIdentifier(cpu); err != nil {
		t.Fatalf("parse payload identifier %q: %v", cpu, err)
	}
}

func TestStripeReportMeterEventUsesSeparateIdentifierAndIdempotencyKey(t *testing.T) {
	transport := &stripeMeterEventRoundTripper{}

	client := &stripeHTTPClient{
		baseURL:    "https://stripe.example.test",
		secretKey:  "sk_test_example",
		apiVersion: "2025-06-30",
		httpClient: &http.Client{Transport: transport},
	}
	params := StripeReportMeterEventParams{
		Identifier:     "team:example:period:1,2:meter:memory",
		IdempotencyKey: "meter-event:payload-hash",
		EventName:      "memory_gib_hours",
		CustomerID:     "cus_example",
		Value:          "1.000000000000",
		Timestamp:      2,
	}
	if err := client.ReportMeterEvent(t.Context(), params); err != nil {
		t.Fatalf("report meter event: %v", err)
	}
	if transport.identifier != params.Identifier {
		t.Fatalf("request identifier = %q, want %q", transport.identifier, params.Identifier)
	}
	if transport.idempotencyKey != params.IdempotencyKey {
		t.Fatalf("request idempotency key = %q, want %q", transport.idempotencyKey, params.IdempotencyKey)
	}
	if transport.identifier == transport.idempotencyKey {
		t.Fatal("logical identifier and HTTP idempotency key must be distinct")
	}
}

func TestStripeCreateCheckoutSessionSendsBackdateStartDate(t *testing.T) {
	transport := &stripeCheckoutSessionRoundTripper{}
	client := &stripeHTTPClient{
		baseURL:    "https://stripe.example.test",
		secretKey:  "sk_test_example",
		apiVersion: "2025-06-30",
		httpClient: &http.Client{Transport: transport},
	}
	anchor := time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)
	if _, err := client.CreateCheckoutSession(t.Context(), StripeCreateCheckoutSessionParams{
		CustomerID:        "cus_example",
		SuccessURL:        "https://app.superserve.test/billing/success",
		CancelURL:         "https://app.superserve.test/billing/cancel",
		ClientReferenceID: "team_example",
		PriceIDs:          []string{"price_cpu"},
		BackdateStartDate: &anchor,
		IdempotencyKey:    "checkout:test",
	}); err != nil {
		t.Fatalf("create checkout session: %v", err)
	}
	if transport.backdateStartDate != strconv.FormatInt(anchor.Unix(), 10) {
		t.Fatalf("subscription backdate_start_date = %q, want %d", transport.backdateStartDate, anchor.Unix())
	}
	if transport.clientReferenceID != "team_example" {
		t.Fatalf("client reference id = %q, want %q", transport.clientReferenceID, "team_example")
	}
}

func TestCheckoutSessionIdempotencyKeyIncludesBackdateStartDate(t *testing.T) {
	teamID := uuid.MustParse("00000000-0000-0000-0000-000000000042")
	customerID := "cus_example"
	successURL := "https://app.superserve.test/billing/success"
	cancelURL := "https://app.superserve.test/billing/cancel"
	priceIDs := []string{"price_cpu"}
	first := checkoutSessionIdempotencyKey(teamID, customerID, successURL, cancelURL, priceIDs, nil)
	if got := checkoutSessionIdempotencyKey(teamID, customerID, successURL, cancelURL, priceIDs, nil); got != first {
		t.Fatalf("same checkout payload produced %q, want %q", got, first)
	}
	anchor := time.Date(2026, 8, 21, 17, 0, 0, 0, time.UTC)
	withAnchor := checkoutSessionIdempotencyKey(teamID, customerID, successURL, cancelURL, priceIDs, &anchor)
	if withAnchor == first {
		t.Fatal("checkout idempotency key ignored backdate start date")
	}
	if got := checkoutSessionIdempotencyKey(teamID, customerID, successURL, cancelURL, priceIDs, &anchor); got != withAnchor {
		t.Fatalf("same checkout payload with backdate produced %q, want %q", got, withAnchor)
	}
}

func TestStripeSubscriptionPeriodBoundsPrefersItemBounds(t *testing.T) {
	obj := stripeSubscriptionObject{
		CurrentPeriodStart: 100,
		CurrentPeriodEnd:   200,
		Items: stripeSubscriptionObjectItems{
			Data: []stripeSubscriptionItem{{
				CurrentPeriodStart: 300,
				CurrentPeriodEnd:   400,
			}},
		},
	}
	start, end, ok := stripeSubscriptionPeriodBounds(obj)
	if !ok {
		t.Fatal("expected item-level subscription period bounds")
	}
	if start != 300 || end != 400 {
		t.Fatalf("subscription period bounds = (%d, %d), want (300, 400)", start, end)
	}
}

func TestStripeSubscriptionPeriodBoundsFallsBackToTopLevel(t *testing.T) {
	obj := stripeSubscriptionObject{
		CurrentPeriodStart: 100,
		CurrentPeriodEnd:   200,
	}
	start, end, ok := stripeSubscriptionPeriodBounds(obj)
	if !ok {
		t.Fatal("expected top-level subscription period bounds")
	}
	if start != 100 || end != 200 {
		t.Fatalf("subscription period bounds = (%d, %d), want (100, 200)", start, end)
	}
}

func TestStripeMeterQuantityPreservesNormalizedUnits(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		want  string
		ok    bool
	}{
		{
			name:  "integer quantity",
			value: 2,
			want:  "2.000000000000",
			ok:    true,
		},
		{
			name:  "rounded decimal quantity",
			value: 977.2464597941668,
			want:  "977.246459794167",
			ok:    true,
		},
		{
			name:  "tiny quantity",
			value: 123.0 / 3600.0,
			want:  "0.034166666667",
			ok:    true,
		},
		{
			name:  "rounds below precision to zero",
			value: 1e-13,
			ok:    false,
		},
		{
			name:  "zero quantity",
			value: 0,
			ok:    false,
		},
		{
			name:  "negative quantity",
			value: -1,
			ok:    false,
		},
		{
			name:  "not a number",
			value: math.NaN(),
			ok:    false,
		},
		{
			name:  "positive infinity",
			value: math.Inf(1),
			ok:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := stripeMeterQuantity(tc.value)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("quantity = %q, want %q", got, tc.want)
			}
		})
	}
}
