package api

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
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
