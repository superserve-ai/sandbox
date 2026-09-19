package api

import (
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"time"
)

type incrementalSummaryTransport struct {
	summary                    string
	expectedStart, expectedEnd string
	calls                      int
}

func (r *incrementalSummaryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	body := `{"data":[{"id":"mtr_example","event_name":"cpu_hours","default_aggregation":{"formula":"sum"},"customer_mapping":{"event_payload_key":"stripe_customer_id"},"value_settings":{"event_payload_key":"value"}}],"has_more":false}`
	if req.URL.Path == "/v1/billing/meters/mtr_example/event_summaries" {
		if req.URL.Query().Get("start_time") != r.expectedStart || req.URL.Query().Get("end_time") != r.expectedEnd || req.URL.Query().Get("customer") != "cus_example" || req.URL.Query().Get("value_grouping_window") != "" {
			return nil, fmt.Errorf("incorrect summary boundaries or grouping: %s", req.URL)
		}
		body = r.summary
	} else if req.URL.Path != "/v1/billing/meters" {
		return nil, fmt.Errorf("unexpected path %s", req.URL.Path)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
}

func TestIncrementalMeterSummaryPreservesDecimalAndMinuteWindow(t *testing.T) {
	transport := &incrementalSummaryTransport{expectedStart: "120", expectedEnd: "3600", summary: `{"data":[{"aggregated_value":12345.123456789123}],"has_more":false}`}
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	quantity, err := client.CountedMeterUsage(t.Context(), "cpu_hours", "cus_example", time.Unix(61, 0), time.Unix(3659, 0))
	if err != nil || quantity != "12345.123456789123" {
		t.Fatalf("summary=%q %v", quantity, err)
	}
	if transport.calls != 2 {
		t.Fatalf("calls=%d", transport.calls)
	}
}

func TestIncrementalMeterSummaryDoesNotInferEventAcceptance(t *testing.T) {
	for _, tc := range []struct {
		body      string
		wantError bool
		want      string
	}{
		{`{"data":[],"has_more":false}`, false, "0"},
		{`{"data":[{"aggregated_value":10}],"has_more":true}`, true, ""},
		{`{"data":[{"aggregated_value":10},{"aggregated_value":5}],"has_more":false}`, true, ""},
	} {
		transport := &incrementalSummaryTransport{expectedStart: "0", expectedEnd: "3600", summary: tc.body}
		client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
		quantity, err := client.CountedMeterUsage(t.Context(), "cpu_hours", "cus_example", time.Unix(0, 0), time.Unix(3600, 0))
		if (err != nil) != tc.wantError || quantity != tc.want {
			t.Fatalf("summary=%q %v for %s", quantity, err, tc.body)
		}
	}
}

func TestMissingMeterErrorsUseBillingErrorRecovery(t *testing.T) {
	if !isStripeMeterErrorEvent("v1.billing.meter.no_meter_found") {
		t.Fatal("thin missing-meter error bypasses expansion and recovery")
	}
	if !isStripeMeterErrorEvent("billing.meter.no_meter_found") {
		t.Fatal("missing-meter error bypasses recovery")
	}
}

func TestIncrementalUsagePartitionsPreserveExactTotal(t *testing.T) {
	for _, key := range []string{"vcpu", "memory_gib", "storage_gib"} {
		t.Run(key, func(t *testing.T) {
			resources := []billingResourceState{{BillingResourceConfig: config.BillingResourceConfig{
				ResourceKey: key, StripeEventName: "example_hours", CheckoutEnabled: true,
			}, Billable: true}}
			for _, checkpoints := range [][]string{
				{"0.0000000000004", "0.0000000000005", "12345.123456789122", "12345.123456789123"},
				{"12345.123456789122", "12345.123456789123"},
				{"12345.123456789123"},
			} {
				reserved := "0"
				sum := new(big.Rat)
				for _, checkpoint := range checkpoints {
					seconds, _ := new(big.Rat).SetString(checkpoint)
					divisor := int64(3600)
					if key != "vcpu" {
						divisor *= 1024
					}
					seconds.Mul(seconds, new(big.Rat).SetInt64(divisor))
					var numeric pgtype.Numeric
					if err := numeric.Scan(seconds.FloatString(16)); err != nil {
						t.Fatal(err)
					}
					items, err := incrementalExportItems(db.TeamBillingUsage{
						VcpuSeconds: numeric, MemoryMibSeconds: numeric, StorageMibSeconds: numeric,
					}, resources)
					if err != nil || len(items) != 1 {
						t.Fatalf("items=%v err=%v", items, err)
					}
					delta, err := billing.DecimalDelta(items[0].Quantity, reserved)
					if err != nil {
						t.Fatal(err)
					}
					value, _ := new(big.Rat).SetString(delta)
					sum.Add(sum, value)
					reserved = items[0].Quantity
				}
				if got := sum.FloatString(12); got != "12345.123456789123" {
					t.Fatalf("partition changed bill: %s", got)
				}
			}
		})
	}
}
