package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
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

func TestIncrementalMeterSummaryAcceptsPolicyQuantitiesBeyondAccountingScale(t *testing.T) {
	transport := &incrementalSummaryTransport{expectedStart: "0", expectedEnd: "3600", summary: `{"data":[{"aggregated_value":1.0000000000000002}],"has_more":false}`}
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	quantity, err := client.CountedMeterUsage(t.Context(), "cpu_hours", "cus_example", time.Unix(0, 0), time.Unix(3600, 0))
	if err != nil || quantity != "1.0000000000000002" {
		t.Fatalf("summary=%q %v", quantity, err)
	}
}

func TestIncrementalMeterSummaryDoesNotInferEventAcceptance(t *testing.T) {
	for _, tc := range []struct {
		body      string
		wantError bool
		want      string
	}{
		{`{"data":[],"has_more":false}`, false, "0"},
		{`{"data":[]}`, true, ""},
		{`{"data":null,"has_more":false}`, true, ""},
		{`{"has_more":false}`, true, ""},
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

type meterBucketTransport func(*http.Request) (*http.Response, error)

func (f meterBucketTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestIncrementalBucketReaderBoundsAndEdges(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 2, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0).Add(7 * time.Hour)
	for _, mode := range []string{"complete", "pagination", "missing", "missing_completion", "missing_data", "null_data", "wrong_meter", "wrong_window", "duplicate", "oversized", "negative", "outage"} {
		t.Run(mode, func(t *testing.T) {
			calls, summaries := 0, 0
			transport := meterBucketTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				body := `{"data":[{"id":"mtr_example","event_name":"cpu_hours","default_aggregation":{"formula":"sum"},"customer_mapping":{"event_payload_key":"stripe_customer_id"},"value_settings":{"event_payload_key":"value"}}],"has_more":false}`
				if strings.HasSuffix(req.URL.Path, "/event_summaries") {
					summaries++
					if mode == "outage" {
						return nil, fmt.Errorf("example provider unavailable")
					}
					q := req.URL.Query()
					if q.Get("customer") != "cus_example" || q.Get("limit") != "100" || q.Get("starting_after") != "" {
						t.Fatalf("unbounded or wrong scope: %s", req.URL)
					}
					a, _ := strconv.ParseInt(q.Get("start_time"), 10, 64)
					b, _ := strconv.ParseInt(q.Get("end_time"), 10, 64)
					if a < start.Unix() || b > end.Unix() {
						t.Fatal("query widened observation window")
					}
					windows, err := meterEvidenceWindows(time.Unix(a, 0), time.Unix(b, 0))
					if err != nil {
						t.Fatal(err)
					}
					if summaries == 2 && q.Get("value_grouping_window") != "day" {
						t.Fatal("interior must group full UTC days")
					}
					if summaries != 2 && q.Get("value_grouping_window") != "" {
						t.Fatal("partial edges cannot use daily grouping")
					}
					var rows []map[string]any
					for i := len(windows) - 1; i >= 0; i-- {
						w := windows[i]
						rows = append(rows, map[string]any{"id": fmt.Sprint("bucket_", i), "meter": "mtr_example", "start_time": w.Start.Unix(), "end_time": w.End.Unix(), "aggregated_value": json.Number("0.000000000001")})
					}
					response := map[string]any{"data": rows, "has_more": false}
					switch mode {
					case "pagination":
						response["has_more"] = true
					case "missing":
						response["data"] = rows[:len(rows)-1]
					case "missing_completion":
						delete(response, "has_more")
					case "missing_data":
						delete(response, "data")
					case "null_data":
						response["data"] = nil
					case "wrong_meter":
						rows[0]["meter"] = "mtr_other"
					case "wrong_window":
						rows[0]["start_time"] = a - 60
					case "duplicate":
						if len(rows) > 1 {
							rows[1] = rows[0]
						} else {
							response["data"] = append(rows, rows[0])
						}
					case "oversized":
						response["data"] = append(rows, map[string]any{
							"id": "extra_summary", "meter": "mtr_example", "start_time": a, "end_time": b, "aggregated_value": 0,
						})
					case "negative":
						rows[0]["aggregated_value"] = -1
					}
					encoded, err := json.Marshal(response)
					if err != nil {
						t.Fatal(err)
					}
					body = string(encoded)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
			})
			client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
			buckets, err := client.BucketedMeterUsage(t.Context(), "cpu_hours", "cus_example", start, end)
			if mode == "complete" || mode == "missing" {
				wantBuckets := 32
				if mode == "missing" {
					// Each of the three summary responses omits one bucket.
					wantBuckets = 29
				}
				if err != nil || len(buckets) != wantBuckets || calls != 4 {
					t.Fatalf("buckets=%d calls=%d err=%v", len(buckets), calls, err)
				}
			} else if err == nil {
				t.Fatal("invalid evidence accepted")
			}
			if calls > 4 {
				t.Fatalf("request budget exceeded: %d", calls)
			}
		})
	}
}

func TestMeterPrecisionBoundary(t *testing.T) {
	for _, total := range []string{"0.000000000001", "1", "8191.999999999999", "8192", "9712.454976049444", "1000000000"} {
		local, _ := meterDecimal(total)
		bound, err := meterPrecisionBound(local)
		if err != nil {
			t.Fatal(err)
		}
		// Independent binary64 spacing oracle, using the lower binade at a
		// rounding boundary because policy is defined by the exact local total.
		f, _ := local.Float64()
		if new(big.Rat).SetFloat64(f).Cmp(local) > 0 {
			f = math.Nextafter(f, 0)
		}
		want := new(big.Rat).Sub(new(big.Rat).SetFloat64(math.Nextafter(f, math.Inf(1))), new(big.Rat).SetFloat64(f))
		if bound.Cmp(want) != 0 {
			t.Fatalf("%s bound=%s want=%s", total, bound, want)
		}
		at := new(big.Rat).Add(local, bound)
		beyond := new(big.Rat).Add(at, new(big.Rat).Quo(bound, big.NewRat(1024, 1)))
		for _, tc := range []struct {
			value    *big.Rat
			eligible bool
		}{{at, true}, {beyond, false}} {
			d, eligible := compareMeterSummary(tc.value.FloatString(110), total)
			if eligible != tc.eligible || d.Err == nil {
				t.Fatalf("boundary comparison %s: %+v eligible=%v", total, d, eligible)
			}
		}
	}
	if bound, err := meterPrecisionBound(new(big.Rat)); err != nil || bound.Sign() != 0 {
		t.Fatalf("zero precision policy: bound=%v err=%v", bound, err)
	}
	for _, total := range []string{"0.0000000000009", "1000000000.000000000001"} {
		r, _ := meterDecimal(total)
		if _, err := meterPrecisionBound(r); err == nil {
			t.Fatalf("unsupported total %s", total)
		}
	}
	if decision, candidate := compareMeterSummary("1000000000.000000000001", "1000000000"); decision.Err == nil || !candidate {
		t.Fatalf("upper reserved boundary must require corroborating evidence: %+v candidate=%v", decision, candidate)
	}
	if decision, candidate := compareMeterSummary("0.000000000001", "0"); decision.Err == nil || candidate || decision.Outcome != "unexplained_excess" {
		t.Fatalf("positive provider usage with empty local ledger was explained: %+v candidate=%v", decision, candidate)
	}
	for _, tc := range []struct {
		provider, reserved, outcome string
	}{
		{"1000000001", "1000000001", "equal"},
		{"1000000000", "1000000001", "provider_lag"},
	} {
		decision, candidate := compareMeterSummary(tc.provider, tc.reserved)
		if decision.Err != nil || candidate || decision.Outcome != tc.outcome {
			t.Fatalf("ordinary %s comparison blocked: %+v candidate=%v", tc.outcome, decision, candidate)
		}
	}
}

func TestCompleteMeterBucketsRetainsPartialEdgesAndZeroWindows(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 2, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	windows, err := meterEvidenceWindows(start, end)
	if err != nil {
		t.Fatal(err)
	}
	provided := []meterUsageBucket{{Start: windows[1].Start, End: windows[1].End, Quantity: "9712.454976049444"}}
	complete := completeMeterBuckets(provided, start, end)
	if len(complete) != 3 || complete[0].Start != start.Unix() || complete[2].End != end.Unix() ||
		complete[0].Quantity != "0" || complete[1].Quantity != provided[0].Quantity || complete[2].Quantity != "0" {
		t.Fatalf("incomplete persisted bucket partition: %+v", complete)
	}
	if complete[0].End != complete[1].Start || complete[1].End != complete[2].Start {
		t.Fatalf("persisted evidence has a gap: %+v", complete)
	}
}

func TestMeterEvidenceWindowsAndLocalInventory(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 2, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	buckets, _ := meterEvidenceWindows(start, end)
	for i := range buckets {
		buckets[i].Quantity = "0"
	}
	buckets[1].Quantity = "9712.454976049444"
	events := []meterLocalEvent{{ID: "example", EventName: "cpu_hours", Customer: "cus_example", Quantity: buckets[1].Quantity, Status: "submitted", Timestamp: buckets[1].Start.Unix()}}
	reserved, _ := meterDecimal(events[0].Quantity)
	for _, mode := range []string{"complete", "missing", "missing_nonzero", "shifted", "nonzero_empty_bucket", "tiny_bucket_drift", "uncertain", "rejected", "pending", "wrong_customer", "wrong_meter", "at_end", "before_start", "wrong_reservations", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			bs := append([]meterUsageBucket(nil), buckets...)
			es := append([]meterLocalEvent(nil), events...)
			total := new(big.Rat).Set(reserved)
			switch mode {
			case "missing":
				bs = bs[:2]
			case "missing_nonzero":
				bs = append(bs[:1], bs[2:]...)
			case "shifted":
				bs[1].Start = bs[1].Start.Add(time.Minute)
			case "nonzero_empty_bucket":
				bs[0].Quantity = "0.000000000001"
			case "tiny_bucket_drift":
				bs[1].Quantity = "9712.454976049445"
			case "uncertain", "rejected", "pending":
				es[0].Status = mode
			case "wrong_customer":
				es[0].Customer = "cus_other"
			case "wrong_meter":
				es[0].EventName = "memory_hours"
			case "at_end":
				es[0].Timestamp = end.Unix()
			case "before_start":
				es[0].Timestamp = start.Unix() - 1
			case "wrong_reservations":
				total.Add(total, big.NewRat(1, 1))
			case "malformed":
				bs[1].Quantity = "NaN"
			}
			err := matchMeterBuckets(es, bs, "cpu_hours", "cus_example", start, end, total)
			if (err == nil) != (mode == "complete" || mode == "missing") {
				t.Fatalf("%s: %v", mode, err)
			}
		})
	}
	for _, window := range [][2]time.Time{{start, start}, {start, end.Add(33 * 24 * time.Hour)}, {start.Add(time.Second), end}} {
		if _, err := meterEvidenceWindows(window[0], window[1]); err == nil {
			t.Fatal("unsupported window")
		}
	}
}

func TestMeterGrowingRepeatedDrift(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for _, shape := range []string{"persistent", "increasing", "decreasing", "sign_changing"} {
		t.Run(shape, func(t *testing.T) {
			var events []meterLocalEvent
			total := new(big.Rat)
			increment, _ := meterDecimal("9712.454976049444")
			for i := 1; i <= 512; i++ {
				total.Add(total, increment)
				events = append(events, meterLocalEvent{EventName: "cpu_hours", Customer: "cus_example", Quantity: increment.FloatString(12), Status: "submitted", Timestamp: start.Add(time.Hour).Unix()})
				bound, _ := meterPrecisionBound(total)
				steps := int64(1)
				switch shape {
				case "increasing":
					steps = int64(i)
				case "decreasing":
					steps = int64(513 - i)
				case "sign_changing":
					if i%2 == 0 {
						steps = -1
					}
				}
				drift := big.NewRat(steps, 1_000_000_000_000)

				provider := new(big.Rat).Add(total, drift)
				for read := 0; read < 2; read++ {
					buckets := []meterUsageBucket{{Start: start, End: start.Add(24 * time.Hour), Quantity: total.FloatString(12)}}
					if err := matchMeterBuckets(events, buckets, "cpu_hours", "cus_example", start, start.Add(24*time.Hour), total); err != nil {
						t.Fatal(err)
					}
					decision, candidate := compareMeterSummary(provider.FloatString(12), total.FloatString(12))
					if drift.Sign() < 0 {
						if decision.Outcome != "provider_lag" || decision.Err != nil || candidate {
							t.Fatalf("lag: %+v", decision)
						}
					} else if drift.Cmp(bound) <= 0 {
						if !candidate {
							t.Fatalf("supported drift rejected: %+v", decision)
						}
					} else if candidate || decision.Outcome != "unexplained_excess" || decision.Err == nil {
						t.Fatalf("outside policy authorized: %+v", decision)
					}
				}
			}
		})
	}
}

type meterFixedSummary string

func (m meterFixedSummary) CountedMeterUsage(context.Context, string, string, time.Time, time.Time) (string, error) {
	return string(m), nil
}

func TestMeterDecisionExactLagAndInvalid(t *testing.T) {
	for _, tc := range []struct {
		provider, reserved, outcome string
		fail                        bool
	}{
		{"10", "10", "equal", false}, {"9", "10", "provider_lag", false}, {"10.1", "10", "unexplained_excess", true},
		{"9712.454976049445", "9712.454976049444", "incomplete", true},
		{"NaN", "10", "incomplete", true}, {"-1", "10", "incomplete", true}, {"1/2", "10", "incomplete", true}, {"1", "bad", "incomplete", true},
	} {
		d := (&Handlers{}).assessMeterSummary(t.Context(), billing.ExportPeriod{}, incrementalExportItem{}, time.Time{}, meterFixedSummary(tc.provider), "cus_example", tc.provider, billing.ExportTotals{Reserved: tc.reserved}, nil)
		if (d.Err != nil) != tc.fail || d.Outcome != tc.outcome {
			t.Fatalf("%+v: %+v", tc, d)
		}
	}
}

func TestMeterEvidenceEventBudget(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	events := make([]meterLocalEvent, meterEvidenceLimit)
	for i := range events {
		events[i] = meterLocalEvent{EventName: "cpu_hours", Customer: "cus_example", Status: "submitted", Quantity: "1", Timestamp: start.Unix()}
	}
	buckets := []meterUsageBucket{{Start: start, End: start.Add(24 * time.Hour), Quantity: strconv.Itoa(meterEvidenceLimit)}}
	if err := matchMeterBuckets(events, buckets, "cpu_hours", "cus_example", start, start.Add(24*time.Hour), big.NewRat(meterEvidenceLimit, 1)); err != nil {
		t.Fatal(err)
	}
	events = append(events, events[0])
	if err := matchMeterBuckets(events, buckets, "cpu_hours", "cus_example", start, start.Add(24*time.Hour), big.NewRat(meterEvidenceLimit, 1)); err == nil {
		t.Fatal("event budget overflow accepted")
	}
}

func TestIncrementalBucketMeterLookupBudget(t *testing.T) {
	calls := 0
	transport := meterBucketTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path != "/v1/billing/meters" {
			t.Fatalf("unresolved meter queried: %s", req.URL)
		}
		body := fmt.Sprintf(`{"data":[{"id":"mtr_other_%d","event_name":"other"}],"has_more":true}`, calls)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if _, err := client.BucketedMeterUsage(t.Context(), "cpu_hours", "cus_example", start, start.Add(24*time.Hour)); err == nil || calls != 5 {
		t.Fatalf("lookup budget: calls=%d err=%v", calls, err)
	}
}

func TestIncrementalDecisionPinsMeterAcrossProviderReads(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	lookups, summaries := 0, 0
	var meters []string
	transport := meterBucketTransport(func(req *http.Request) (*http.Response, error) {
		var body string
		if req.URL.Path == "/v1/billing/meters" {
			lookups++
			meter := "mtr_original"
			if lookups > 1 {
				meter = "mtr_replacement"
			}
			body = fmt.Sprintf(`{"data":[{"id":%q,"event_name":"cpu_hours","default_aggregation":{"formula":"sum"},"customer_mapping":{"event_payload_key":"stripe_customer_id"},"value_settings":{"event_payload_key":"value"}}],"has_more":false}`, meter)
		} else {
			summaries++
			meter := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/v1/billing/meters/"), "/event_summaries")
			meters = append(meters, meter)
			q := req.URL.Query()
			if q.Get("customer") != "cus_example" || q.Get("start_time") != strconv.FormatInt(start.Unix(), 10) || q.Get("end_time") != strconv.FormatInt(end.Unix(), 10) {
				t.Fatalf("decision query scope changed: %s", req.URL)
			}
			quantity := "9712.454976049445"
			if q.Get("value_grouping_window") == "day" {
				quantity = "9712.454976049444"
			}
			body = fmt.Sprintf(`{"data":[{"id":"summary_example","meter":%q,"start_time":%d,"end_time":%d,"aggregated_value":%s}],"has_more":false}`, meter, start.Unix(), end.Unix(), quantity)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})
	client := &stripeHTTPClient{baseURL: "https://stripe.example.test", secretKey: "sk_test_example", apiVersion: "2025-06-30", httpClient: &http.Client{Transport: transport}}
	reader := pinMeterSummaryReader(client)
	value, err := reader.CountedMeterUsage(t.Context(), "cpu_hours", "cus_example", start, end)
	if err != nil || value != "9712.454976049445" {
		t.Fatalf("initial summary: %q %v", value, err)
	}
	for pass := 0; pass < 2; pass++ {
		buckets, err := reader.(stripeMeterBucketReader).BucketedMeterUsage(t.Context(), "cpu_hours", "cus_example", start, end)
		if err != nil || len(buckets) != 1 || buckets[0].Quantity != "9712.454976049444" {
			t.Fatalf("bucket pass %d: %+v %v", pass, buckets, err)
		}
	}
	if reread, err := reader.CountedMeterUsage(t.Context(), "cpu_hours", "cus_example", start, end); err != nil || reread != value {
		t.Fatalf("summary reread: %q %v", reread, err)
	}
	if lookups != 1 || summaries != 4 {
		t.Fatalf("decision lookup/request budget: lookups=%d summaries=%d", lookups, summaries)
	}
	for _, meter := range meters {
		if meter != "mtr_original" {
			t.Fatalf("decision mixed meter identities: %v", meters)
		}
	}
	if _, err := reader.CountedMeterUsage(t.Context(), "memory_hours", "cus_example", start, end); err == nil {
		t.Fatal("pinned reader accepted a different event name")
	}
	if _, err := reader.(stripeMeterBucketReader).BucketedMeterUsage(t.Context(), "memory_hours", "cus_example", start, end); err == nil {
		t.Fatal("pinned buckets accepted a different event name")
	}
	if lookups != 1 || summaries != 4 {
		t.Fatal("changed event name reached the provider")
	}
	// Finalization resolves the active mapping independently of this decision.
	h := &Handlers{Stripe: client}
	if current, err := h.ResolveActiveBillingMeter(t.Context(), "cpu_hours"); err != nil || current != "mtr_replacement" || meterReaderID(reader) != "mtr_original" {
		t.Fatalf("current mapping reused pinned identity: %q %v", current, err)
	}
	// A new decision resolves the current mapping; pinning is not a global cache.
	if _, err := pinMeterSummaryReader(client).CountedMeterUsage(t.Context(), "cpu_hours", "cus_example", start, end); err != nil {
		t.Fatal(err)
	}
	if lookups != 3 || summaries != 5 || meters[4] != "mtr_replacement" {
		t.Fatalf("new decision retained stale mapping: lookups=%d meters=%v", lookups, meters)
	}
}
