//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/config"
)

func seedIncrementalPeriod(t *testing.T) (billing.ExportStore, billing.ExportPeriod) {
	t.Helper()
	team, _, start, end := seedBillingPeriodForStripe(t, true, true)
	p := billing.ExportPeriod{TeamID: team, Start: start, End: end}
	store := billing.ExportStore{Pool: testPool}
	if err := store.Enroll(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	return store, p
}

func reserveIncrement(t *testing.T, s billing.ExportStore, p billing.ExportPeriod, total string) *billing.ExportEvent {
	t.Helper()
	event, err := s.Reserve(t.Context(), p, "cpu", total, p.End, billing.ExportPayload{EventName: "example_cpu_hours", CustomerID: "cus_example", Timestamp: p.End.Add(-time.Second).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func acceptIncrement(t *testing.T, s billing.ExportStore, p billing.ExportPeriod) *billing.ExportEvent {
	t.Helper()
	event, err := s.Claim(t.Context(), p)
	if err != nil || event == nil {
		t.Fatalf("claim: %v, %v", event, err)
	}
	if err = s.Acknowledge(t.Context(), *event, nil); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestIntegration_IncrementalAllocationConcurrencyAndEarlierRejection(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	reserveIncrement(t, s, p, "10")
	first := acceptIncrement(t, s, p)
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Reserve(context.Background(), p, "cpu", "15", p.End, billing.ExportPayload{EventName: "example_cpu_hours", CustomerID: "cus_example", Timestamp: p.End.Add(-time.Second).Unix()})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	second := acceptIncrement(t, s, p)
	if second.Quantity != "5.000000000000" {
		t.Fatalf("delta=%s", second.Quantity)
	}
	for i := 0; i < 2; i++ {
		if found, err := s.Reject(t.Context(), first.Identifier, "", first.CustomerID, first.EventName, "provider rejected earlier event"); err != nil || !found {
			t.Fatalf("reject: %v %v", found, err)
		}
	}
	totals, err := s.Totals(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if totals.Submitted != "5.000000000000" || totals.Reserved != "15.000000000000" || totals.Rejected != "10.000000000000" {
		t.Fatalf("non-contiguous accounting: %+v", totals)
	}
	if event := reserveIncrement(t, s, p, "15"); event != nil {
		t.Fatalf("rejection released coverage: %+v", event)
	}
	if err = s.RecoverRejected(t.Context(), first.ID, "reviewed provider rejection and corrected meter configuration"); err != nil {
		t.Fatal(err)
	}
	recovered := acceptIncrement(t, s, p)
	if recovered.Quantity != first.Quantity || recovered.Identifier == first.Identifier {
		t.Fatalf("bad recovery: %+v", recovered)
	}
	if found, err := s.Reject(t.Context(), first.Identifier, "", first.CustomerID, first.EventName, "duplicate old callback"); err != nil || !found {
		t.Fatalf("late duplicate: %v %v", found, err)
	}
	totals, err = s.Totals(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if totals.Submitted != "15.000000000000" || totals.Rejected != "0" {
		t.Fatalf("late callback changed replacement/later acceptance: %+v", totals)
	}
	var count int
	if err = testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_export_allocation WHERE team_id=$1`, p.TeamID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("got %d allocations, want 2", count)
	}
}

func TestIntegration_IncrementalCrashRetryAndRetentionLimit(t *testing.T) {
	for _, name := range []string{"successful_retry", "timeout_until_retention_limit"} {
		t.Run(name, func(t *testing.T) {
			retryAcknowledged := name == "successful_retry"
			s, p := seedIncrementalPeriod(t)
			reserveIncrement(t, s, p, "10")
			first, err := s.Claim(t.Context(), p)
			if err != nil || first == nil {
				t.Fatalf("claim: %v %v", first, err)
			}
			accepted := make(map[string]billing.ExportPayload)
			var attempts []billing.ExportPayload
			submit := func(payload billing.ExportPayload) error {
				attempts = append(attempts, payload)
				if prior, exists := accepted[payload.Identifier]; exists && prior != payload {
					return errors.New("provider received changed payload for accepted identifier")
				}
				accepted[payload.Identifier] = payload
				return nil
			}
			if err = submit(first.ExportPayload); err != nil {
				t.Fatal(err)
			}
			// The provider accepted the event, but the process died before local ack.
			if _, err = testPool.Exec(t.Context(), `UPDATE billing_export_event SET lease_until=now()-interval '1 second' WHERE id=$1`, first.ID); err != nil {
				t.Fatal(err)
			}
			s = billing.ExportStore{Pool: testPool}
			second, err := s.Claim(t.Context(), p)
			if err != nil || second == nil {
				t.Fatalf("retry: %v %v", second, err)
			}
			if first.ID != second.ID || first.AllocationID != second.AllocationID {
				t.Fatalf("retry replaced persisted event: %+v %+v", first, second)
			}
			if first.ExportPayload != second.ExportPayload {
				t.Fatalf("retry mutated payload: %+v %+v", first, second)
			}
			if err = s.Acknowledge(t.Context(), *first, nil); !errors.Is(err, billing.ErrExportRecoveryRequired) {
				t.Fatalf("stale owner acknowledged event: %v", err)
			}
			if err = submit(second.ExportPayload); err != nil {
				t.Fatal(err)
			}
			if len(attempts) != 2 || attempts[0] != attempts[1] || len(accepted) != 1 {
				t.Fatalf("provider retry did not deduplicate: attempts=%+v accepted=%+v", attempts, accepted)
			}
			if retryAcknowledged {
				if err = s.Acknowledge(t.Context(), *second, nil); err != nil {
					t.Fatal(err)
				}
				totals, err := s.Totals(t.Context(), p, "cpu")
				if err != nil {
					t.Fatal(err)
				}
				if totals.Submitted != "10.000000000000" || totals.Reserved != totals.Submitted || totals.Pending != "0" {
					t.Fatalf("acknowledged retry accounting: %+v", totals)
				}
				var events, submitted int
				if err = testPool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER (WHERE status='submitted')
					FROM billing_export_event WHERE allocation_id=$1`, first.AllocationID).Scan(&events, &submitted); err != nil {
					t.Fatal(err)
				}
				if events != 1 || submitted != 1 {
					t.Fatalf("retry persisted %d events, %d submitted; want one submitted event", events, submitted)
				}
				if event := reserveIncrement(t, s, p, "10"); event != nil {
					t.Fatalf("acknowledged retry released coverage: %+v", event)
				}
				if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
					t.Fatalf("acknowledged event queued again: %+v %v", event, err)
				}
				return
			}
			if err = s.Acknowledge(t.Context(), *second, errors.New("timeout")); err != nil {
				t.Fatal(err)
			}
			totals, err := s.Totals(t.Context(), p, "cpu")
			if err != nil {
				t.Fatal(err)
			}
			if totals.Submitted != "0" || totals.Reserved != "10.000000000000" {
				t.Fatalf("timeout accounting: %+v", totals)
			}
			if _, err = testPool.Exec(t.Context(), `UPDATE billing_export_event SET first_attempt_at=now()-interval '24 hours',next_attempt_at=now() WHERE id=$1`, first.ID); err != nil {
				t.Fatal(err)
			}
			expired, err := s.Claim(t.Context(), p)
			if err != nil || expired != nil {
				t.Fatalf("retried beyond retention: %v %v", expired, err)
			}
			var state string
			if err = testPool.QueryRow(t.Context(), `SELECT status FROM billing_export_event WHERE id=$1`, first.ID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != "recovery_required" {
				t.Fatalf("expired state=%s", state)
			}
			if event := reserveIncrement(t, s, p, "10"); event != nil {
				t.Fatal("expired uncertainty released coverage")
			}
		})
	}
}

func TestIntegration_IncrementalExternalEventAdoptionAfterSubmission(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	reserveIncrement(t, s, p, "10")
	local := acceptIncrement(t, s, p)
	if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID); err != nil {
		t.Fatal(err)
	}
	external := billing.AdoptedExport{Resource: "cpu", Through: p.End, ExportPayload: billing.ExportPayload{
		Identifier: "external-" + p.TeamID.String(), IdempotencyKey: "external-key-" + p.TeamID.String(),
		EventName: local.EventName, CustomerID: local.CustomerID, Quantity: "3", Timestamp: local.Timestamp,
	}}
	inventory := []billing.AdoptedExport{external, {Resource: "cpu", Through: p.End, ExportPayload: local.ExportPayload}}
	if err := s.Adopt(t.Context(), p, inventory[:1], "reviewed external evidence"); err == nil {
		t.Fatal("accepted inventory missing local submitted event")
	}
	inventory[1].Quantity = "9"
	if err := s.Adopt(t.Context(), p, inventory, "reviewed external evidence"); err == nil {
		t.Fatal("accepted changed local payload")
	}
	totals, err := s.Totals(t.Context(), p, "cpu")
	if err != nil || totals.Reserved != "10.000000000000" {
		t.Fatalf("failed adoption changed coverage: %+v %v", totals, err)
	}
	inventory[1].ExportPayload = local.ExportPayload
	for i := 0; i < 2; i++ {
		if err := s.Adopt(t.Context(), p, inventory, "reviewed complete provider inventory"); err != nil {
			t.Fatal(err)
		}
	}
	var source, status string
	if err := testPool.QueryRow(t.Context(), `SELECT source,status FROM billing_export_event WHERE id=$1 AND allocation_id=$2`, local.ID, local.AllocationID).Scan(&source, &status); err != nil || source != "export" || status != "submitted" {
		t.Fatalf("local event changed: %s %s %v", source, status, err)
	}
	totals, err = s.Totals(t.Context(), p, "cpu")
	if err != nil || totals.Reserved != "13.000000000000" || totals.Submitted != totals.Reserved {
		t.Fatalf("reconciled totals: %+v %v", totals, err)
	}
	if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=true WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID); err != nil {
		t.Fatal(err)
	}
	if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
		t.Fatalf("adoption queued a resubmission: %+v %v", event, err)
	}
	if event := reserveIncrement(t, s, p, "15"); event == nil || event.Quantity != "2.000000000000" {
		t.Fatalf("incorrect residual after external adoption: %+v", event)
	}
}

func assertIncrementalEventBoundaries(t *testing.T, identifier string, timestamp int64, through time.Time, coverageStart, coverageEnd string) {
	t.Helper()
	var gotTimestamp int64
	var gotThrough time.Time
	var gotStart, gotEnd string
	var coverageMatches bool
	if err := testPool.QueryRow(t.Context(), `SELECT e.event_timestamp,a.measured_through,a.coverage_start::text,a.coverage_end::text,
		a.coverage_start=$2::numeric AND a.coverage_end=$3::numeric
		FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id
		WHERE e.identifier=$1`, identifier, coverageStart, coverageEnd).Scan(&gotTimestamp, &gotThrough, &gotStart, &gotEnd, &coverageMatches); err != nil {
		t.Fatal(err)
	}
	if gotTimestamp != timestamp || !gotThrough.Equal(through) || !coverageMatches {
		t.Fatalf("event %s: timestamp=%d measured_through=%s coverage=[%s,%s), want timestamp=%d measured_through=%s coverage=[%s,%s)",
			identifier, gotTimestamp, gotThrough, gotStart, gotEnd, timestamp, through, coverageStart, coverageEnd)
	}
}

func TestIntegration_IncrementalAdoptionEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"incomplete_inventory", http.StatusBadRequest},
		{"unknown_additional_resource", http.StatusConflict},
		{"wrong_customer", http.StatusBadRequest},
		{"wrong_resource", http.StatusBadRequest},
		{"wrong_event_name", http.StatusBadRequest},
		{"timestamp_before_period", http.StatusBadRequest},
		{"timestamp_at_period_end", http.StatusBadRequest},
		{"boundary_after_event", http.StatusBadRequest},
		{"boundary_before_event", http.StatusBadRequest},
		{"boundary_outside_period", http.StatusBadRequest},
		{"provider_total_mismatch", http.StatusConflict},
		{"provider_unavailable", http.StatusConflict},
		{"valid_repeated_adoption", http.StatusOK},
		{"legacy_repeated_adoption", http.StatusOK},
		{"legacy_removed", http.StatusOK},
		{"legacy_disabled", http.StatusOK},
		{"legacy_renamed", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			team, periodID, start, end := seedBillingPeriodForStripe(t, true, false)
			if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id,stripe_customer_id,stripe_subscription_id,stripe_subscription_status,commercial_billing_anchor)
				VALUES($1,$2,$3,'active',$4)`, team, "cus_"+team.String(), "sub_"+team.String(), start); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled)
				VALUES($1,'billing_storage_billing_enabled',false)
				ON CONFLICT(team_id,key) DO UPDATE SET enabled=false`, team); err != nil {
				t.Fatal(err)
			}
			customer := "cus_" + team.String()
			through := start.Add(24 * time.Hour)
			events := []billing.AdoptedExport{
				{Resource: "cpu", Through: through, ExportPayload: billing.ExportPayload{
					Identifier: "manual-cpu-" + team.String(), IdempotencyKey: "manual-cpu-key-" + team.String(),
					EventName: "cpu_vcpu_hours", CustomerID: customer, Quantity: "1.25", Timestamp: through.Add(-time.Second).Unix(),
				}},
				{Resource: "memory", Through: through, ExportPayload: billing.ExportPayload{
					Identifier: "manual-memory-" + team.String(), IdempotencyKey: "manual-memory-key-" + team.String(),
					EventName: "memory_gib_hours", CustomerID: customer, Quantity: "2.5", Timestamp: through.Add(-time.Second).Unix(),
				}},
			}
			complete := true
			switch tc.name {
			case "incomplete_inventory":
				complete = false
			case "unknown_additional_resource":
				events = events[:1]
			case "wrong_customer":
				events[0].CustomerID = "cus_other_example"
			case "wrong_resource":
				events[0].Resource = "memory"
			case "wrong_event_name":
				events[0].EventName = "unknown_meter"
			case "timestamp_before_period":
				events[0].Timestamp = start.Add(-time.Second).Unix()
			case "timestamp_at_period_end":
				events[0].Timestamp = end.Unix()
			case "boundary_after_event":
				events[0].Through = through.Add(time.Hour)
			case "boundary_before_event":
				events[0].Through = through.Add(-time.Hour)
			case "boundary_outside_period":
				events[0].Through = end.Add(time.Hour)
			}
			if strings.HasPrefix(tc.name, "legacy_") {
				for _, event := range events {
					if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_usage_export
                        (team_id,period_start,period_end,resource_type,stripe_customer_id,stripe_meter_event_identifier,stripe_event_name,value,status,stripe_idempotency_key)
                        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'sent',$9)`, team, start, end, event.Resource, event.CustomerID, event.Identifier, event.EventName, event.Quantity, event.IdempotencyKey); err != nil {
						t.Fatal(err)
					}
				}
			}
			reads := make(map[string]int)
			stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
			stripe.countedUsage = func(eventName, gotCustomer string, gotStart, gotEnd time.Time) (string, error) {
				if gotCustomer != customer || !gotStart.Equal(start) || !gotEnd.Equal(end) {
					t.Fatalf("unexpected summary scope: %s %s %s", gotCustomer, gotStart, gotEnd)
				}
				reads[eventName]++
				if tc.name == "provider_unavailable" {
					return "", errors.New("provider summary unavailable")
				}
				switch eventName {
				case "cpu_vcpu_hours":
					if tc.name == "provider_total_mismatch" {
						return "1.5", nil
					}
					return "1.25", nil
				case "memory_gib_hours":
					return "2.5", nil
				case "renamed_cpu_hours":
					return "0", nil
				default:
					t.Fatalf("unexpected billable meter: %s", eventName)
					return "", nil
				}
			}
			body, err := json.Marshal(map[string]any{
				"complete_inventory": complete, "evidence": "reviewed complete provider inventory", "events": events,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
			r := newBillingRouter(t, stripe)
			if tc.name == "legacy_removed" || tc.name == "legacy_disabled" || tc.name == "legacy_renamed" {
				resources := []config.BillingResourceConfig{{ResourceKey: "memory_gib", Billable: true, CheckoutEnabled: true, StripeEventName: "memory_gib_hours"}}
				if tc.name != "legacy_removed" {
					resources = append(resources, config.BillingResourceConfig{ResourceKey: "vcpu", Billable: tc.name == "legacy_renamed", CheckoutEnabled: true, StripeEventName: "renamed_cpu_hours"})
				}
				r = newBillingRouterWithPool(t, stripe, testPool, resources...)
			}
			admin := seedPlatformAdminProfile(t)
			path := "/internal/teams/" + team.String() + "/billing/periods/" + periodID + "/adopt-exports"
			attempts := 1
			if tc.status == http.StatusOK {
				attempts = 2
			}
			var firstSnapshot string
			for attempt := 0; attempt < attempts; attempt++ {
				w := doBillingOperator(r, path, operatorRBACToken, admin.String(), string(body))
				if w.Code != tc.status {
					t.Fatalf("attempt %d: got %d, want %d: %s", attempt, w.Code, tc.status, w.Body.String())
				}
				var enabled bool
				if err := testPool.QueryRow(t.Context(), `SELECT feature_enabled('billing_export_enabled',$1)`, team).Scan(&enabled); err != nil || enabled {
					t.Fatalf("adoption enabled export: %v %v", enabled, err)
				}
				var allocations, persisted, adopted int
				if err := testPool.QueryRow(t.Context(), `SELECT
					(SELECT count(*) FROM billing_export_allocation WHERE team_id=$1),
					count(e.id), count(e.id) FILTER (WHERE e.source='adopted' AND e.status='adopted' AND e.attempt_count=0)
					FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id
					WHERE a.team_id=$1`, team).Scan(&allocations, &persisted, &adopted); err != nil {
					t.Fatal(err)
				}
				want := 0
				if tc.status == http.StatusOK {
					want = len(events)
					response := mustJSON(t, w)
					if response["adopted"] != float64(want) || response["export_enabled"] != false {
						t.Fatalf("unexpected handover response: %v", response)
					}
				}
				if allocations != want || persisted != want || adopted != want {
					t.Fatalf("allocations=%d events=%d adopted without attempts=%d, want %d", allocations, persisted, adopted, want)
				}
				if len(stripe.reportCalls) != 0 {
					t.Fatal("adoption submitted meter events")
				}
				if tc.status == http.StatusOK {
					for _, event := range events {
						assertIncrementalEventBoundaries(t, event.Identifier, event.Timestamp, through, "0", event.Quantity)
					}
					var snapshot string
					if err := testPool.QueryRow(t.Context(), `SELECT jsonb_agg(jsonb_build_object('allocation',to_jsonb(a),'event',to_jsonb(e)) ORDER BY e.id)::text
						FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1`, team).Scan(&snapshot); err != nil {
						t.Fatal(err)
					}
					if attempt == 0 {
						firstSnapshot = snapshot
					} else if snapshot != firstSnapshot {
						t.Fatal("repeated adoption mutated persisted allocations or events")
					}
					if reads["cpu_vcpu_hours"] != attempt+1 || reads["memory_gib_hours"] != attempt+1 {
						t.Fatalf("adoption did not verify both provider meters: %v", reads)
					}
				}
			}
			if tc.name == "unknown_additional_resource" && reads["memory_gib_hours"] != 1 {
				t.Fatalf("omitted resource was not checked with provider: %v", reads)
			}
		})
	}
}

func TestIntegration_IncrementalAdoptionRequiresSettledReservations(t *testing.T) {
	for _, status := range []string{"pending", "uncertain", "recovery_required", "rejected"} {
		t.Run(status, func(t *testing.T) {
			s, p := seedIncrementalPeriod(t)
			local := reserveIncrement(t, s, p, "10")
			if _, err := testPool.Exec(t.Context(), `UPDATE billing_export_event SET status=$2 WHERE id=$1`, local.ID, status); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID); err != nil {
				t.Fatal(err)
			}
			inventory := []billing.AdoptedExport{{Resource: "cpu", Through: p.End, ExportPayload: local.ExportPayload}}
			if err := s.Adopt(t.Context(), p, inventory, "reviewed inventory"); err == nil {
				t.Fatal("adoption accepted unresolved reservation")
			}
		})
	}
}

func TestIntegration_IncrementalPreloadAdoptionAndResidual(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID); err != nil {
		t.Fatal(err)
	}
	through := p.Start.Add(24 * time.Hour)
	events := []billing.AdoptedExport{
		{Resource: "cpu", Through: through, ExportPayload: billing.ExportPayload{Identifier: "preload-cpu-" + p.TeamID.String(), IdempotencyKey: "preload-key-cpu-" + p.TeamID.String(), EventName: "example_cpu_hours", CustomerID: "cus_example", Quantity: "10.125", Timestamp: through.Add(-time.Second).Unix()}},
		{Resource: "memory", Through: through, ExportPayload: billing.ExportPayload{Identifier: "preload-memory-" + p.TeamID.String(), IdempotencyKey: "preload-key-memory-" + p.TeamID.String(), EventName: "example_memory_hours", CustomerID: "cus_example", Quantity: "10.125", Timestamp: through.Add(-time.Second).Unix()}},
	}
	for i := 0; i < 2; i++ {
		if err := s.Adopt(t.Context(), p, events, "complete verified manual event inventory"); err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			assertIncrementalEventBoundaries(t, event.Identifier, event.Timestamp, through, "0", "10.125")
		}
	}
	if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=true WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID); err != nil {
		t.Fatal(err)
	}
	if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
		t.Fatalf("adoption submitted an external event: %v %v", event, err)
	}
	for _, preload := range events {
		if event, err := s.Reserve(t.Context(), p, preload.Resource, preload.Quantity, through, preload.ExportPayload); err != nil || event != nil {
			t.Fatalf("unchanged %s preload reserved again: %+v %v", preload.Resource, event, err)
		}
	}
	catchupThrough := through.Add(time.Hour)
	catchupTimestamp := catchupThrough.Add(-time.Second).Unix()
	event, err := s.Reserve(t.Context(), p, "cpu", "15.125", catchupThrough, billing.ExportPayload{
		EventName: events[0].EventName, CustomerID: events[0].CustomerID, Timestamp: catchupTimestamp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if event == nil || event.Quantity != "5.000000000000" {
		t.Fatalf("preload residual: %+v", event)
	}
	assertIncrementalEventBoundaries(t, event.Identifier, catchupTimestamp, catchupThrough, "10.125", "15.125")
	if submitted := acceptIncrement(t, s, p); submitted.ExportPayload != event.ExportPayload {
		t.Fatalf("catch-up submitted %+v, want residual %+v", submitted.ExportPayload, event.ExportPayload)
	}
	if repeated := reserveIncrement(t, s, p, "15.125"); repeated != nil {
		t.Fatalf("catch-up retry reserved usage again: %+v", repeated)
	}
	if extra, err := s.Claim(t.Context(), p); err != nil || extra != nil {
		t.Fatalf("catch-up queued more than the residual: %+v %v", extra, err)
	}
	if _, err := s.Reserve(t.Context(), p, "cpu", "9", p.End, billing.ExportPayload{}); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("downward correction: %v", err)
	}
	_, err = testPool.Exec(t.Context(), `UPDATE billing_export_event SET quantity_payload='11' WHERE identifier=$1`, events[0].Identifier)
	if err == nil {
		t.Fatal("adopted payload was mutable")
	}
	_, err = testPool.Exec(t.Context(), `INSERT INTO billing_usage_export(team_id,period_start,period_end,resource_type,stripe_customer_id,stripe_meter_event_identifier,stripe_event_name,value,status)
        VALUES($1,$2,$3,'cpu','cus_example','legacy-overlap','example_cpu_hours',15.125,'pending')`, p.TeamID, p.Start, p.End)
	if err == nil {
		t.Fatal("legacy writer bypassed enrollment fence")
	}
	if _, err = testPool.Exec(t.Context(), `UPDATE team_billing_usage SET vcpu_seconds=15.125*3600,memory_mib_seconds=10.125*3600*1024,storage_mib_seconds=0
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End); err != nil {
		t.Fatal(err)
	}
	if _, err = testPool.Exec(t.Context(), `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at)
        VALUES($1,100,100,'example contractual credit',$2)`, p.TeamID, p.Start); err != nil {
		t.Fatal(err)
	}
	if _, err = testPool.Exec(t.Context(), `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
        VALUES($1,$2,$3,'cpu',15.125,15.125,15.125,15.125,$2,$3),($1,$2,$3,'memory',10.125,10.125,10.125,10.125,$2,$3)`, p.TeamID, p.Start, p.End); err != nil {
		t.Fatal(err)
	}
	if _, err = testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported',exported_at=now()
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = billing.FinalizeTeamBillingPeriodWithCredits(t.Context(), testPool, p.TeamID, p.Start, p.End); err != nil {
			t.Fatal(err)
		}
	}
	var ledgerCount int
	if err = testPool.QueryRow(t.Context(), `SELECT count(*) FROM team_credit_ledger WHERE team_id=$1`, p.TeamID).Scan(&ledgerCount); err != nil {
		t.Fatal(err)
	}
	if ledgerCount != 1 {
		t.Fatalf("credit ledger consumed %d times", ledgerCount)
	}
	rejected := billing.ExportEvent{ExportPayload: events[0].ExportPayload}
	if err = testPool.QueryRow(t.Context(), `SELECT id FROM billing_export_event WHERE identifier=$1`, rejected.Identifier).Scan(&rejected.ID); err != nil {
		t.Fatal(err)
	}
	frozenState := func() string {
		t.Helper()
		var state string
		if err := testPool.QueryRow(t.Context(), `SELECT jsonb_build_array(
            (SELECT to_jsonb(p) FROM team_billing_period p WHERE team_id=$1 AND period_start=$2 AND period_end=$3),
            (SELECT to_jsonb(u) FROM team_billing_usage u WHERE team_id=$1 AND period_start=$2 AND period_end=$3),
            (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.id) FROM team_credit_ledger l WHERE team_id=$1),
            (SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM team_credit_grant g WHERE team_id=$1))::text`,
			p.TeamID, p.Start, p.End).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	beforeRecovery := frozenState()
	if _, err = s.Reject(t.Context(), rejected.Identifier, "", rejected.CustomerID, rejected.EventName, "post-finalization discrepancy"); err != nil {
		t.Fatal(err)
	}
	if got := billingPeriodStatus(t, p.TeamID, p.Start, p.End); got != "finalized" {
		t.Fatalf("late rejection mutated finalized period: %s", got)
	}
	if _, err = testPool.Exec(t.Context(), `UPDATE team_billing_account SET commercial_billing_anchor=$2,stripe_subscription_status='canceled' WHERE team_id=$1`, p.TeamID, p.Start); err != nil {
		t.Fatal(err)
	}
	stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
	stripe.countedUsage = func(eventName, customer string, start, end time.Time) (string, error) {
		if eventName == "cpu_vcpu_hours" {
			return "15.125", nil
		}
		return "10.125", nil
	}
	admin := seedPlatformAdminProfile(t)
	t.Setenv("OPERATOR_API_TOKEN", operatorRBACToken)
	r := newBillingRouter(t, stripe)
	recoveryPath := "/internal/billing/export-events/" + rejected.ID.String() + "/recover"
	w := doBillingOperator(r, recoveryPath, operatorRBACToken, admin.String(), `{"evidence":"reviewed definitive rejection after finalization"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("finalized recovery: %d %s", w.Code, w.Body.String())
	}
	w = doBillingOperator(r, recoveryPath, operatorRBACToken, admin.String(), `{"evidence":"duplicate recovery request"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate finalized recovery: %d %s", w.Code, w.Body.String())
	}
	if _, err = s.Reserve(t.Context(), p, "cpu", "16", p.End, billing.ExportPayload{}); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("finalized recovery allowed new coverage: %v", err)
	}
	exportPath := "/internal/teams/" + p.TeamID.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
	for i := 0; i < 2; i++ {
		w = doInternal(r, "POST", exportPath, admin.String(), "")
		if w.Code != http.StatusOK {
			t.Fatalf("finalized correction submission: %d %s", w.Code, w.Body.String())
		}
	}
	if len(stripe.reportCalls) != 1 {
		t.Fatalf("finalized correction submitted %d events, want one", len(stripe.reportCalls))
	}
	correction := stripe.reportCalls[0]
	if correction.Identifier == rejected.Identifier || correction.IdempotencyKey == rejected.IdempotencyKey ||
		correction.Value != rejected.Quantity || correction.Timestamp != rejected.Timestamp ||
		correction.EventName != rejected.EventName || correction.CustomerID != rejected.CustomerID {
		t.Fatalf("finalized correction changed coverage/payload: %+v", correction)
	}
	if _, err = s.Reject(t.Context(), rejected.Identifier, "", rejected.CustomerID, rejected.EventName, "duplicate original rejection"); err != nil {
		t.Fatal(err)
	}
	totals, err := s.Totals(t.Context(), p, "cpu")
	if err != nil || totals.Submitted != "15.125000000000" || totals.Rejected != "0" {
		t.Fatalf("finalized corrected accounting: %+v %v", totals, err)
	}
	if after := frozenState(); after != beforeRecovery {
		t.Fatalf("correction mutated frozen totals or credits: before=%s after=%s", beforeRecovery, after)
	}
	correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status='active' WHERE team_id=$1`, p.TeamID)
	next := billing.ExportPeriod{TeamID: p.TeamID, Start: p.End, End: p.End.AddDate(0, 1, 0)}
	if _, err = testPool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'open')`, next.TeamID, next.Start, next.End); err != nil {
		t.Fatal(err)
	}
	if err = s.Enroll(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	continuation := reserveIncrement(t, s, next, "1")
	if continuation == nil || continuation.Quantity != "1.000000000000" {
		t.Fatalf("next-period continuation: %+v", continuation)
	}

}

func TestIntegration_IncrementalInactiveSubscriptionFrozenCorrection(t *testing.T) {
	for _, status := range []string{"exported", "finalized"} {
		for _, subscription := range []string{"canceled", "past_due", ""} {
			t.Run(status+"/"+subscription, func(t *testing.T) {
				s, p, actor, payload := frozenCorrectionFixture(t)
				if _, err := s.Reserve(t.Context(), p, "memory", "10", p.End, billing.ExportPayload{
					EventName: "example_memory_hours", CustomerID: payload.CustomerID, Timestamp: payload.Timestamp,
				}); err != nil {
					t.Fatal(err)
				}
				acceptIncrement(t, s, p)
				correctionExec(t, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,
        local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
        VALUES($1,$2,$3,'cpu',10,10,10,10,$2,$3),($1,$2,$3,'memory',10,10,10,10,$2,$3)`, p.TeamID, p.Start, p.End)
				correctionExec(t, `UPDATE team_billing_period SET status=$2,exported_at=now(),
        finalized_at=CASE WHEN $2='finalized' THEN now() ELSE NULL END,
        gross_charges_usd=CASE WHEN $2='finalized' THEN 1 ELSE NULL END,
        credits_applied_usd=CASE WHEN $2='finalized' THEN 0.25 ELSE NULL END,
        net_invoice_amount_usd=CASE WHEN $2='finalized' THEN 0.75 ELSE NULL END WHERE team_id=$1`, p.TeamID, status)
				correctionExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2,
        stripe_subscription_status=NULLIF($3,'') WHERE team_id=$1`, p.TeamID, p.Start, subscription)
				correctionExec(t, `UPDATE sandbox_compute_billing_interval SET ended_at=started_at+interval '12 hours' WHERE team_id=$1`, p.TeamID)
				measured, err := s.MeasureCorrection(t.Context(), p, "cpu")
				if err != nil {
					t.Fatal(err)
				}
				if err := s.ApplyCorrection(t.Context(), measured.ID, actor, "accept_usage", "reviewed additional usage", payload); err != nil {
					t.Fatal(err)
				}
				stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
				stripe.countedUsage = func(eventName, customer string, start, end time.Time) (string, error) {
					if eventName == "cpu_vcpu_hours" {
						return "12", nil
					}
					return "10", nil
				}
				r := newBillingRouter(t, stripe)
				path := "/internal/teams/" + p.TeamID.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
				for i := 0; i < 2; i++ {
					w := doInternal(r, "POST", path, actor.String(), "")
					if w.Code != http.StatusOK {
						t.Fatalf("frozen correction: %d %s", w.Code, w.Body.String())
					}
				}
				if len(stripe.reportCalls) != 1 || stripe.reportCalls[0].Value != "2.000000000000" {
					t.Fatalf("expected one correction delivery: %+v", stripe.reportCalls)
				}
				if got := billingPeriodStatus(t, p.TeamID, p.Start, p.End); got != status {
					t.Fatalf("frozen status changed: %s", got)
				}
			})
		}
	}
}

func TestIntegration_IncrementalInactiveSubscriptionCannotEnrollOrAllocate(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		for _, status := range []string{"open", "approved"} {
			t.Run(fmt.Sprintf("%s/enrolled=%v", status, enrolled), func(t *testing.T) {
				team, _, start, end := seedBillingPeriodForStripe(t, true, true)
				p := billing.ExportPeriod{TeamID: team, Start: start, End: end}
				if enrolled {
					if err := (billing.ExportStore{Pool: testPool}).Enroll(t.Context(), p); err != nil {
						t.Fatal(err)
					}
				}
				correctionExec(t, `UPDATE team_billing_period SET status=$2 WHERE team_id=$1`, team, status)
				correctionExec(t, `UPDATE team_billing_account SET commercial_billing_anchor=$2,
        stripe_subscription_status='canceled' WHERE team_id=$1`, team, start)
				stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
				r := newBillingRouter(t, stripe)
				admin := seedPlatformAdminProfile(t)
				path := "/internal/teams/" + team.String() + "/billing/periods/" + apiPeriodID(start, end) + "/export"
				w := doInternal(r, "POST", path, admin.String(), "")
				if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "active subscription") {
					t.Fatalf("inactive allocation: %d %s", w.Code, w.Body.String())
				}
				var gotEnrolled bool
				var allocations int
				if err := testPool.QueryRow(t.Context(), `SELECT
        EXISTS(SELECT 1 FROM billing_incremental_period WHERE team_id=$1),
        (SELECT count(*) FROM billing_export_allocation WHERE team_id=$1)`, team).Scan(&gotEnrolled, &allocations); err != nil {
					t.Fatal(err)
				}
				if gotEnrolled != enrolled || allocations != 0 || len(stripe.reportCalls) != 0 {
					t.Fatalf("inactive subscription enrolled=%v allocations=%d submissions=%d", gotEnrolled, allocations, len(stripe.reportCalls))
				}
			})
		}
	}
}

func TestIntegration_IncrementalCloseExportsResidualAndRetriesUnresolved(t *testing.T) {
	for _, subscription := range []string{"active", "canceled", "past_due", ""} {
		t.Run("subscription="+subscription, func(t *testing.T) {
			testIncrementalCloseRetriesUnresolved(t, subscription)
		})
	}
}

func testIncrementalCloseRetriesUnresolved(t *testing.T, subscription string) {
	t.Helper()
	s, p := seedIncrementalPeriod(t)
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, p.TeamID, p.Start); err != nil {
		t.Fatal(err)
	}
	customer := "cus_" + p.TeamID.String()
	resources := map[string]string{"cpu": "cpu_vcpu_hours", "memory": "memory_gib_hours"}
	accepted := make(map[string]billing.ExportPayload)
	for resource, eventName := range resources {
		through := p.Start.Add(time.Hour)
		event, err := s.Reserve(t.Context(), p, resource, "0.75", through, billing.ExportPayload{
			EventName: eventName, CustomerID: customer, Timestamp: through.Add(-time.Second).Unix(),
		})
		if err != nil || event == nil {
			t.Fatalf("reserve partial increment: %+v %v", event, err)
		}
		initial := acceptIncrement(t, s, p)
		accepted[initial.Identifier] = initial.ExportPayload
	}
	stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{reportErr: errors.New("submission timeout"), reportErrAt: 1}}
	stripe.countedUsage = func(eventName, gotCustomer string, start, end time.Time) (string, error) {
		if gotCustomer != customer || !start.Equal(p.Start) || !end.Equal(p.End) {
			t.Fatalf("unexpected summary scope: %s %s %s", gotCustomer, start, end)
		}
		for i, call := range stripe.reportCalls {
			// The first attempt timed out without provider acceptance.
			if i == 0 {
				continue
			}
			payload := billing.ExportPayload{Identifier: call.Identifier, IdempotencyKey: call.IdempotencyKey,
				EventName: call.EventName, CustomerID: call.CustomerID, Quantity: call.Value, Timestamp: call.Timestamp}
			if prior, exists := accepted[call.Identifier]; exists && prior != payload {
				t.Fatalf("retry changed accepted payload: %+v %+v", prior, payload)
			}
			accepted[call.Identifier] = payload
		}
		total := new(big.Rat)
		for _, event := range accepted {
			if event.EventName == eventName {
				quantity, ok := new(big.Rat).SetString(event.Quantity)
				if !ok {
					t.Fatalf("invalid quantity: %s", event.Quantity)
				}
				total.Add(total, quantity)
			}
		}
		return total.FloatString(12), nil
	}
	admin := seedPlatformAdminProfile(t)
	r := newBillingRouter(t, stripe)
	path := "/internal/teams/" + p.TeamID.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
	w := doInternal(r, "POST", path, admin.String(), "")
	if w.Code != http.StatusConflict {
		t.Fatalf("unresolved close: %d %s", w.Code, w.Body.String())
	}
	if got := billingPeriodStatus(t, p.TeamID, p.Start, p.End); got != "exporting" {
		t.Fatalf("unresolved close status: %s", got)
	}
	if _, err := billing.FinalizeTeamBillingPeriodWithCredits(t.Context(), testPool, p.TeamID, p.Start, p.End); err == nil {
		t.Fatal("finalized with unresolved residual")
	}
	if len(stripe.reportCalls) != 2 {
		t.Fatalf("close submitted %d events, want two residuals", len(stripe.reportCalls))
	}
	for _, call := range stripe.reportCalls {
		if call.Value != "1.250000000000" {
			t.Fatalf("close submitted %s, want residual 1.25", call.Value)
		}
	}
	failed := stripe.reportCalls[0]
	var state string
	if err := testPool.QueryRow(t.Context(), `SELECT status FROM billing_export_event WHERE identifier=$1`, failed.Identifier).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "uncertain" {
		t.Fatalf("failed residual status: %s", state)
	}
	correctionExec(t, `UPDATE team_billing_account SET stripe_subscription_status=NULLIF($2,'') WHERE team_id=$1`, p.TeamID, subscription)
	if _, err := testPool.Exec(t.Context(), `UPDATE billing_export_event SET next_attempt_at=now() WHERE identifier=$1`, failed.Identifier); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		w = doInternal(r, "POST", path, admin.String(), "")
		if w.Code != http.StatusOK {
			t.Fatalf("resolved close %d: %d %s", i, w.Code, w.Body.String())
		}
		if got := billingPeriodStatus(t, p.TeamID, p.Start, p.End); got != "exported" {
			t.Fatalf("resolved close status: %s", got)
		}
		if len(stripe.reportCalls) != 3 || stripe.reportCalls[2] != failed {
			t.Fatalf("close did not retry only the unchanged residual: %+v", stripe.reportCalls)
		}
	}
	for resource, eventName := range resources {
		counted, err := stripe.CountedMeterUsage(t.Context(), eventName, customer, p.Start, p.End)
		if err != nil || counted != "2.000000000000" {
			t.Fatalf("final provider quantity for %s: %s %v", resource, counted, err)
		}
		totals, err := s.Totals(t.Context(), p, resource)
		if err != nil || totals.Submitted != counted || totals.Reserved != counted || totals.Pending != "0" || totals.Rejected != "0" {
			t.Fatalf("final accounting for %s: %+v %v", resource, totals, err)
		}
	}
	var authoritativeCPU, authoritativeMemory string
	if err := testPool.QueryRow(t.Context(), `SELECT (vcpu_seconds/3600)::text,(memory_mib_seconds/(3600*1024))::text
		FROM team_billing_usage WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&authoritativeCPU, &authoritativeMemory); err != nil {
		t.Fatal(err)
	}
	for _, quantity := range []string{authoritativeCPU, authoritativeMemory} {
		got, ok := new(big.Rat).SetString(quantity)
		if !ok || got.Cmp(big.NewRat(2, 1)) != 0 {
			t.Fatalf("authoritative final quantity: %s, want 2", quantity)
		}
	}
	if len(accepted) != 4 {
		t.Fatalf("accepted %d unique events, want two initial increments and two residuals", len(accepted))
	}
	if _, err := billing.FinalizeTeamBillingPeriodWithCredits(t.Context(), testPool, p.TeamID, p.Start, p.End); err != nil {
		t.Fatalf("finalize resolved close: %v", err)
	}
}

func TestIntegration_IncrementalCloseRequiresProviderEvidence(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	reserveIncrement(t, s, p, "2")
	event := acceptIncrement(t, s, p)
	_, err := testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported',exported_at=now() WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End)
	if err == nil {
		t.Fatal("closed on submission alone")
	}
	_, err = testPool.Exec(t.Context(), `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
        VALUES($1,$2,$3,'cpu',2,2,2,2,$2,$3)`, p.TeamID, p.Start, p.End)
	if err != nil {
		t.Fatal(err)
	}
	_, err = testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported',exported_at=now() WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Reject(t.Context(), event.Identifier, "", event.CustomerID, event.EventName, "late rejection"); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = testPool.QueryRow(t.Context(), `SELECT status FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "exporting" {
		t.Fatalf("late rejection did not block finalization: %s", status)
	}
}

func TestIntegration_IncrementalReservationQueryPlan(t *testing.T) {
	_, p := seedIncrementalPeriod(t)
	_, err := testPool.Exec(t.Context(), `INSERT INTO billing_export_allocation(team_id,period_start,period_end,resource_type,coverage_start,coverage_end,measured_through)
        SELECT $1,$2,$3,'cpu',n-1,n,$3 FROM generate_series(1,1000) n ORDER BY n`, p.TeamID, p.Start, p.End)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = testPool.Exec(t.Context(), `ANALYZE billing_export_allocation`); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	err = testPool.QueryRow(t.Context(), `EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON)
        SELECT coverage_end FROM billing_export_allocation WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type='cpu'
        ORDER BY coverage_end DESC LIMIT 1`, p.TeamID, p.Start, p.End).Scan(&raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("reservation lookup with 1000 increments: %s", raw)
	var plans []map[string]any
	if err = json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(err)
	}
	var inspect func(map[string]any)
	inspect = func(node map[string]any) {
		rows, _ := node["Actual Rows"].(float64)
		removed, _ := node["Rows Removed by Filter"].(float64)
		rechecked, _ := node["Rows Removed by Index Recheck"].(float64)
		loops, _ := node["Actual Loops"].(float64)
		if (rows+removed+rechecked)*loops > 32 {
			t.Errorf("reservation lookup scanned too many rows: %v", node)
		}
		if children, ok := node["Plans"].([]any); ok {
			for _, child := range children {
				inspect(child.(map[string]any))
			}
		}
	}
	inspect(plans[0]["Plan"].(map[string]any))
}

func TestIntegration_IncrementalExpiredRecoveryResolution(t *testing.T) {
	for _, outcome := range []string{"accepted", "rejected"} {
		t.Run(outcome, func(t *testing.T) {
			s, p := seedIncrementalPeriod(t)
			original := reserveIncrement(t, s, p, "10")
			claimed, err := s.Claim(t.Context(), p)
			if err != nil || claimed == nil {
				t.Fatalf("claim: %v %v", claimed, err)
			}
			reserveIncrement(t, s, p, "15")
			later := acceptIncrement(t, s, p)
			if _, err = testPool.Exec(t.Context(), `UPDATE billing_export_event SET first_attempt_at=now()-interval '24 hours',lease_until=now()-interval '1 second' WHERE id=$1`, original.ID); err != nil {
				t.Fatal(err)
			}
			if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
				t.Fatalf("expired claim: %v %v", event, err)
			}
			if err = s.RecoverRejected(t.Context(), original.ID, "no confirmed rejection"); err == nil {
				t.Fatal("uncertain event replaced without resolution")
			}
			for _, invalid := range []struct{ outcome, evidence string }{{outcome, " \n"}, {"unknown", "reviewed"}} {
				if err = s.ResolveRecovery(t.Context(), original.ID, invalid.outcome, invalid.evidence); err == nil {
					t.Fatal("invalid resolution accepted")
				}
			}
			if _, err = testPool.Exec(t.Context(), `UPDATE billing_export_event SET status='submitted' WHERE id=$1`, original.ID); err == nil {
				t.Fatal("accepted expired event without evidence")
			}
			const evidence = "reviewed provider event identity, payload and definitive outcome"
			if err = s.ResolveRecovery(t.Context(), original.ID, outcome, evidence); err != nil {
				t.Fatal(err)
			}
			if err = s.ResolveRecovery(t.Context(), original.ID, outcome, evidence); !errors.Is(err, billing.ErrExportRecoveryRequired) {
				t.Fatalf("duplicate resolution: %v", err)
			}
			if err = s.Acknowledge(t.Context(), *claimed, nil); !errors.Is(err, billing.ErrExportRecoveryRequired) {
				t.Fatalf("stale acknowledgement: %v", err)
			}
			if event := reserveIncrement(t, s, p, "15"); event != nil {
				t.Fatal("resolution released reserved coverage")
			}
			if outcome == "accepted" {
				if _, err = testPool.Exec(t.Context(), `INSERT INTO billing_export_observation
                    (team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
                    VALUES($1,$2,$3,'cpu',15,15,15,15,date_trunc('minute',$2::timestamptz),date_trunc('minute',$3::timestamptz))`, p.TeamID, p.Start, p.End); err != nil {
					t.Fatal(err)
				}
				if _, err = testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported',exported_at=now()
                    WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End); err != nil {
					t.Fatal(err)
				}
			}
			var periodBefore, periodAfter string
			if err = testPool.QueryRow(t.Context(), `SELECT to_jsonb(p)::text FROM team_billing_period p
                WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&periodBefore); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if found, err := s.Reject(t.Context(), original.Identifier, original.IdempotencyKey, original.CustomerID, original.EventName, "delayed rejection"); err != nil || !found {
					t.Fatalf("resolved callback: %v %v", found, err)
				}
			}
			var status, callbackEvidence string
			if err = testPool.QueryRow(t.Context(), `SELECT status,last_error FROM billing_export_event WHERE id=$1`, original.ID).Scan(&status, &callbackEvidence); err != nil {
				t.Fatal(err)
			}
			wantStatus, wantCallbackEvidence := "rejected", "delayed rejection"
			if outcome == "accepted" {
				wantStatus = "submitted"
				wantCallbackEvidence = "rejection callback contradicts reviewed acceptance: delayed rejection"
			}
			if status != wantStatus || callbackEvidence != wantCallbackEvidence {
				t.Fatalf("callback changed resolution or lost evidence: %s %q", status, callbackEvidence)
			}
			if err = testPool.QueryRow(t.Context(), `SELECT to_jsonb(p)::text FROM team_billing_period p
                WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&periodAfter); err != nil || periodAfter != periodBefore {
				t.Fatalf("resolved callback changed period: before=%s after=%s err=%v", periodBefore, periodAfter, err)
			}
			var payload billing.ExportPayload
			var recordedOutcome, recordedEvidence string
			err = testPool.QueryRow(t.Context(), `SELECT identifier,idempotency_key,event_name,customer_id,quantity_payload,event_timestamp,recovery_outcome,recovery_evidence FROM billing_export_event WHERE id=$1`, original.ID).
				Scan(&payload.Identifier, &payload.IdempotencyKey, &payload.EventName, &payload.CustomerID, &payload.Quantity, &payload.Timestamp, &recordedOutcome, &recordedEvidence)
			if err != nil || payload != original.ExportPayload || recordedOutcome != outcome || recordedEvidence != evidence {
				t.Fatalf("resolution altered payload or lost evidence: %+v %s %s %v", payload, recordedOutcome, recordedEvidence, err)
			}
			if _, err = testPool.Exec(t.Context(), `UPDATE billing_export_event SET recovery_evidence='changed' WHERE id=$1`, original.ID); err == nil {
				t.Fatal("resolution evidence was mutable")
			}
			if outcome == "rejected" {
				if err = s.RecoverRejected(t.Context(), original.ID, "reviewed replacement after definitive rejection"); err != nil {
					t.Fatal(err)
				}
				replacement := acceptIncrement(t, s, p)
				if replacement.AllocationID != original.AllocationID || replacement.Quantity != original.Quantity || replacement.Identifier == original.Identifier {
					t.Fatalf("invalid replacement: %+v", replacement)
				}
			} else if err = s.RecoverRejected(t.Context(), original.ID, evidence); err == nil {
				t.Fatal("accepted resolution was replaced")
			}
			totals, err := s.Totals(t.Context(), p, "cpu")
			if err != nil || totals.Submitted != "15.000000000000" || totals.Reserved != "15.000000000000" || totals.Rejected != "0" {
				t.Fatalf("resolved accounting: %+v %v", totals, err)
			}
			var laterStatus string
			if err = testPool.QueryRow(t.Context(), `SELECT status FROM billing_export_event WHERE id=$1`, later.ID).Scan(&laterStatus); err != nil || laterStatus != "submitted" {
				t.Fatalf("later event changed: %s %v", laterStatus, err)
			}
			if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
				t.Fatalf("resolved coverage was resubmitted: %v %v", event, err)
			}
		})
	}
}

func TestIntegration_IncrementalRejectionRollsBackWithTransaction(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	reserveIncrement(t, s, p, "10")
	first := acceptIncrement(t, s, p)
	if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
        VALUES($1,$2,$3,'cpu',10,10,10,10,$2,$3)`, p.TeamID, p.Start, p.End); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported',exported_at=now()
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End); err != nil {
		t.Fatal(err)
	}
	tx, err := testPool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if handled, err := s.RejectTx(t.Context(), tx, first.Identifier, "", first.CustomerID, first.EventName, "example rejection"); err != nil || !handled {
		t.Fatalf("reject in transaction: handled=%v err=%v", handled, err)
	}
	var eventStatus, periodStatus string
	if err := tx.QueryRow(t.Context(), `SELECT status FROM billing_export_event WHERE id=$1`, first.ID).Scan(&eventStatus); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(t.Context(), `SELECT status FROM team_billing_period
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&periodStatus); err != nil {
		t.Fatal(err)
	}
	if eventStatus != "rejected" || periodStatus != "exporting" {
		t.Fatalf("transaction did not apply rejection: event=%s period=%s", eventStatus, periodStatus)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var exportedAtPresent bool
	if err := testPool.QueryRow(t.Context(), `SELECT status FROM billing_export_event WHERE id=$1`, first.ID).Scan(&eventStatus); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(t.Context(), `SELECT status,exported_at IS NOT NULL FROM team_billing_period
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End).Scan(&periodStatus, &exportedAtPresent); err != nil {
		t.Fatal(err)
	}
	if eventStatus != "submitted" || periodStatus != "exported" || !exportedAtPresent {
		t.Fatalf("rejection escaped rollback: event=%s period=%s exported_at_present=%v", eventStatus, periodStatus, exportedAtPresent)
	}
}

func TestIntegration_IncrementalEarlierRejectionThroughWebhook(t *testing.T) {
	poolConfig := testPool.Config()
	poolConfig.MaxConns = 1
	poolConfig.MinConns = 0
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, eventType := range []string{"v1.billing.meter.error_report_triggered", "v1.billing.meter.no_meter_found"} {
		for _, identity := range []string{"identifier", "idempotency_key", "both", "conflicting_keys", "wrong_customer", "wrong_event"} {
			t.Run(eventType+"/"+identity, func(t *testing.T) {
				s, p := seedIncrementalPeriod(t)
				reserveIncrement(t, s, p, "10")
				first := acceptIncrement(t, s, p)
				reserveIncrement(t, s, p, "15")
				later := acceptIncrement(t, s, p)
				key := first.Identifier
				if identity == "idempotency_key" {
					key = first.IdempotencyKey
				}
				request := map[string]any{"identifier": first.Identifier, "idempotency_key": first.IdempotencyKey,
					"event_name": first.EventName, "payload": map[string]any{"stripe_customer_id": first.CustomerID}}
				wantRejected := true
				switch identity {
				case "identifier", "idempotency_key":
					request = map[string]any{identity: key}
				case "conflicting_keys":
					request["idempotency_key"] = later.IdempotencyKey
					wantRejected = false
				case "wrong_customer":
					request["payload"] = map[string]any{"stripe_customer_id": "cus_other"}
					wantRejected = false
				case "wrong_event":
					request["event_name"] = "example_memory_hours"
					wantRejected = false
				}
				retrieved, err := json.Marshal(map[string]any{"data": map[string]any{
					"reason": map[string]any{"error_types": []any{map[string]any{"sample_errors": []any{map[string]any{
						"request": request, "error_message": "meter rejected earlier increment",
					}}}}},
				}})
				if err != nil {
					t.Fatal(err)
				}
				stripe := &thinEventStripeClient{fakeStripeClient: &fakeStripeClient{}, retrieved: retrieved}
				r := newBillingRouterWithPool(t, stripe, pool)
				payload, err := json.Marshal(map[string]any{"id": "evt_" + first.ID.String(), "type": eventType, "created": "2026-07-02T12:00:00.000Z"})
				if err != nil {
					t.Fatal(err)
				}
				for attempt := 0; attempt < 2; attempt++ {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					req := httptest.NewRequestWithContext(ctx, "POST", "/stripe/webhook", strings.NewReader(string(payload)))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Stripe-Signature", stripeSignature(t, payload, time.Now().UTC(), testStripeMeterErrorWebhookSecret))
					if w := doRequest(r, req); w.Code != http.StatusOK {
						t.Fatalf("webhook attempt %d: %d %s", attempt, w.Code, w.Body.String())
					}
				}
				var laterStatus, laterPayload string
				if err := testPool.QueryRow(t.Context(), `SELECT status,quantity_payload FROM billing_export_event WHERE id=$1`, later.ID).Scan(&laterStatus, &laterPayload); err != nil {
					t.Fatal(err)
				}
				if laterStatus != "submitted" || laterPayload != later.Quantity {
					t.Fatalf("later event changed: %s %s", laterStatus, laterPayload)
				}
				totals, err := s.Totals(t.Context(), p, "cpu")
				if err != nil {
					t.Fatal(err)
				}
				wantSubmitted, wantRejectedTotal := "15.000000000000", "0"
				if wantRejected {
					wantSubmitted, wantRejectedTotal = "5.000000000000", "10.000000000000"
				}
				if totals.Submitted != wantSubmitted || totals.Rejected != wantRejectedTotal || totals.Reserved != "15.000000000000" {
					t.Fatalf("webhook accounting: %+v", totals)
				}
				if event := reserveIncrement(t, s, p, "15"); event != nil {
					t.Fatalf("rejection released coverage: %+v", event)
				}
				if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
					t.Fatalf("callback queued speculative retry: %+v %v", event, err)
				}
				if len(stripe.reportCalls) != 0 {
					t.Fatal("webhook resubmitted usage")
				}
			})
		}
	}
}

func TestIntegration_IncrementalProviderDiscrepancyAndOutageBlockClose(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, p.TeamID, p.Start); err != nil {
		t.Fatal(err)
	}
	admin := seedPlatformAdminProfile(t)
	phase := "mismatch"
	reads := make(map[string]int)
	stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
	stripe.countedUsage = func(eventName, customer string, start, end time.Time) (string, error) {
		if customer != "cus_"+p.TeamID.String() || !start.Equal(p.Start) || !end.Equal(p.End) {
			t.Fatalf("unexpected summary scope: %s %s %s", customer, start, end)
		}
		reads[eventName]++
		if phase == "outage" && reads[eventName]%2 == 0 {
			return "", errors.New("provider summary unavailable")
		}
		if phase == "recovered" {
			return "2", nil
		}
		if len(stripe.reportCalls) == 0 {
			return "0", nil
		}
		return "1", nil
	}
	r := newBillingRouter(t, stripe)
	path := "/internal/teams/" + p.TeamID.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
	for _, mode := range []string{"mismatch", "outage", "recovered"} {
		phase = mode
		clear(reads)
		w := doInternal(r, "POST", path, admin.String(), "")
		if mode == "recovered" {
			if w.Code != http.StatusOK {
				t.Fatalf("reconciled close: %d %s", w.Code, w.Body.String())
			}
		} else if w.Code != http.StatusConflict {
			t.Fatalf("%s close: got %d, want conflict: %s", mode, w.Code, w.Body.String())
		}
		if len(stripe.reportCalls) != 2 {
			t.Fatalf("%s submitted %d events, want original two", mode, len(stripe.reportCalls))
		}
		for _, resource := range []string{"cpu", "memory"} {
			var local, submitted, reserved string
			var counted, lastError *string
			if err := testPool.QueryRow(t.Context(), `SELECT local_quantity::text,submitted_quantity::text,reserved_quantity::text,counted_quantity::text,last_error
				FROM billing_export_observation WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type=$4`, p.TeamID, p.Start, p.End, resource).Scan(&local, &submitted, &reserved, &counted, &lastError); err != nil {
				t.Fatal(err)
			}
			if local != "2.000000000000" || submitted != local || reserved != local {
				t.Fatalf("%s accounting: %s %s %s", mode, local, submitted, reserved)
			}
			if mode == "outage" {
				if counted != nil || lastError == nil || *lastError != "provider summary unavailable" {
					t.Fatalf("outage not observable: counted=%v error=%v", counted, lastError)
				}
			} else {
				want := "1"
				if mode == "recovered" {
					want = "2"
				}
				if counted == nil || *counted != want || lastError != nil {
					t.Fatalf("%s observation: counted=%v error=%v", mode, counted, lastError)
				}
			}
			totals, err := s.Totals(t.Context(), p, resource)
			if err != nil {
				t.Fatal(err)
			}
			if totals.Submitted != "2.000000000000" || totals.Reserved != totals.Submitted {
				t.Fatalf("provider uncertainty changed event accounting: %+v", totals)
			}
		}
		wantStatus := "exporting"
		if mode == "recovered" {
			wantStatus = "exported"
		}
		if got := billingPeriodStatus(t, p.TeamID, p.Start, p.End); got != wantStatus {
			t.Fatalf("%s period status: %s", mode, got)
		}
	}
	if stripe.reportCalls[0].Identifier == stripe.reportCalls[1].Identifier || stripe.reportCalls[0].EventName == stripe.reportCalls[1].EventName {
		t.Fatal("submitted duplicate resource payload")
	}
	var events int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_export_event e JOIN billing_export_allocation a ON a.id=e.allocation_id WHERE a.team_id=$1`, p.TeamID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatalf("reconciliation created %d events, want 2", events)
	}
}

func doBillingOperator(r *gin.Engine, path, token, actor, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("X-Actor-User-Id", actor)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestIntegration_IncrementalMutationOperatorAuthorization(t *testing.T) {
	admin := seedPlatformAdminProfile(t)
	nonAdmin := seedSuperserveEmailProfile(t)
	for _, path := range []string{
		"/internal/teams/invalid/billing/periods/invalid/adopt-exports",
		"/internal/teams/invalid/billing/periods/invalid/measure-correction",
		"/internal/billing/export-corrections/invalid/apply",
		"/internal/billing/export-events/invalid/recover",
	} {
		for _, tc := range []struct {
			name, configuredToken, token, actor string
			status                              int
		}{
			{"host_token_with_admin_actor", operatorRBACToken, internalRBACToken, admin.String(), http.StatusUnauthorized},
			{"missing_token", operatorRBACToken, "", admin.String(), http.StatusUnauthorized},
			{"unconfigured_operator", "", operatorRBACToken, admin.String(), http.StatusUnauthorized},
			{"missing_actor", operatorRBACToken, operatorRBACToken, "", http.StatusUnauthorized},
			{"non_admin_actor", operatorRBACToken, operatorRBACToken, nonAdmin.String(), http.StatusForbidden},
			{"authorized_operator", operatorRBACToken, operatorRBACToken, admin.String(), http.StatusBadRequest},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				t.Setenv("OPERATOR_API_TOKEN", tc.configuredToken)
				r := newBillingRouter(t, &fakeStripeClient{})
				w := doBillingOperator(r, path, tc.token, tc.actor, `{}`)
				if w.Code != tc.status {
					t.Fatalf("got %d, want %d: %s", w.Code, tc.status, w.Body.String())
				}
			})
		}
	}
}

func TestIntegration_IncrementalRejectCorrelatesOnePeriod(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	_, otherPeriod := seedIncrementalPeriod(t)
	reserveIncrement(t, s, p, "10")
	first := acceptIncrement(t, s, p)
	reserveIncrement(t, s, otherPeriod, "20")
	other := acceptIncrement(t, s, otherPeriod)
	for _, period := range []billing.ExportPeriod{p, otherPeriod} {
		if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_export_observation
            (team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end,observed_at)
            SELECT team_id,period_start,period_end,resource_type,sum(quantity),sum(quantity),sum(quantity),sum(quantity),
                date_trunc('minute',period_start),date_trunc('minute',period_end),now()
            FROM billing_export_allocation a JOIN billing_export_event e ON e.allocation_id=a.id
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND e.active
            GROUP BY team_id,period_start,period_end,resource_type`, period.TeamID, period.Start, period.End); err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported',exported_at=now()
            WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, period.TeamID, period.Start, period.End); err != nil {
			t.Fatal(err)
		}
	}
	for _, keys := range [][2]string{{first.Identifier, other.IdempotencyKey}, {first.Identifier, "stale-key"}, {"stale-identifier", first.IdempotencyKey}, {"", ""}} {
		found, err := s.Reject(t.Context(), keys[0], keys[1], first.CustomerID, first.EventName, "mismatched callback")
		if err != nil || found {
			t.Fatalf("mismatched rejection: %v %v", found, err)
		}
	}
	assertState := func(event *billing.ExportEvent, period billing.ExportPeriod, wantEvent, wantPeriod string) {
		t.Helper()
		var eventStatus, periodStatus string
		var exported bool
		if err := testPool.QueryRow(t.Context(), `SELECT e.status,p.status,p.exported_at IS NOT NULL
            FROM billing_export_event e JOIN team_billing_period p ON p.team_id=$2 AND p.period_start=$3 AND p.period_end=$4
            WHERE e.id=$1`, event.ID, period.TeamID, period.Start, period.End).Scan(&eventStatus, &periodStatus, &exported); err != nil {
			t.Fatal(err)
		}
		if eventStatus != wantEvent || periodStatus != wantPeriod || exported != (wantPeriod == "exported") {
			t.Fatalf("event=%s period=%s exported=%v", eventStatus, periodStatus, exported)
		}
	}
	assertState(first, p, "submitted", "exported")
	assertState(other, otherPeriod, "submitted", "exported")
	for attempt := 0; attempt < 2; attempt++ {
		found, err := s.Reject(t.Context(), first.Identifier, first.IdempotencyKey, first.CustomerID, first.EventName, "matched callback")
		if err != nil || !found {
			t.Fatalf("matched rejection: %v %v", found, err)
		}
		assertState(first, p, "rejected", "exporting")
		assertState(other, otherPeriod, "submitted", "exported")
	}
}

func TestIntegration_IncrementalMetricsBacklogAndFreshness(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	ctx := t.Context()
	for i, state := range []string{"pending", "uncertain", "recovery_required"} {
		e := reserveIncrement(t, s, p, []string{"1", "2", "3"}[i])
		if _, err := testPool.Exec(ctx, `UPDATE billing_export_event SET status=$2 WHERE id=$1`, e.ID, state); err != nil {
			t.Fatal(err)
		}
	}
	samples, err := s.Backlog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 6 {
		t.Fatalf("samples: %+v", samples)
	}
	for _, sample := range samples {
		if sample.Count > 1000 {
			t.Fatalf("unbounded sample: %+v", sample)
		}
		if (sample.State == "pending" || sample.State == "uncertain" || sample.State == "recovery_required") && sample.Count < 1 {
			t.Fatalf("missing state: %+v", sample)
		}
	}
	age, err := s.PreviousObservationAge(ctx, p, "cpu")
	if err != nil || age != nil {
		t.Fatalf("missing observation: %v %v", age, err)
	}
	_, err = testPool.Exec(ctx, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end,observed_at)
 VALUES($1,$2,$3,'cpu',3,0,3,0,$2,$3,now()-interval '1 day')`, p.TeamID, p.Start, p.End)
	if err != nil {
		t.Fatal(err)
	}
	age, err = s.PreviousObservationAge(ctx, p, "cpu")
	if err != nil || age == nil || *age < 86000 {
		t.Fatalf("stale observation: %v %v", age, err)
	}
	_, err = testPool.Exec(ctx, `UPDATE billing_export_observation SET last_error='provider unavailable' WHERE team_id=$1`, p.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	age, err = s.PreviousObservationAge(ctx, p, "cpu")
	if err != nil || age != nil {
		t.Fatalf("failed observation reported fresh: %v %v", age, err)
	}
}

func TestIntegration_IncrementalExactReservationAndObservation(t *testing.T) {
	_, p := seedIncrementalPeriod(t)
	for _, statement := range []string{
		`UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`,
		`UPDATE team_billing_usage SET vcpu_seconds=44442444.4444408428,
		 memory_mib_seconds=45509063111.1074230272 WHERE team_id=$1 AND period_start=$2`,
		`UPDATE team_billing_period SET status='exporting' WHERE team_id=$1 AND period_start=$2`,
	} {
		if _, err := testPool.Exec(t.Context(), statement, p.TeamID, p.Start); err != nil {
			t.Fatal(err)
		}
	}
	stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
	stripe.countedUsage = func(eventName, customer string, start, end time.Time) (string, error) {
		total := new(big.Rat)
		for _, call := range stripe.reportCalls {
			if call.EventName == eventName {
				value, ok := new(big.Rat).SetString(call.Value)
				if !ok {
					t.Fatalf("invalid event quantity: %q", call.Value)
				}
				total.Add(total, value)
			}
		}
		return total.FloatString(12), nil
	}
	router := newBillingRouter(t, stripe)
	admin := seedPlatformAdminProfile(t)
	path := "/internal/teams/" + p.TeamID.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
	// The second call observes the frozen period without allocating more usage.
	for attempt := 0; attempt < 2; attempt++ {
		w := doInternal(router, "POST", path, admin.String(), "")
		if w.Code != http.StatusOK {
			t.Fatalf("export: %d %s", w.Code, w.Body.String())
		}
		if len(stripe.reportCalls) != 4 {
			t.Fatalf("got %d events, want two exact parts per resource", len(stripe.reportCalls))
		}
		for _, resource := range []string{"cpu", "memory"} {
			var local, reserved, submitted, counted string
			if err := testPool.QueryRow(t.Context(), `SELECT local_quantity::text,reserved_quantity::text,
			 submitted_quantity::text,counted_quantity::text FROM billing_export_observation
			 WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type=$4`,
				p.TeamID, p.Start, p.End, resource).Scan(&local, &reserved, &submitted, &counted); err != nil {
				t.Fatal(err)
			}
			for _, got := range []string{local, reserved, submitted, counted} {
				if got != "12345.123456789123" {
					t.Fatalf("%s quantity lost precision: %s", resource, got)
				}
			}
		}
	}
}

func TestIntegration_IncrementalDisabledStorageRemainsReconcilable(t *testing.T) {
	for _, source := range []string{"submitted", "adopted"} {
		t.Run(source, func(t *testing.T) {
			testIncrementalDisabledStorageRemainsReconcilable(t, source)
		})
	}
}

func testIncrementalDisabledStorageRemainsReconcilable(t *testing.T, source string) {
	s, p := seedIncrementalPeriod(t)
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, p.TeamID, p.Start); err != nil {
		t.Fatal(err)
	}
	setStorageEnabled := func(enabled bool) {
		t.Helper()
		if _, err := testPool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled)
            VALUES($1,'billing_storage_billing_enabled',$2)
            ON CONFLICT(team_id,key) DO UPDATE SET enabled=EXCLUDED.enabled`, p.TeamID, enabled); err != nil {
			t.Fatal(err)
		}
	}
	setStorageEnabled(true)
	original := billing.ExportPayload{
		EventName: "storage_gib_hours", CustomerID: "cus_" + p.TeamID.String(), Timestamp: p.End.Add(-time.Second).Unix(),
	}
	if source == "adopted" {
		if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID); err != nil {
			t.Fatal(err)
		}
		var inventory []billing.AdoptedExport
		for i, quantity := range []string{"0.25", "0.75"} {
			payload := original
			payload.Identifier = fmt.Sprintf("example-storage-%s-%d", p.TeamID, i)
			payload.IdempotencyKey = payload.Identifier
			payload.Quantity = quantity
			inventory = append(inventory, billing.AdoptedExport{Resource: "storage", Through: p.End, ExportPayload: payload})
		}
		if err := s.Adopt(t.Context(), p, inventory, "reviewed complete storage inventory"); err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=true WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID); err != nil {
			t.Fatal(err)
		}
	} else {
		for _, total := range []string{"0.25", "1"} {
			if _, err := s.Reserve(t.Context(), p, "storage", total, p.End, original); err != nil {
				t.Fatal(err)
			}
			acceptIncrement(t, s, p)
		}
	}
	setStorageEnabled(false)
	// Full-hour measurements can continue accumulating after billing is disabled.
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_usage SET storage_mib_seconds=3*3686400
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, p.TeamID, p.Start, p.End); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `UPDATE sandbox_storage_interval SET ended_at=started_at+interval '3 hours'
        WHERE team_id=$1`, p.TeamID); err != nil {
		t.Fatal(err)
	}

	phase := "mismatch"
	storageReads := 0
	stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
	stripe.countedUsage = func(eventName, customer string, start, end time.Time) (string, error) {
		if customer != original.CustomerID || !start.Equal(p.Start) || !end.Equal(p.End) {
			t.Fatalf("unexpected summary scope: %s %s %s", customer, start, end)
		}
		if eventName == "storage_gib_hours" {
			storageReads++
			switch phase {
			case "outage":
				return "", errors.New("storage summary unavailable")
			case "mismatch":
				return "0", nil
			default:
				return "1", nil
			}
		}
		for _, call := range stripe.reportCalls {
			if call.EventName == eventName {
				return "2", nil
			}
		}
		return "0", nil
	}
	r := newBillingRouter(t, stripe)
	admin := seedPlatformAdminProfile(t)
	path := "/internal/teams/" + p.TeamID.String() + "/billing/periods/" + apiPeriodID(p.Start, p.End) + "/export"
	for _, mode := range []string{"mismatch", "outage", "matched", "frozen"} {
		phase = mode
		storageReads = 0
		if mode == "frozen" {
			if _, err := testPool.Exec(t.Context(), `UPDATE billing_export_observation SET observed_at=now()-interval '3 hours'
                WHERE team_id=$1 AND resource_type='storage'`, p.TeamID); err != nil {
				t.Fatal(err)
			}
		}
		w := doInternal(r, "POST", path, admin.String(), "")
		wantCode, wantStatus := http.StatusConflict, "exporting"
		if mode == "matched" || mode == "frozen" {
			wantCode, wantStatus = http.StatusOK, "exported"
		}
		if w.Code != wantCode || billingPeriodStatus(t, p.TeamID, p.Start, p.End) != wantStatus {
			t.Fatalf("%s close: %d %s", mode, w.Code, w.Body.String())
		}
		if storageReads != 1 {
			t.Fatalf("%s storage summary reads = %d, want 1", mode, storageReads)
		}
		var local, reserved, submitted string
		var counted, lastError *string
		var fresh bool
		if err := testPool.QueryRow(t.Context(), `SELECT local_quantity::text,reserved_quantity::text,submitted_quantity::text,
            counted_quantity::text,last_error,observed_at>now()-interval '1 minute'
            FROM billing_export_observation WHERE team_id=$1 AND period_start=$2 AND period_end=$3 AND resource_type='storage'`,
			p.TeamID, p.Start, p.End).Scan(&local, &reserved, &submitted, &counted, &lastError, &fresh); err != nil {
			t.Fatal(err)
		}
		for _, quantity := range []string{local, reserved, submitted} {
			value, ok := new(big.Rat).SetString(quantity)
			if !ok || value.Cmp(big.NewRat(1, 1)) != 0 {
				t.Fatalf("%s storage accounting: %s %s %s", mode, local, reserved, submitted)
			}
		}
		if !fresh {
			t.Fatalf("%s storage observation is stale", mode)
		}
		if mode == "outage" {
			if counted != nil || lastError == nil || *lastError != "storage summary unavailable" {
				t.Fatalf("storage outage lost: counted=%v error=%v", counted, lastError)
			}
		} else {
			want := "1"
			if mode == "mismatch" {
				want = "0"
			}
			if counted == nil || *counted != want || lastError != nil {
				t.Fatalf("%s storage evidence: counted=%v error=%v", mode, counted, lastError)
			}
		}
	}
	if len(stripe.reportCalls) != 2 {
		t.Fatalf("submitted %d events, want CPU and memory only", len(stripe.reportCalls))
	}
	for _, call := range stripe.reportCalls {
		if call.EventName == original.EventName {
			t.Fatal("disabled storage was resubmitted")
		}
	}
	var allocations int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM billing_export_allocation WHERE team_id=$1 AND resource_type='storage'`, p.TeamID).Scan(&allocations); err != nil || allocations != 2 {
		t.Fatalf("storage allocations = %d, want 2: %v", allocations, err)
	}

	planKey := "storage-coverage-" + p.TeamID.String()
	insertPricingPlanForTest(t, t.Context(), planKey, true)
	if _, err := testPool.Exec(t.Context(), `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from)
        VALUES($1,'vcpu','second',0.001,$2),($1,'memory_gib','second',0.001,$2),($1,'storage_gib','second',0.001,$2)`, planKey, p.Start); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from)
        VALUES($1,$2,$3)`, p.TeamID, planKey, p.Start); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at)
        VALUES($1,100,100,'example credit',$2)`, p.TeamID, p.Start); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		result, err := billing.FinalizeTeamBillingPeriodWithCredits(t.Context(), testPool, p.TeamID, p.Start, p.End)
		if err != nil {
			t.Fatalf("finalize disabled storage: %v", err)
		}
		// Two CPU/memory hours plus one exported storage hour, not three measured hours.
		assertFloatNear(t, numericFloat64(t, result.Period.GrossChargesUsd), 18)
		assertFloatNear(t, numericFloat64(t, result.Period.CreditsAppliedUsd), 18)
		assertFloatNear(t, numericFloat64(t, result.Period.NetInvoiceAmountUsd), 0)
		assertFloatNear(t, numericFloat64(t, result.Usage.StorageMibSeconds), 3*3686400)
		if i == 0 {
			assertFloatNear(t, result.Charges.Breakdown.StorageUSD, 3.6)
			assertFloatNear(t, result.Charges.CreditsRemainingUSD, 82)
		}
		var remaining float64
		if err := testPool.QueryRow(t.Context(), `SELECT remaining_usd FROM team_credit_grant WHERE team_id=$1`, p.TeamID).Scan(&remaining); err != nil {
			t.Fatal(err)
		}
		assertFloatNear(t, remaining, 82)
	}
}

func TestIntegration_IncrementalSkippedDisabledEnrollment(t *testing.T) {
	for _, legacyStatus := range []string{"", "pending", "sent", "accepted", "failed"} {
		name := legacyStatus
		if name == "" {
			name = "disabled_only"
		}
		t.Run(name, func(t *testing.T) {
			team, _, start, end := seedBillingPeriodForStripe(t, true, true)
			if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_usage_export
                (team_id,period_start,period_end,resource_type,stripe_meter_event_identifier,stripe_event_name,value,status)
                VALUES($1,$2,$3,'storage',$4,'storage_gib_hours',1,'skipped_disabled')`, team, start, end, "example-disabled-storage-"+team.String()); err != nil {
				t.Fatal(err)
			}
			if legacyStatus != "" {
				if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_usage_export
                    (team_id,period_start,period_end,resource_type,stripe_meter_event_identifier,stripe_event_name,value,status)
                    VALUES($1,$2,$3,'cpu',$5,'cpu_vcpu_hours',2,$4)`, team, start, end, legacyStatus, "example-live-cpu-"+team.String()); err != nil {
					t.Fatal(err)
				}
			}
			store := billing.ExportStore{Pool: testPool}
			period := billing.ExportPeriod{TeamID: team, Start: start, End: end}
			err := store.Enroll(t.Context(), period)
			if legacyStatus != "" {
				if !errors.Is(err, billing.ErrExportRecoveryRequired) {
					t.Fatalf("live legacy attempt did not block enrollment: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if event := reserveIncrement(t, store, period, "2"); event == nil || event.Quantity != "2.000000000000" {
				t.Fatalf("disabled legacy row prevented full billable allocation: %+v", event)
			}
		})
	}
}

func TestIntegration_IncrementalManualExportWithSkippedDisabledHistory(t *testing.T) {
	team, periodID, start, end := seedBillingPeriodForStripe(t, true, true)
	if _, err := testPool.Exec(t.Context(), `UPDATE team_billing_account SET commercial_billing_anchor=$2 WHERE team_id=$1`, team, start); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled)
        VALUES($1,'billing_storage_billing_enabled',false) ON CONFLICT(team_id,key) DO UPDATE SET enabled=false`, team); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_usage_export
        (team_id,period_start,period_end,resource_type,stripe_meter_event_identifier,stripe_event_name,value,status)
        VALUES($1,$2,$3,'storage',$4,'storage_gib_hours',1,'skipped_disabled')`, team, start, end, "example-disabled-storage-"+team.String()); err != nil {
		t.Fatal(err)
	}
	stripe := &summaryStripeClient{fakeStripeClient: &fakeStripeClient{}}
	stripe.countedUsage = func(eventName, customer string, gotStart, gotEnd time.Time) (string, error) {
		if customer != "cus_"+team.String() || !gotStart.Equal(start) || !gotEnd.Equal(end) {
			t.Fatal("unexpected provider summary scope")
		}
		for _, call := range stripe.reportCalls {
			if call.EventName == eventName {
				return call.Value, nil
			}
		}
		return "0", nil
	}
	router := newBillingRouter(t, stripe)
	admin := seedPlatformAdminProfile(t)
	path := "/internal/teams/" + team.String() + "/billing/periods/" + periodID + "/export"
	for i := 0; i < 2; i++ {
		w := doInternal(router, "POST", path, admin.String(), "")
		if w.Code != http.StatusOK {
			t.Fatalf("manual export: %d %s", w.Code, w.Body.String())
		}
	}
	var enrolled bool
	if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_incremental_period
        WHERE team_id=$1 AND period_start=$2 AND period_end=$3)`, team, start, end).Scan(&enrolled); err != nil || !enrolled {
		t.Fatalf("manual export did not enroll period: %v %v", enrolled, err)
	}
	if len(stripe.reportCalls) != 2 {
		t.Fatalf("provider submissions = %d, want 2 across repeated exports", len(stripe.reportCalls))
	}
	for _, call := range stripe.reportCalls {
		if (call.EventName != "cpu_vcpu_hours" && call.EventName != "memory_gib_hours") || call.Value != "2.000000000000" {
			t.Fatalf("unexpected billable submission: %+v", call)
		}
	}
	if got := exportAttemptCount(t, team, "skipped_disabled"); got != 1 {
		t.Fatalf("preserved disabled attempts = %d, want 1", got)
	}
}

func TestIntegration_IncrementalLegacyHandover(t *testing.T) {
	for _, outcome := range []string{"accepted", "sent", "pending", "failed", "omitted", "quantity_mismatch", "key_mismatch", "invalid_boundary", "boundary_after_event", "boundary_before_event"} {
		t.Run(outcome, func(t *testing.T) {
			team, _, _ := seedTeamAndKeyWithRole(t, "viewer")
			start := time.Now().UTC().Truncate(time.Hour).Add(-24 * time.Hour)
			end := start.AddDate(0, 1, 0)
			if _, err := testPool.Exec(t.Context(), `INSERT INTO team_billing_period(team_id,period_start,period_end,status)
                VALUES($1,$2,$3,'open')`, team, start, end); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(t.Context(), `INSERT INTO team_feature_flag(team_id,key,enabled)
                VALUES($1,'billing_export_enabled',false) ON CONFLICT(team_id,key) DO UPDATE SET enabled=false`, team); err != nil {
				t.Fatal(err)
			}
			p := billing.ExportPeriod{TeamID: team, Start: start, End: end}
			s := billing.ExportStore{Pool: testPool}
			event := billing.AdoptedExport{Resource: "cpu", Through: start.Add(time.Hour), ExportPayload: billing.ExportPayload{
				Identifier: "legacy-" + team.String(), IdempotencyKey: "legacy-key-" + team.String(),
				CustomerID: "cus_example", EventName: "example_cpu_hours", Quantity: "10.125", Timestamp: start.Add(time.Hour - time.Second).Unix(),
			}}
			status := outcome
			if status != "pending" && status != "failed" && status != "sent" {
				status = "accepted"
			}
			if _, err := testPool.Exec(t.Context(), `INSERT INTO billing_usage_export
                (team_id,period_start,period_end,resource_type,stripe_customer_id,stripe_meter_event_identifier,stripe_event_name,value,status,stripe_idempotency_key)
                VALUES($1,$2,$3,'cpu',$4,$5,$6,$7,$8,$9)`, team, start, end, event.CustomerID, event.Identifier, event.EventName, event.Quantity, status, event.IdempotencyKey); err != nil {
				t.Fatal(err)
			}
			if err := s.Enroll(t.Context(), p); !errors.Is(err, billing.ErrExportRecoveryRequired) {
				t.Fatalf("unreviewed enrollment: %v", err)
			}
			switch outcome {
			case "omitted":
				event.Identifier = "other-" + team.String()
			case "quantity_mismatch":
				event.Quantity = "11.125"
			case "key_mismatch":
				event.IdempotencyKey = "other-key-" + team.String()
			case "invalid_boundary":
				event.Through = start
			case "boundary_after_event":
				event.Through = event.Through.Add(time.Hour)
			case "boundary_before_event":
				event.Through = event.Through.Add(-time.Minute)
			}
			inventory := []billing.AdoptedExport{event}
			err := s.Adopt(t.Context(), p, inventory, "reviewed provider inventory")
			if outcome != "accepted" && outcome != "sent" {
				if err == nil {
					t.Fatal("unsafe handover succeeded")
				}
				var enrolled bool
				if err := testPool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM billing_incremental_period WHERE team_id=$1)`, team).Scan(&enrolled); err != nil || enrolled {
					t.Fatalf("failed handover left enrollment: %v %v", enrolled, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Adopt(t.Context(), p, inventory, "reviewed provider inventory"); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(t.Context(), `UPDATE team_feature_flag SET enabled=true WHERE team_id=$1 AND key='billing_export_enabled'`, team); err != nil {
				t.Fatal(err)
			}
			if claimed, err := s.Claim(t.Context(), p); err != nil || claimed != nil {
				t.Fatalf("adopted legacy event was queued for submission: %v %v", claimed, err)
			}
			residual := reserveIncrement(t, s, p, "15.125")
			if residual == nil || residual.Quantity != "5.000000000000" {
				t.Fatalf("legacy coverage was not deducted: %+v", residual)
			}
			if duplicate := reserveIncrement(t, s, p, "15.125"); duplicate != nil {
				t.Fatal("repeated catch-up reserved duplicate coverage")
			}
			if _, err := testPool.Exec(t.Context(), `UPDATE billing_usage_export SET value=15.125 WHERE team_id=$1`, team); err == nil {
				t.Fatal("legacy writer bypassed handover fence")
			}
		})
	}
}

func TestIntegration_BillingExportPreviewAccountingCompatibility(t *testing.T) {
	ctx := t.Context()
	team, periodID, start, end := seedBillingPeriodForStripe(t, true, true)
	viewerKey := seedKeyForExistingTeamWithRole(t, team, "viewer")
	var legacyID string
	if err := testPool.QueryRow(ctx, `INSERT INTO billing_usage_export
        (team_id,period_start,period_end,resource_type,stripe_meter_event_identifier,stripe_event_name,value,status)
        VALUES ($1,$2,$3,'cpu','example-shadow-preview','example_cpu_hours',2,'skipped_shadow') RETURNING id`,
		team, start, end).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	type attempt struct {
		ID         string     `json:"id"`
		Resource   string     `json:"resource_type"`
		Identifier string     `json:"stripe_meter_event_identifier"`
		EventName  string     `json:"stripe_event_name"`
		Value      float64    `json:"value"`
		Status     string     `json:"status"`
		Error      *string    `json:"error"`
		SentAt     *time.Time `json:"sent_at"`
		CreatedAt  time.Time  `json:"created_at"`
	}
	router := newBillingRouter(t, nil)
	preview := func() []attempt {
		t.Helper()
		response := do(router, "GET", "/teams/"+team.String()+"/billing/periods/"+periodID+"/export-preview", viewerKey, "")
		if response.Code != http.StatusOK {
			t.Fatalf("preview: %d %s", response.Code, response.Body.String())
		}
		var body struct {
			TeamID   string    `json:"team_id"`
			PeriodID string    `json:"period_id"`
			Attempts []attempt `json:"attempts"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.TeamID != team.String() || body.PeriodID != periodID || body.Attempts == nil {
			t.Fatalf("incompatible preview: %s", response.Body.String())
		}
		return body.Attempts
	}
	legacy := preview()
	if len(legacy) != 1 || legacy[0].ID != legacyID || legacy[0].Status != "skipped_shadow" || legacy[0].Value != 2 {
		t.Fatalf("legacy history: %+v", legacy)
	}
	store := billing.ExportStore{Pool: testPool}
	period := billing.ExportPeriod{TeamID: team, Start: start, End: end}
	if err := store.Enroll(ctx, period); err != nil {
		t.Fatal(err)
	}
	if got := preview(); len(got) != 0 {
		t.Fatalf("enrolled preview retained shadow history: %+v", got)
	}
	reserveIncrement(t, store, period, "1.25")
	first := acceptIncrement(t, store, period)
	if found, err := store.Reject(ctx, first.Identifier, "", first.CustomerID, first.EventName, "example rejection"); err != nil || !found {
		t.Fatalf("reject: %v %v", found, err)
	}
	if err := store.RecoverRejected(ctx, first.ID, "reviewed rejection"); err != nil {
		t.Fatal(err)
	}
	replacement := acceptIncrement(t, store, period)
	pending := reserveIncrement(t, store, period, "2")
	got := preview()
	if len(got) != 3 {
		t.Fatalf("event history: %+v", got)
	}
	byID := make(map[string]attempt)
	for _, item := range got {
		byID[item.ID] = item
		if item.Resource != "cpu" || item.EventName != "example_cpu_hours" || item.CreatedAt.IsZero() {
			t.Fatalf("event metadata missing: %+v", item)
		}
	}
	for _, want := range []struct {
		event  *billing.ExportEvent
		status string
		value  float64
		sent   bool
	}{
		{first, "rejected", 1.25, true},
		{replacement, "submitted", 1.25, true},
		{pending, "pending", 0.75, false},
	} {
		item, ok := byID[want.event.ID.String()]
		if !ok || item.Identifier != want.event.Identifier || item.Status != want.status || item.Value != want.value || (item.SentAt != nil) != want.sent {
			t.Fatalf("event mapping: %+v, want %+v", item, want)
		}
	}
	if item := byID[first.ID.String()]; item.Error == nil || *item.Error != "example rejection" {
		t.Fatalf("rejection detail missing: %+v", item)
	}
}
