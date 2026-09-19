//go:build integration

package integration

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/billing"
)

func TestIntegration_IncrementalMeterPinnedAcrossConcurrentConfigurations(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, name := range []string{"example_cpu_hours", "renamed_cpu_hours"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Reserve(t.Context(), p, "cpu", "10", p.End, billing.ExportPayload{EventName: name, CustomerID: "cus_example", Timestamp: p.End.Add(-time.Second).Unix()})
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
	first := acceptIncrement(t, s, p)
	next, err := s.Reserve(t.Context(), p, "cpu", "15", p.End, billing.ExportPayload{EventName: "another_cpu_hours", CustomerID: "cus_example", Timestamp: p.End.Add(-time.Second).Unix()})
	if err != nil || next == nil || next.EventName != first.EventName || next.Quantity != "5.000000000000" {
		t.Fatalf("new reservation: %+v %v; first meter=%s", next, err, first.EventName)
	}
	if found, err := s.Reject(t.Context(), first.Identifier, "", first.CustomerID, first.EventName, "example rejection"); err != nil || !found {
		t.Fatalf("reject: %v %v", found, err)
	}
	if err := s.RecoverRejected(t.Context(), first.ID, "reviewed rejected event"); err != nil {
		t.Fatal(err)
	}
	name, err := s.MeterEventName(t.Context(), p, "cpu", "another_cpu_hours")
	if err != nil || name != first.EventName {
		t.Fatalf("recovery meter=%s err=%v", name, err)
	}
	fresh := p
	fresh.Start, fresh.End = p.End, p.End.AddDate(0, 1, 0)
	name, err = s.MeterEventName(t.Context(), fresh, "cpu", "another_cpu_hours")
	if err != nil || name != "another_cpu_hours" {
		t.Fatalf("new period meter=%s err=%v", name, err)
	}
}

func TestIntegration_IncrementalCorrectionKeepsPeriodMeter(t *testing.T) {
	s, p, actor, payload := frozenCorrectionFixture(t)
	correctionExec(t, `UPDATE sandbox_compute_billing_interval SET ended_at=started_at+interval '12 hours' WHERE team_id=$1`, p.TeamID)
	c, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	payload.EventName = "renamed_cpu_hours"
	if err := s.ApplyCorrection(t.Context(), c.ID, actor, "accept_usage", "reviewed additional usage", payload); err != nil {
		t.Fatal(err)
	}
	event := acceptIncrement(t, s, p)
	if event.EventName != "example_cpu_hours" || event.Quantity != "2.000000000000" {
		t.Fatalf("correction: %+v", event)
	}
}

func TestIntegration_IncrementalAdoptionPinsMeterAndRejectsMixedInventory(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	correctionExec(t, `UPDATE team_feature_flag SET enabled=false WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID)
	through := p.Start.Add(24 * time.Hour)
	event := billing.AdoptedExport{Resource: "cpu", Through: through, ExportPayload: billing.ExportPayload{
		Identifier: "preload-" + p.TeamID.String(), IdempotencyKey: "preload-" + p.TeamID.String(), EventName: "example_cpu_hours", CustomerID: "cus_example", Quantity: "10", Timestamp: through.Add(-time.Second).Unix(),
	}}
	other := event
	other.Identifier += "-other"
	other.IdempotencyKey = other.Identifier
	other.EventName = "renamed_cpu_hours"
	if err := s.Adopt(t.Context(), p, []billing.AdoptedExport{event, other}, "reviewed inventory"); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("mixed inventory: %v", err)
	}
	totals, err := s.Totals(t.Context(), p, "cpu")
	if err != nil || totals.Reserved != "0" {
		t.Fatalf("mixed inventory did not roll back: %+v %v", totals, err)
	}
	if err := s.Adopt(t.Context(), p, []billing.AdoptedExport{event}, "reviewed inventory"); err != nil {
		t.Fatal(err)
	}
	correctionExec(t, `UPDATE team_feature_flag SET enabled=true WHERE team_id=$1 AND key='billing_export_enabled'`, p.TeamID)
	payload := event.ExportPayload
	payload.EventName = "renamed_cpu_hours"
	next, err := s.Reserve(t.Context(), p, "cpu", "15", through, payload)
	if err != nil || next == nil || next.EventName != event.EventName || next.Quantity != "5.000000000000" {
		t.Fatalf("adopted residual: %+v %v", next, err)
	}
}
