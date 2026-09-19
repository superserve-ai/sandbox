//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/billing"
)

func correctionExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func frozenCorrectionFixture(t *testing.T) (billing.ExportStore, billing.ExportPeriod, uuid.UUID, billing.ExportPayload) {
	t.Helper()
	s, p := seedIncrementalPeriod(t)
	actor := seedPlatformAdminProfile(t)
	correctionExec(t, `UPDATE sandbox_compute_billing_interval SET ended_at=started_at+interval '10 hours' WHERE team_id=$1`, p.TeamID)
	correctionExec(t, `UPDATE team_billing_usage SET vcpu_seconds=36000,memory_mib_seconds=36864000,storage_mib_seconds=0 WHERE team_id=$1`, p.TeamID)
	correctionExec(t, `INSERT INTO billing_export_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds)
        VALUES($1,$2,$3,28800,29491200)`, p.TeamID, p.Start, p.End)
	reserveIncrement(t, s, p, "10")
	acceptIncrement(t, s, p)
	correctionExec(t, `UPDATE team_billing_period SET status='exporting' WHERE team_id=$1`, p.TeamID)
	payload := billing.ExportPayload{EventName: "example_cpu_hours", CustomerID: "cus_example", Timestamp: p.End.Add(-time.Second).Unix()}
	return s, p, actor, payload
}

func TestIntegration_IncrementalCorrectionRollupCatchupAndTrueLateUsage(t *testing.T) {
	s, p, actor, payload := frozenCorrectionFixture(t)
	// An hourly source catches up from 8 to 10 after a raw close froze 10.
	correctionExec(t, `UPDATE billing_export_usage SET vcpu_seconds=36000 WHERE team_id=$1`, p.TeamID)
	c, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if c.Measured != "10.000000000000" || c.Baseline != "10.000000000000" || c.Target != "10.000000000000" {
		t.Fatalf("catchup: %+v", c)
	}
	for i := 0; i < 2; i++ {
		if err = s.ApplyCorrection(t.Context(), c.ID, actor, "accept_usage", "reviewed rollup catchup", payload); err != nil {
			t.Fatal(err)
		}
	}
	if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
		t.Fatalf("catchup became billable: %+v %v", event, err)
	}

	// Genuine extra raw usage is measured against the authoritative baseline.
	correctionExec(t, `UPDATE sandbox_compute_billing_interval SET ended_at=started_at+interval '12 hours' WHERE team_id=$1`, p.TeamID)
	c, err = s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if c.Target != "12.000000000000" {
		t.Fatalf("late target: %+v", c)
	}
	for i := 0; i < 2; i++ {
		if err = s.ApplyCorrection(t.Context(), c.ID, actor, "accept_usage", "reviewed additional raw usage", payload); err != nil {
			t.Fatal(err)
		}
	}
	event := acceptIncrement(t, s, p)
	if event.Quantity != "2.000000000000" {
		t.Fatalf("late delta: %+v", event)
	}
	c, err = s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyCorrection(t.Context(), c.ID, actor, "accept_usage", "second reviewed measurement", payload); err != nil {
		t.Fatal(err)
	}
	if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
		t.Fatalf("duplicate late usage: %+v %v", event, err)
	}
	var unchanged bool
	if err = testPool.QueryRow(t.Context(), `SELECT vcpu_seconds=36000 FROM team_billing_usage WHERE team_id=$1`, p.TeamID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatalf("changed close baseline: %v %v", unchanged, err)
	}
	if _, err = testPool.Exec(t.Context(), `UPDATE team_billing_usage SET vcpu_seconds=43200 WHERE team_id=$1`, p.TeamID); err == nil {
		t.Fatal("close baseline remained writable")
	}
}

func TestIntegration_IncrementalCorrectionFinalizationPricesApprovedComputeUsage(t *testing.T) {
	s, p, actor, payload := frozenCorrectionFixture(t)
	memoryPayload := payload
	memoryPayload.EventName = "example_memory_hours"
	memory, err := s.MeasureCorrection(t.Context(), p, "memory")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyCorrection(t.Context(), memory.ID, actor, "accept_usage", "reviewed initial memory coverage", memoryPayload); err != nil {
		t.Fatal(err)
	}
	acceptIncrement(t, s, p)
	correctionExec(t, `UPDATE sandbox_compute_billing_interval SET ended_at=started_at+interval '12 hours' WHERE team_id=$1`, p.TeamID)
	for _, resource := range []string{"cpu", "memory"} {
		correction, err := s.MeasureCorrection(t.Context(), p, resource)
		if err != nil {
			t.Fatal(err)
		}
		if correction.Target != "12.000000000000" {
			t.Fatalf("%s correction: %+v", resource, correction)
		}
		resourcePayload := payload
		if resource == "memory" {
			resourcePayload = memoryPayload
		}
		if err := s.ApplyCorrection(t.Context(), correction.ID, actor, "accept_usage", "reviewed additional compute usage", resourcePayload); err != nil {
			t.Fatal(err)
		}
		if event := acceptIncrement(t, s, p); event.Quantity != "2.000000000000" {
			t.Fatalf("%s correction delta: %+v", resource, event)
		}
		correctionExec(t, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,
            local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
            VALUES($1,$2,$3,$4,12,12,12,12,$2,$3)`, p.TeamID, p.Start, p.End, resource)
	}
	correctionExec(t, `UPDATE team_billing_period SET status='exported',exported_at=now() WHERE team_id=$1`, p.TeamID)
	planKey := "corrected-compute-" + p.TeamID.String()
	insertPricingPlanForTest(t, t.Context(), planKey, true)
	correctionExec(t, `INSERT INTO pricing_rate(plan_key,resource,unit,price_usd,effective_from)
        VALUES($1,'vcpu','second',0.001,$2),($1,'memory_gib','second',0.001,$2)`, planKey, p.Start)
	correctionExec(t, `INSERT INTO team_pricing_plan(team_id,plan_key,effective_from) VALUES($1,$2,$3)`, p.TeamID, planKey, p.Start)
	correctionExec(t, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_at)
        VALUES($1,80,80,'example credit',$2)`, p.TeamID, p.Start)
	for i := 0; i < 2; i++ {
		result, err := billing.FinalizeTeamBillingPeriodWithCredits(t.Context(), testPool, p.TeamID, p.Start, p.End)
		if err != nil {
			t.Fatal(err)
		}
		assertFloatNear(t, numericFloat64(t, result.Period.GrossChargesUsd), 86.4)
		assertFloatNear(t, numericFloat64(t, result.Period.CreditsAppliedUsd), 80)
		assertFloatNear(t, numericFloat64(t, result.Period.NetInvoiceAmountUsd), 6.4)
		assertFloatNear(t, numericFloat64(t, result.Usage.VcpuSeconds), 36000)
		assertFloatNear(t, numericFloat64(t, result.Usage.MemoryMibSeconds), 36864000)
		if i == 0 {
			assertFloatNear(t, result.Charges.Breakdown.ComputeUSD, 43.2)
			assertFloatNear(t, result.Charges.Breakdown.MemoryUSD, 43.2)
		}
		var remaining, consumed float64
		var entries int
		if err := testPool.QueryRow(t.Context(), `SELECT remaining_usd FROM team_credit_grant WHERE team_id=$1`, p.TeamID).Scan(&remaining); err != nil {
			t.Fatal(err)
		}
		if err := testPool.QueryRow(t.Context(), `SELECT count(*),sum(amount_usd) FROM team_credit_ledger WHERE team_id=$1`, p.TeamID).Scan(&entries, &consumed); err != nil {
			t.Fatal(err)
		}
		assertFloatNear(t, remaining, 0)
		assertFloatNear(t, consumed, 80)
		if entries != 1 {
			t.Fatalf("credit applications = %d, want 1", entries)
		}
	}
}

func TestIntegration_IncrementalCorrectionRejectsChangedMeasurementAndConcurrentReview(t *testing.T) {
	s, p, actor, payload := frozenCorrectionFixture(t)
	c, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	correctionExec(t, `UPDATE sandbox_compute_billing_interval SET ended_at=started_at+interval '11 hours' WHERE team_id=$1`, p.TeamID)
	if err = s.ApplyCorrection(t.Context(), c.ID, actor, "accept_usage", "stale proposal", payload); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("stale raw source accepted: %v", err)
	}
	first, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []uuid.UUID{first.ID, second.ID} {
		wg.Add(1)
		go func(id uuid.UUID) {
			defer wg.Done()
			results <- s.ApplyCorrection(context.Background(), id, actor, "accept_usage", "concurrent reviewed measurement", payload)
		}(id)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent approvals: %d successes", successes)
	}
	event := acceptIncrement(t, s, p)
	if event.Quantity != "1.000000000000" {
		t.Fatalf("overlapping correction: %+v", event)
	}
	if event, err := s.Claim(t.Context(), p); err != nil || event != nil {
		t.Fatalf("duplicate correction: %+v %v", event, err)
	}
}

func TestIntegration_IncrementalCorrectionDownwardDispositionAndSubsequentAllocation(t *testing.T) {
	s, p := seedIncrementalPeriod(t)
	actor := seedPlatformAdminProfile(t)
	reserveIncrement(t, s, p, "10")
	acceptIncrement(t, s, p)
	correctionExec(t, `INSERT INTO billing_export_usage(team_id,period_start,period_end,vcpu_seconds) VALUES($1,$2,$3,28800)`, p.TeamID, p.Start, p.End)
	c, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	payload := billing.ExportPayload{EventName: "example_cpu_hours", CustomerID: "cus_example", Timestamp: p.End.Add(-time.Second).Unix()}
	if err = s.ApplyCorrection(t.Context(), c.ID, actor, "accept_usage", "incorrect automatic adjustment", payload); err == nil {
		t.Fatal("downward usage accepted without disposition")
	}
	if err = s.ApplyCorrection(t.Context(), c.ID, actor, "retain_exported", "reviewed existing exported quantity remains unchanged", payload); err != nil {
		t.Fatal(err)
	}
	for _, local := range []string{"8", "9", "10"} {
		target, err := s.CorrectionTarget(t.Context(), p, "cpu", local)
		if err != nil {
			t.Fatal(err)
		}
		if e := reserveIncrement(t, s, p, target); e != nil {
			t.Fatalf("retained excess billed again: %+v", e)
		}
	}
	target, err := s.CorrectionTarget(t.Context(), p, "cpu", "11")
	if err != nil {
		t.Fatal(err)
	}
	if e := reserveIncrement(t, s, p, target); e == nil || e.Quantity != "1.000000000000" {
		t.Fatalf("subsequent growth: %+v", e)
	}
	target, err = s.CorrectionTarget(t.Context(), p, "cpu", "7")
	if err != nil || target != "7" {
		t.Fatalf("new downward discrepancy hidden: %s %v", target, err)
	}
}

func TestIntegration_IncrementalCorrectionPreservesAnomaliesAfterProposal(t *testing.T) {
	for _, action := range []string{"accept_usage", "retain_exported"} {
		t.Run(action, func(t *testing.T) {
			s, p, actor, payload := frozenCorrectionFixture(t)
			if action == "retain_exported" {
				correctionExec(t, `UPDATE sandbox_compute_billing_interval SET ended_at=started_at+interval '8 hours' WHERE team_id=$1`, p.TeamID)
			}
			insertAnomaly := func(resource string) uuid.UUID {
				t.Helper()
				id := uuid.New()
				correctionExec(t, `INSERT INTO billing_period_anomaly(id,team_id,period_start,period_end,severity,kind,details)
        VALUES($1,$2,$3,$4,'error','incremental_export_exceeds_usage',jsonb_build_object('resource',$5::text))`, id, p.TeamID, p.Start, p.End, resource)
				return id
			}
			before := insertAnomaly("cpu")
			otherResource := insertAnomaly("memory")
			c, err := s.MeasureCorrection(t.Context(), p, "cpu")
			if err != nil {
				t.Fatal(err)
			}
			after := insertAnomaly("cpu")
			assertResolution := func(id uuid.UUID, want bool) {
				t.Helper()
				var resolved, attributed bool
				if err := testPool.QueryRow(t.Context(), `SELECT resolved_at IS NOT NULL,COALESCE(resolved_by=$2,false)
        FROM billing_period_anomaly WHERE id=$1`, id, actor).Scan(&resolved, &attributed); err != nil {
					t.Fatal(err)
				}
				if resolved != want || attributed != want {
					t.Fatalf("anomaly %s: resolved=%v attributed=%v, want %v", id, resolved, attributed, want)
				}
			}
			for i := 0; i < 2; i++ {
				if err = s.ApplyCorrection(t.Context(), c.ID, actor, action, "reviewed proposal", payload); err != nil {
					t.Fatal(err)
				}
				assertResolution(before, true)
				assertResolution(after, false)
				assertResolution(otherResource, false)
			}
			fresh, err := s.MeasureCorrection(t.Context(), p, "cpu")
			if err != nil {
				t.Fatal(err)
			}
			if err = s.ApplyCorrection(t.Context(), fresh.ID, actor, action, "reviewed later anomaly", payload); err != nil {
				t.Fatal(err)
			}
			assertResolution(after, true)
			assertResolution(otherResource, false)
		})
	}
}

func TestIntegration_IncrementalCorrectionRemeasurementClipsAnniversaryBoundaries(t *testing.T) {
	s, p, _, _ := frozenCorrectionFixture(t)
	// The interval overlaps both sides of the authoritative period. Only the
	// exact period overlap is measured, including a non-hour-aligned anchor.
	next := billing.ExportPeriod{TeamID: p.TeamID, Start: p.End.Add(17*time.Minute + 13*time.Second), End: p.End.AddDate(0, 1, 0).Add(17*time.Minute + 13*time.Second)}
	correctionExec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status) VALUES($1,$2,$3,'approved')`, next.TeamID, next.Start, next.End)
	correctionExec(t, `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds,memory_mib_seconds,storage_mib_seconds) VALUES($1,$2,$3,0,0,0)`, next.TeamID, next.Start, next.End)
	if err := s.Enroll(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	correctionExec(t, `UPDATE team_billing_period SET status='exporting' WHERE team_id=$1 AND period_start=$2`, next.TeamID, next.Start)
	correctionExec(t, `UPDATE sandbox_compute_billing_interval SET started_at=$2,ended_at=$3 WHERE team_id=$1`, p.TeamID, next.Start.Add(-time.Hour), next.End.Add(time.Hour))
	c, err := s.MeasureCorrection(t.Context(), next, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if c.Measured != "744.000000000000" {
		t.Fatalf("anniversary clipping: %+v", c)
	}
	prior, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	// The previous period ends 17m13s before the next one starts.
	if prior.Measured != "0.713055555556" {
		t.Fatalf("prior boundary overlap: %+v", prior)
	}
}

func TestIntegration_IncrementalCorrectionAfterFinalizationUsesExistingDelivery(t *testing.T) {
	s, p, actor, payload := frozenCorrectionFixture(t)
	correctionExec(t, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,
        local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
        VALUES($1,$2,$3,'cpu',10,10,10,10,$2,$3)`, p.TeamID, p.Start, p.End)
	correctionExec(t, `UPDATE team_billing_period SET status='finalized',exported_at=now(),finalized_at=now(),
        gross_charges_usd=1,credits_applied_usd=0.25,net_invoice_amount_usd=0.75 WHERE team_id=$1`, p.TeamID)
	frozenState := func() string {
		t.Helper()
		var state string
		if err := testPool.QueryRow(t.Context(), `SELECT jsonb_build_array(
        (SELECT to_jsonb(p) FROM team_billing_period p WHERE team_id=$1),
        (SELECT to_jsonb(u) FROM team_billing_usage u WHERE team_id=$1))::text`, p.TeamID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := frozenState()
	correctionExec(t, `UPDATE sandbox_compute_billing_interval SET ended_at=started_at+interval '11 hours' WHERE team_id=$1`, p.TeamID)
	c, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyCorrection(t.Context(), c.ID, actor, "accept_usage", "reviewed finalized late usage", payload); err != nil {
		t.Fatal(err)
	}
	// Ordinary allocation still cannot write finalized coverage.
	if _, err = s.Reserve(t.Context(), p, "cpu", "12", p.End, payload); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("ordinary finalized allocation: %v", err)
	}
	e, err := s.Claim(t.Context(), p)
	if err != nil || e == nil {
		t.Fatalf("claim reviewed correction: %+v %v", e, err)
	}
	if err = s.Acknowledge(t.Context(), *e, errors.New("ambiguous transport timeout")); err != nil {
		t.Fatal(err)
	}
	correctionExec(t, `UPDATE billing_export_event SET next_attempt_at=now() WHERE id=$1`, e.ID)
	retry, err := s.Claim(t.Context(), p)
	if err != nil || retry == nil || retry.ID != e.ID || retry.ExportPayload != e.ExportPayload {
		t.Fatalf("correction retry changed identity: %+v %v", retry, err)
	}
	if err = s.Acknowledge(t.Context(), *retry, nil); err != nil {
		t.Fatal(err)
	}
	target, err := s.CorrectionTarget(t.Context(), p, "cpu", "10")
	if err != nil || target != "11.000000000000" {
		t.Fatalf("corrected reconciliation target: %s %v", target, err)
	}
	if after := frozenState(); after != before {
		t.Fatalf("finalized financial state changed: %s -> %s", before, after)
	}
}

func TestIntegration_IncrementalCorrectionNoopVersionAndCloseGate(t *testing.T) {
	s, p, actor, payload := frozenCorrectionFixture(t)
	correctionExec(t, `INSERT INTO billing_period_anomaly(team_id,period_start,period_end,severity,kind,details)
        VALUES($1,$2,$3,'error','usage_after_export_freeze','{"hour_start":"2026-06-01T00:00:00Z"}')`, p.TeamID, p.Start, p.End)
	first, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	stale, err := s.MeasureCorrection(t.Context(), p, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyCorrection(t.Context(), first.ID, actor, "accept_usage", "reviewed CPU catchup", payload); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyCorrection(t.Context(), stale.ID, actor, "accept_usage", "stale no-op review", payload); !errors.Is(err, billing.ErrExportRecoveryRequired) {
		t.Fatalf("no-op approval ignored version: %v", err)
	}
	correctionExec(t, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,
        local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
        VALUES($1,$2,$3,'cpu',10,10,10,10,$2,$3)`, p.TeamID, p.Start, p.End)
	if _, err = testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported',exported_at=now() WHERE team_id=$1`, p.TeamID); err == nil {
		t.Fatal("close bypassed unreviewed resource")
	}
	memory, err := s.MeasureCorrection(t.Context(), p, "memory")
	if err != nil {
		t.Fatal(err)
	}
	memoryPayload := payload
	memoryPayload.EventName = "example_memory_hours"
	if err = s.ApplyCorrection(t.Context(), memory.ID, actor, "accept_usage", "reviewed memory catchup and missing coverage", memoryPayload); err != nil {
		t.Fatal(err)
	}
	var resolved bool
	if err = testPool.QueryRow(t.Context(), `SELECT resolved_at IS NOT NULL AND resolved_by=$2 FROM billing_period_anomaly WHERE team_id=$1`, p.TeamID, actor).Scan(&resolved); err != nil || !resolved {
		t.Fatalf("review not recorded: %v %v", resolved, err)
	}
	if _, err = testPool.Exec(t.Context(), `UPDATE team_billing_period SET status='exported',exported_at=now() WHERE team_id=$1`, p.TeamID); err == nil {
		t.Fatal("close bypassed pending correction delivery")
	}
	event := acceptIncrement(t, s, p)
	if event.Quantity != "10.000000000000" {
		t.Fatalf("missing memory coverage: %+v", event)
	}
	correctionExec(t, `INSERT INTO billing_export_observation(team_id,period_start,period_end,resource_type,
        local_quantity,submitted_quantity,reserved_quantity,counted_quantity,query_start,query_end)
        VALUES($1,$2,$3,'memory',10,10,10,10,$2,$3)`, p.TeamID, p.Start, p.End)
	correctionExec(t, `UPDATE team_billing_period SET status='exported',exported_at=now() WHERE team_id=$1`, p.TeamID)
}
