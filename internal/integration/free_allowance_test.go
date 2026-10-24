//go:build integration

package integration

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/db"
)

func assignFreePlan(t *testing.T, teamID uuid.UUID, since time.Time) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO team_plan_assignment (team_id, plan_key, kind, terms, limits, effective_from, source, reason)
		VALUES ($1, 'free', 'free',
		        '{"allowance":{"amount_cents":13,"period":"day_window","on_exhausted":"pause","compute":{"seconds":7200,"vcpu":1,"memory_gib":1}}}',
		        '{"max_concurrent":1,"max_vcpu":1,"max_memory_mib":1024,"max_disk_mib":4096}', $2, 'migration', 'test')`, teamID, since); err != nil {
		t.Fatalf("assign free plan: %v", err)
	}
}

func seedComputeInterval(t *testing.T, teamID, sandboxID uuid.UUID, vcpu, memoryMib int, started time.Time, ended *time.Time) {
	t.Helper()
	reason := any(nil)
	if ended != nil {
		reason = "paused"
	}
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO sandbox_compute_billing_interval (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, sandboxID, teamID, vcpu, memoryMib, started, ended, reason); err != nil {
		t.Fatalf("seed compute interval: %v", err)
	}
}

func eligible(t *testing.T, teamID uuid.UUID) bool {
	t.Helper()
	ok, err := testQueries.IsTeamSandboxBillingEligible(context.Background(), teamID)
	if err != nil {
		t.Fatalf("eligibility: %v", err)
	}
	return ok
}

func cents(t *testing.T, row db.GetFreeAllowanceRow) (allowance, used float64) {
	t.Helper()
	a, err := row.AllowanceUsd.Float64Value()
	if err != nil {
		t.Fatal(err)
	}
	u, err := row.UsedUsd.Float64Value()
	if err != nil {
		t.Fatal(err)
	}
	return a.Float64 * 100, u.Float64 * 100
}

func TestIntegration_FreeAllowance_UnassignedTeamKeepsLegacyRules(t *testing.T) {
	ctx := context.Background()
	trial, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, expires_at)
		VALUES ($1, 5, 5, 'signup trial credit', now() - interval '1 second')`, trial); err != nil {
		t.Fatalf("seed expired trial: %v", err)
	}
	if eligible(t, trial) {
		t.Fatal("an unassigned team with an expired trial became eligible")
	}
	sbx := seedActiveSandbox(t, trial, "free-unassigned")
	seedComputeInterval(t, trial, sbx, 4, 8192, time.Now().Add(-10*time.Hour), nil)
	if _, err := testQueries.GetFreeAllowance(ctx, trial); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("free allowance for an unassigned team = %v, want no rows", err)
	}
	if blocked, err := testQueries.RefreshFreeAllowance(ctx, trial); err != nil || blocked {
		t.Fatalf("refresh for an unassigned team = %v, %v; want not blocked", blocked, err)
	}
	var reason *string
	if err := testPool.QueryRow(ctx, `SELECT billing_pause_reason($1, $2)`, trial, sbx).Scan(&reason); err != nil || reason == nil || *reason != "billing_ineligible" {
		t.Fatalf("pause reason = %v (err %v), want billing_ineligible", reason, err)
	}
}

func TestIntegration_FreeAllowance_FreeTeamNeedsNoCardOrCredit(t *testing.T) {
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, expires_at)
		VALUES ($1, 5, 5, 'signup trial credit', now() - interval '1 second')`, team); err != nil {
		t.Fatalf("seed expired trial: %v", err)
	}
	assignFreePlan(t, team, time.Now().Add(-time.Hour))
	if !eligible(t, team) {
		t.Fatal("a Free team without card or credit is not eligible")
	}
	row, err := testQueries.GetFreeAllowance(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	allowance, used := cents(t, row)
	if row.HasWindow || math.Abs(allowance-13.32) > 1e-9 || used != 0 || row.Exhausted {
		t.Fatalf("fresh Free allowance = %+v (allowance %v used %v), want no window, 13.32c, nothing used", row, allowance, used)
	}
}

func TestIntegration_FreeAllowance_CapPausesAndRefusesUntilReset(t *testing.T) {
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	now := time.Now()
	assignFreePlan(t, team, now.Add(-48*time.Hour))
	sbx := seedActiveSandbox(t, team, "free-capped")
	started := now.Add(-3 * time.Hour)
	seedComputeInterval(t, team, sbx, 1, 1024, started, nil)

	blocked, err := testQueries.RefreshFreeAllowance(ctx, team)
	if err != nil || !blocked {
		t.Fatalf("refresh after 3h of 1 vCPU + 1 GiB = %v, %v; want blocked", blocked, err)
	}
	if eligible(t, team) {
		t.Fatal("a capped Free team is still eligible")
	}
	admission, err := testQueries.GetTeamSandboxAdmission(ctx, team)
	if err != nil || !admission.AllowanceBlocked || admission.AllowanceResetsAt.Sub(started.Add(24*time.Hour)).Abs() > time.Millisecond {
		t.Fatalf("admission %+v (err %v), want the cap until window start + 24h = %v", admission, err, started.Add(24*time.Hour))
	}
	row, err := testQueries.GetFreeAllowance(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	allowance, used := cents(t, row)
	if !row.HasWindow || !row.Exhausted || used < allowance {
		t.Fatalf("capped allowance = %+v, want an exhausted window", row)
	}
	teams, err := testQueries.ListTeamsWithBillingPauseDue(ctx, db.ListTeamsWithBillingPauseDueParams{BatchLimit: 100000})
	if err != nil || !slices.Contains(teams, team) {
		t.Fatalf("teams with pauses due = %v (err %v), want the capped team", teams, err)
	}
	claimed, err := testQueries.ClaimBillingPauseSandbox(ctx, db.ClaimBillingPauseSandboxParams{ID: sbx, TeamID: team, LeaseSeconds: 90})
	if err != nil || claimed.PauseOpTrigger == nil || *claimed.PauseOpTrigger != "free_allowance_exhausted" {
		t.Fatalf("claim = %+v, %v; want trigger free_allowance_exhausted", claimed, err)
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE sandbox_compute_billing_interval SET started_at = started_at - interval '24 hours', ended_at = now() - interval '22 hours'
		WHERE sandbox_id = $1`, sbx); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE billing_free_allowance SET window_started_at = window_started_at - interval '24 hours',
		       resets_at = resets_at - interval '24 hours', blocked_until = blocked_until - interval '24 hours'
		WHERE team_id = $1`, team); err != nil {
		t.Fatal(err)
	}
	if !eligible(t, team) {
		t.Fatal("a Free team is still refused after its window reset")
	}
	row, err = testQueries.GetFreeAllowance(ctx, team)
	if err != nil || row.HasWindow || row.Exhausted {
		t.Fatalf("after reset = %+v (err %v), want no open window until the next start", row, err)
	}
}

func TestIntegration_FreeAllowance_WindowStartsAtFirstStartAfterPreviousWindow(t *testing.T) {
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	now := time.Now()
	assignFreePlan(t, team, now.Add(-72*time.Hour))
	sbx := seedActiveSandbox(t, team, "free-window")
	first := now.Add(-50 * time.Hour)
	firstEnd := first.Add(30 * time.Minute)
	seedComputeInterval(t, team, sbx, 1, 1024, first, &firstEnd)
	second := now.Add(-10 * time.Hour)
	secondEnd := second.Add(20 * time.Minute)
	seedComputeInterval(t, team, sbx, 1, 1024, second, &secondEnd)

	row, err := testQueries.GetFreeAllowance(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	if !row.HasWindow || row.WindowStartedAt.Sub(second).Abs() > time.Millisecond {
		t.Fatalf("window started %v, want the first start after the earlier window ended (%v)", row.WindowStartedAt, second)
	}
	allowance, used := cents(t, row)
	want := 20 * 60 * (0.000014 + 0.0000045) * 100
	if math.Abs(used-want) > 0.01 || row.Exhausted || allowance <= used {
		t.Fatalf("used %v cents, want %v from the current window only", used, want)
	}
}

func TestIntegration_FreeAllowance_UsageBeforeFreeIsNotCounted(t *testing.T) {
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	now := time.Now()
	since := now.Add(-time.Hour)
	assignFreePlan(t, team, since)
	sbx := seedActiveSandbox(t, team, "free-carried")
	seedComputeInterval(t, team, sbx, 8, 32768, now.Add(-5*time.Hour), nil)

	row, err := testQueries.GetFreeAllowance(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	if row.WindowStartedAt.Sub(since).Abs() > time.Millisecond {
		t.Fatalf("window started %v, want the Free assignment %v", row.WindowStartedAt, since)
	}
	if !row.Exhausted {
		t.Fatal("an 8 vCPU sandbox running for an hour on Free did not exhaust the allowance")
	}
}

func TestIntegration_TeamPauseAll_RetriesRevertsAndSparesLaterResumes(t *testing.T) {
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	assignFreePlan(t, team, time.Now())
	if _, err := testPool.Exec(ctx, `UPDATE team SET max_sandboxes = 10 WHERE id = $1`, team); err != nil {
		t.Fatal(err)
	}
	before := seedActiveSandbox(t, team, "pause-all-before")

	if n, err := testQueries.RequestTeamPauseAll(ctx, db.RequestTeamPauseAllParams{TeamID: team, Reason: "plan_switch_free"}); err != nil || n != 1 {
		t.Fatalf("request named %d sandboxes (err %v), want the one running", n, err)
	}
	if n, err := testQueries.RequestTeamPauseAll(ctx, db.RequestTeamPauseAllParams{TeamID: team, Reason: "plan_switch_free"}); err != nil || n != 0 {
		t.Fatalf("repeated request named %d more (err %v), want none", n, err)
	}
	after := seedActiveSandbox(t, team, "pause-all-after")
	due := func() []uuid.UUID {
		t.Helper()
		ids, err := testQueries.ListBillingPauseSandboxes(ctx, db.ListBillingPauseSandboxesParams{TeamID: team, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	if ids := due(); !slices.Equal(ids, []uuid.UUID{before}) {
		t.Fatalf("due = %v, want only the sandbox running at the request", ids)
	}
	teams, err := testQueries.ListTeamsWithBillingPauseDue(ctx, db.ListTeamsWithBillingPauseDueParams{BatchLimit: 100000})
	if err != nil || !slices.Contains(teams, team) {
		t.Fatalf("teams with pauses due = %v (err %v)", teams, err)
	}

	claimed, err := testQueries.ClaimBillingPauseSandbox(ctx, db.ClaimBillingPauseSandboxParams{ID: before, TeamID: team, LeaseSeconds: 90})
	if err != nil || claimed.PauseOpTrigger == nil || *claimed.PauseOpTrigger != "plan_switch_free" {
		t.Fatalf("claim = %+v, %v; want trigger plan_switch_free", claimed, err)
	}
	if _, err := testQueries.RevertPauseToActive(ctx, db.RevertPauseToActiveParams{SandboxID: before, TeamID: team, PauseOpID: claimed.PauseOpID, PauseOpLeaseVersion: &claimed.PauseOpLeaseVersion}); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if n, err := testQueries.SettleTeamPauseTargets(ctx, team); err != nil || n != 0 {
		t.Fatalf("settled %d targets (err %v) after a revert, want the target kept", n, err)
	}
	if ids := due(); !slices.Equal(ids, []uuid.UUID{before}) {
		t.Fatalf("due after revert = %v, want the reverted sandbox again", ids)
	}

	claimed, err = testQueries.ClaimBillingPauseSandbox(ctx, db.ClaimBillingPauseSandboxParams{ID: before, TeamID: team, LeaseSeconds: 90})
	if err != nil {
		t.Fatal(err)
	}
	if err := finalize(before, team, uuid.UUID(claimed.PauseOpID.Bytes), claimed.PauseOpLeaseVersion); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active' WHERE id = $1`, before); err != nil {
		t.Fatal(err)
	}
	if ids := due(); len(ids) != 0 {
		t.Fatalf("due after the pause landed and the customer resumed = %v, want none", ids)
	}
	if n, err := testQueries.RequestTeamPauseAll(ctx, db.RequestTeamPauseAllParams{TeamID: team, Reason: "plan_switch_free"}); err != nil || n != 0 {
		t.Fatalf("retry after a later resume named %d (err %v), want none", n, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_plan_assignment SET effective_to=clock_timestamp() WHERE team_id=$1 AND effective_to IS NULL`, team); err != nil {
		t.Fatal(err)
	}
	assignFreePlan(t, team, time.Now())

	if n, err := testQueries.RequestTeamPauseAll(ctx, db.RequestTeamPauseAllParams{TeamID: team, Reason: "plan_switch_free"}); err != nil || n != 2 {
		t.Fatalf("second request named %d (err %v), want both running sandboxes", n, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_plan_assignment SET effective_to = now() WHERE team_id = $1 AND effective_to IS NULL`, team); err != nil {
		t.Fatal(err)
	}
	if ids := due(); len(ids) != 0 {
		t.Fatalf("due after the team left Free = %v, want the switch-to-Free pause dropped", ids)
	}
	_ = after
}

func activationBucket(t *testing.T, teamID uuid.UUID) (string, string) {
	t.Helper()
	var bucket string
	var reason *string
	if err := testPool.QueryRow(context.Background(), `SELECT bucket, reason FROM pricing_v2_activation_bucket($1)`, teamID).Scan(&bucket, &reason); err != nil {
		t.Fatalf("activation bucket: %v", err)
	}
	if reason == nil {
		return bucket, ""
	}
	return bucket, *reason
}

func TestIntegration_PricingV2Activation_Buckets(t *testing.T) {
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}

	noCard, _ := seedTeamAndKey(t)
	exec(`INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, expires_at)
		VALUES ($1, 5, 0, 'signup trial credit', now() - interval '1 second')`, noCard)

	payg, _ := seedTeamAndKey(t)
	exec(`INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'past_due')`, payg, "cus_"+payg.String(), "sub_"+payg.String())

	lapsed, _ := seedTeamAndKey(t)
	exec(`INSERT INTO team_billing_account (team_id, stripe_customer_id) VALUES ($1, $2)`, lapsed, "cus_"+lapsed.String())

	granted, _ := seedTeamAndKey(t)
	exec(`INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason) VALUES ($1, 50, 50, 'staff credit')`, granted)

	assigned, _ := seedTeamAndKey(t)
	assignFreePlan(t, assigned, time.Now())

	blocked, _ := seedTeamAndKey(t)
	exec(`INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status)
		VALUES ($1, $2, $3, 'active')`, blocked, "cus_"+blocked.String(), "sub_"+blocked.String())
	exec(`INSERT INTO abuse_restrictions (subject_type, subject_value, subject_team_id, action, source, reason)
		VALUES ('team', $1::text, $1::uuid, 'create', 'test', 'test')`, blocked)

	checkoutLease, _ := seedTeamAndKey(t)
	exec(`INSERT INTO team_billing_account(team_id,checkout_initializing_at) VALUES($1,clock_timestamp())`, checkoutLease)
	checkoutPossible, _ := seedTeamAndKey(t)
	exec(`INSERT INTO team_billing_account(team_id,checkout_may_exist) VALUES($1,true)`, checkoutPossible)
	paidChoice, _ := seedTeamAndKey(t)
	exec(`INSERT INTO billing_signup_choice(team_id,state,offer_key,generation,actor_id,base_price_id,request_payload)
        VALUES($1,'pending','pro_monthly',clock_timestamp(),$2,'price_test','{}')
        ON CONFLICT(team_id) DO UPDATE SET state='pending',offer_key='pro_monthly',generation=clock_timestamp(),actor_id=$2,base_price_id='price_test',request_payload='{}'`, paidChoice, uuid.New())
	for _, tc := range []struct {
		name   string
		team   uuid.UUID
		bucket string
		reason string
	}{
		{"no card", noCard, "free", ""},
		{"card on file", payg, "legacy_payg", ""},
		{"customer without a live subscription", lapsed, "lapsed", ""},
		{"no card with granted credit", granted, "free", ""},
		{"abuse blocked with a card", blocked, "blocked", "abuse_blocked"},
		{"already assigned", assigned, "assigned", "already_assigned"},
		{"checkout lease", checkoutLease, "skipped", "checkout_pending"},
		{"checkout may exist", checkoutPossible, "skipped", "checkout_pending"},
		{"pending paid choice", paidChoice, "skipped", "checkout_pending"},
	} {
		if bucket, reason := activationBucket(t, tc.team); bucket != tc.bucket || reason != tc.reason {
			t.Errorf("%s: bucket %q reason %q, want %q %q", tc.name, bucket, reason, tc.bucket, tc.reason)
		}
	}

	assignFreePlan(t, blocked, time.Now())
	if eligible(t, blocked) {
		t.Fatal("assigning Free lifted an abuse block")
	}
}

func TestIntegration_FreeShape_AdmissionCarriesLimitsAndResumeRefusesLarger(t *testing.T) {
	ctx := context.Background()
	unassigned, _ := seedTeamAndKey(t)
	if row, err := testQueries.GetTeamSandboxAdmission(ctx, unassigned); err != nil || row.ShapeLimited {
		t.Fatalf("unassigned admission = %+v, %v; want no shape limit", row, err)
	}

	team, _ := seedTeamAndKey(t)
	assignFreePlan(t, team, time.Now())
	row, err := testQueries.GetTeamSandboxAdmission(ctx, team)
	if err != nil || !row.Eligible || !row.ShapeLimited || row.MaxVcpu != 1 || row.MaxMemoryMib != 1024 || row.MaxDiskMib != 4096 {
		t.Fatalf("Free admission = %+v, %v; want eligible with 1 vCPU / 1024 MiB / 4096 MiB", row, err)
	}

	large := seedPausedSandbox(t, team)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET vcpu_count = 2, memory_mib = 1024, disk_mib = 4096 WHERE id = $1`, large); err != nil {
		t.Fatal(err)
	}
	fits := seedPausedSandbox(t, team)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET vcpu_count = 1, memory_mib = 1024, disk_mib = 4096 WHERE id = $1`, fits); err != nil {
		t.Fatal(err)
	}
	claim := func(id uuid.UUID) (db.ClaimResumeRow, error) {
		return testQueries.ClaimResume(ctx, db.ClaimResumeParams{ID: id, TeamID: team, LockKey: id.String(),
			MaxVcpu: &row.MaxVcpu, MaxMemoryMib: &row.MaxMemoryMib, MaxDiskMib: &row.MaxDiskMib})
	}
	if _, err := claim(large); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("claim of a sandbox above the Free shape = %v, want no rows", err)
	}
	if kept, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: large, TeamID: team}); err != nil || kept.Status != db.SandboxStatusPaused {
		t.Fatalf("refused sandbox = %s, %v; want it kept paused", kept.Status, err)
	}
	if c, err := claim(fits); err != nil || c.Sandbox.Status != db.SandboxStatusResuming {
		t.Fatalf("claim of a sandbox within the Free shape = %+v, %v", c, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'paused' WHERE id = $1`, fits); err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.ClaimResume(ctx, db.ClaimResumeParams{ID: large, TeamID: team, LockKey: large.String()}); err == nil {
		t.Fatal("claim without supplied caps bypassed the current Free plan")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "SS002" {
			t.Fatalf("claim without supplied caps = %v", err)
		}
	}
}

func TestIntegration_FreeAllowance_MissingAllowanceCapsAtOnce(t *testing.T) {
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_plan_assignment (team_id, plan_key, kind, terms, limits, effective_from, source, reason)
		VALUES ($1, 'free', 'free', '{}', '{"max_concurrent":1}', now() - interval '1 hour', 'migration', 'test')`, team); err != nil {
		t.Fatal(err)
	}
	sbx := seedActiveSandbox(t, team, "free-no-allowance")
	seedComputeInterval(t, team, sbx, 1, 1024, time.Now().Add(-time.Minute), nil)
	if blocked, err := testQueries.RefreshFreeAllowance(ctx, team); err != nil || !blocked {
		t.Fatalf("refresh with no frozen allowance = %v, %v; want capped rather than unlimited", blocked, err)
	}
}

func TestIntegration_FreeShape_AbsentCapsDoNotLimit(t *testing.T) {
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_plan_assignment (team_id, plan_key, kind, terms, limits, effective_from, source, reason)
		VALUES ($1, 'free', 'free', '{}', '{"max_concurrent":1,"max_vcpu":2}', now(), 'migration', 'test')`, team); err != nil {
		t.Fatal(err)
	}
	row, err := testQueries.GetTeamSandboxAdmission(ctx, team)
	if err != nil || !row.ShapeLimited || row.MaxVcpu != 2 || row.MaxMemoryMib != 0 || row.MaxDiskMib != 0 {
		t.Fatalf("admission = %+v, %v; want only the vCPU cap", row, err)
	}
	sbx := seedPausedSandbox(t, team)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET vcpu_count = 2, memory_mib = 8192, disk_mib = 65536 WHERE id = $1`, sbx); err != nil {
		t.Fatal(err)
	}
	if c, err := testQueries.ClaimResume(ctx, db.ClaimResumeParams{ID: sbx, TeamID: team, LockKey: sbx.String(), MaxVcpu: &row.MaxVcpu}); err != nil || c.Sandbox.Status != db.SandboxStatusResuming {
		t.Fatalf("claim within the only cap = %+v, %v", c, err)
	}
}

func TestIntegration_FreeAllowance_CapLabelEndsWhenTeamLeavesFree(t *testing.T) {
	ctx := context.Background()
	team, _ := seedTeamAndKey(t)
	assignFreePlan(t, team, time.Now().Add(-48*time.Hour))
	sbx := seedActiveSandbox(t, team, "free-left")
	seedComputeInterval(t, team, sbx, 1, 1024, time.Now().Add(-3*time.Hour), nil)
	if blocked, err := testQueries.RefreshFreeAllowance(ctx, team); err != nil || !blocked {
		t.Fatalf("refresh = %v, %v; want capped", blocked, err)
	}
	if row, err := testQueries.GetTeamSandboxAdmission(ctx, team); err != nil || !row.AllowanceBlocked {
		t.Fatalf("admission = %+v, %v; want the cap reported", row, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE team_plan_assignment SET effective_to = now() WHERE team_id = $1 AND effective_to IS NULL`, team); err != nil {
		t.Fatal(err)
	}
	if row, err := testQueries.GetTeamSandboxAdmission(ctx, team); err != nil || row.AllowanceBlocked || row.ShapeLimited {
		t.Fatalf("admission after leaving Free = %+v, %v; want no Free cap or shape", row, err)
	}
}

type activationStripe struct {
	api.StripeBillingClient
	credit        map[string]float64
	before        func()
	unknownErrors bool
}

func (s activationStripe) GetCustomerCreditBalance(_ context.Context, customer string) (api.StripeCreditBalance, error) {
	if s.before != nil {
		s.before()
	}
	if _, ok := s.credit[customer]; !ok && s.unknownErrors {
		return api.StripeCreditBalance{}, errors.New("customer unavailable")
	}
	return api.StripeCreditBalance{AvailableUSD: s.credit[customer]}, nil
}

func TestIntegration_PricingV2Activation_RechecksSwitchAndCustomerAfterStripe(t *testing.T) {
	for _, change := range []string{"switch_off", "customer_changed"} {
		t.Run(change, func(t *testing.T) {
			ctx := t.Context()
			team, _ := seedTeamAndKey(t)
			region := "usw"
			t.Cleanup(func() {
				_, _ = testPool.Exec(context.Background(), `UPDATE team SET home_region='use' WHERE id=$1`, team)
			})
			customer := "cus_" + team.String()
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := testPool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`UPDATE team SET home_region=$2 WHERE id=$1`, team, region)
			exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, team, customer)
			setPricingSwitch(t, "v2")
			stripe := activationStripe{credit: map[string]float64{customer: 5}, before: func() {
				if change == "switch_off" {
					_, _ = testPool.Exec(ctx, `UPDATE billing_pricing_switch SET pricing_version='legacy'`)
				} else {
					_, _ = testPool.Exec(ctx, `UPDATE team_billing_account SET stripe_customer_id=$2 WHERE team_id=$1`, team, customer+"_replacement")
				}
			}}
			batch, err := api.NewPricingV2Activation(testPool, stripe, region, testSystemTeamID.String()).ApplyBatch(ctx, "operator@example.com", "launch", 10)
			if change == "switch_off" {
				if !errors.Is(err, api.ErrPricingV2Off) {
					t.Fatalf("apply after switch-off = %+v, %v", batch, err)
				}
			} else if err != nil || batch.Deferred != 1 {
				t.Fatalf("apply after customer change = %+v, %v; want one deferred", batch, err)
			}
			var assigned bool
			if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1)`, team).Scan(&assigned); err != nil || assigned {
				t.Fatalf("assigned after authority changed = %v, %v", assigned, err)
			}
		})
	}
}

func TestIntegration_PricingV2Activation_ApplyAssignsEveryBucketOnce(t *testing.T) {
	ctx := context.Background()
	region := "usw"
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := testPool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	team := func() uuid.UUID {
		id, _ := seedTeamAndKey(t)
		exec(`UPDATE team SET home_region = $2 WHERE id = $1`, id, region)
		return id
	}
	payg, lapsedCredit, lapsedSpent, noCard, blocked := team(), team(), team(), team(), team()
	pendingCheckout := team()
	exec(`INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,$2)`, pendingCheckout, "cus_"+pendingCheckout.String())
	exec(`INSERT INTO billing_signup_choice(team_id,state,offer_key,generation,actor_id,base_price_id,request_payload)
        VALUES($1,'pending','pro_monthly',clock_timestamp(),$2,'price_test','{}')
        ON CONFLICT(team_id) DO UPDATE SET state='pending',offer_key='pro_monthly',generation=clock_timestamp(),actor_id=$2,base_price_id='price_test',request_payload='{}'`, pendingCheckout, uuid.New())
	exec(`INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status) VALUES ($1, $2, $3, 'active')`, payg, "cus_"+payg.String(), "sub_"+payg.String())
	exec(`INSERT INTO team_billing_account (team_id, stripe_customer_id, stripe_subscription_id, stripe_subscription_status) VALUES ($1, $2, $3, 'canceled')`, lapsedCredit, "cus_"+lapsedCredit.String(), "sub_"+lapsedCredit.String())
	exec(`INSERT INTO team_billing_account (team_id, stripe_customer_id) VALUES ($1, $2)`, lapsedSpent, "cus_"+lapsedSpent.String())
	exec(`INSERT INTO abuse_restrictions (subject_type, subject_value, subject_team_id, action, source, reason) VALUES ('team', $1::text, $1::uuid, 'resume', 'test', 'test')`, blocked)
	stripe := activationStripe{credit: map[string]float64{"cus_" + lapsedCredit.String(): 3.5}}
	activation := api.NewPricingV2Activation(testPool, stripe, region, testSystemTeamID.String())

	report, err := activation.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listed := func(teams []api.ActivationTeam, id uuid.UUID) bool {
		return slices.ContainsFunc(teams, func(a api.ActivationTeam) bool { return a.TeamID == id })
	}
	if report.PricingVersion != "legacy" || !listed(report.BlockedToFree, blocked) || !listed(report.LapsedWithCredit, lapsedCredit) ||
		!listed(report.LapsedNoCredit, lapsedSpent) || report.Pending < 5 || !listed(report.Skipped, pendingCheckout) {
		t.Fatalf("report = %+v", report)
	}
	if _, err := activation.ApplyBatch(ctx, "operator@example.com", "pricing v2 launch", 500); !errors.Is(err, api.ErrPricingV2Off) {
		t.Fatalf("apply with the switch off = %v, want ErrPricingV2Off", err)
	}
	var assignments int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM team_plan_assignment a JOIN team t ON t.id = a.team_id WHERE t.home_region = $1`, region).Scan(&assignments); err != nil || assignments != 0 {
		t.Fatalf("assignments while off = %d (err %v), want none", assignments, err)
	}

	exec(`UPDATE billing_pricing_switch SET pricing_version = 'v2'`)
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE billing_pricing_switch SET pricing_version = 'legacy'`)
	})
	for remaining := report.Pending; remaining > 0; {
		batch, err := activation.ApplyBatch(ctx, "operator@example.com", "pricing v2 launch", 2)
		if err != nil {
			t.Fatal(err)
		}
		if batch.AssignedFree+batch.AssignedLegacyPAYG == 0 {
			t.Fatalf("a batch made no progress with %d remaining", batch.Remaining)
		}
		remaining = batch.Remaining
	}
	for id, want := range map[uuid.UUID]string{payg: "legacy_payg", lapsedCredit: "legacy_payg", lapsedSpent: "free", noCard: "free", blocked: "free"} {
		var kind, source string
		if err := testPool.QueryRow(ctx, `SELECT kind, source FROM team_plan_assignment WHERE team_id = $1 AND effective_to IS NULL`, id).Scan(&kind, &source); err != nil || kind != want || source != "migration" {
			t.Errorf("team %s: kind %q source %q (err %v), want %s from migration", id, kind, source, err, want)
		}
	}
	allowanceRow, err := testQueries.GetFreeAllowance(ctx, noCard)
	if err != nil {
		t.Fatal(err)
	}
	allowance, used := cents(t, allowanceRow)
	if allowance <= 0 || used != 0 || !eligible(t, noCard) {
		t.Fatalf("migrated Free allowance = %v, used = %v; want positive allowance and admission", allowance, used)
	}
	exec(`UPDATE billing_pricing_switch SET pricing_version = 'legacy'`)
	if !eligible(t, noCard) {
		t.Fatal("switching off stopped servicing an existing Free assignment")
	}
	if row, err := testQueries.GetTeamSandboxAdmission(ctx, noCard); err != nil || !row.ShapeLimited {
		t.Fatalf("switch-off admission = %+v, %v; want the existing Free shape enforced", row, err)
	}
	exec(`UPDATE billing_pricing_switch SET pricing_version = 'v2'`)
	var checkoutAssigned bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1)`, pendingCheckout).Scan(&checkoutAssigned); err != nil || checkoutAssigned {
		t.Fatalf("in-flight paid checkout assigned = %v, %v", checkoutAssigned, err)
	}
	if eligible(t, blocked) {
		t.Fatal("activation lifted an abuse block")
	}
	again, err := activation.ApplyBatch(ctx, "operator@example.com", "pricing v2 launch", 500)
	if err != nil || again.AssignedFree+again.AssignedLegacyPAYG != 0 || again.Remaining != 0 {
		t.Fatalf("re-run = %+v, %v; want nothing left to do", again, err)
	}
	var audits int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type = 'billing.pricing_v2.activation_applied' AND new_value->>'region' = $1 AND new_value->>'actor' = 'operator@example.com'`, region).Scan(&audits); err != nil || audits < 3 {
		t.Fatalf("audit rows = %d (err %v), want one per batch", audits, err)
	}
}

func TestIntegration_PricingV2Activation_BackfillsContractsWithoutChangingAuthority(t *testing.T) {
	ctx := t.Context()
	contracts := []db.BillingCommercialContract{
		commercialActivate(t, commercialFixture(t, false)),
		commercialActivate(t, commercialFixture(t, true)),
	}
	pending := commercialFixture(t, false)
	before := map[uuid.UUID]string{}
	for _, c := range append(append([]db.BillingCommercialContract{}, contracts...), pending) {
		if _, err := testPool.Exec(ctx, `UPDATE team SET home_region='usw' WHERE id=$1`, c.TeamID); err != nil {
			t.Fatal(err)
		}
		var snapshot string
		if err := testPool.QueryRow(ctx, `SELECT to_jsonb(c)::text FROM billing_commercial_contract c WHERE id=$1`, c.ID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		before[c.ID] = snapshot
	}
	for _, c := range contracts {
		if _, err := testPool.Exec(ctx, `INSERT INTO billing_contract_limits(contract_id,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates)
            VALUES($1,77,3,8192,16384,6)`, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	setPricingSwitch(t, "v2")
	activation := api.NewPricingV2Activation(testPool, nil, "usw", testSystemTeamID.String())
	report, err := activation.Report(ctx)
	if err != nil || report.ToContract != 2 || report.SkippedReasons["pending_contract"] != 1 {
		t.Fatalf("contract report = %+v, %v", report, err)
	}
	batch, err := activation.ApplyBatch(ctx, "operator@example.com", "preserve existing contracts", 500)
	if err != nil || batch.AssignedContract != 2 || batch.AssignedFree != 0 || batch.Remaining != 0 {
		t.Fatalf("contract backfill = %+v, %v", batch, err)
	}
	for _, c := range contracts {
		var linked uuid.UUID
		var kind string
		var fee, credit int64
		var limit int
		if err := testPool.QueryRow(ctx, `SELECT contract_id,kind,(terms->>'fee_cents')::bigint,(terms->>'monthly_credit_cents')::bigint,
            (limits->>'max_concurrent')::int FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL`, c.TeamID).
			Scan(&linked, &kind, &fee, &credit, &limit); err != nil {
			t.Fatal(err)
		}
		if linked != c.ID || kind != "subscription" || fee != c.ChargeAmountCents || credit != c.EntitlementAmountCents || limit != 77 {
			t.Fatalf("contract assignment = %s %s fee=%d credit=%d limit=%d", linked, kind, fee, credit, limit)
		}
		var snapshot string
		if err := testPool.QueryRow(ctx, `SELECT to_jsonb(c)::text FROM billing_commercial_contract c WHERE id=$1`, c.ID).Scan(&snapshot); err != nil || snapshot != before[c.ID] {
			t.Fatalf("contract authority changed: %v", err)
		}
	}
	var assigned bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1)`, pending.TeamID).Scan(&assigned); err != nil || assigned {
		t.Fatalf("pending contract was assigned: %v, %v", assigned, err)
	}
	again, err := activation.ApplyBatch(ctx, "operator@example.com", "preserve existing contracts", 500)
	if err != nil || len(again.Assigned) != 0 {
		t.Fatalf("contract rerun = %+v, %v", again, err)
	}
}

func TestIntegration_PricingV2Activation_ContinuesPastUnreadableCustomers(t *testing.T) {
	ctx := t.Context()
	ids := make([]uuid.UUID, 201)
	for i := range ids {
		ids[i] = uuid.New()
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	if _, err := testPool.Exec(ctx, `INSERT INTO team(id,name,home_region) SELECT id,'migration-'||id::text,'usw' FROM unnest($1::uuid[]) x(id)`, ids); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `UPDATE team SET home_region='use' WHERE id=ANY($1)`, ids)
	})
	if _, err := testPool.Exec(ctx, `INSERT INTO team_billing_account(team_id,stripe_customer_id) SELECT id,'cus_'||id::text FROM unnest($1::uuid[]) x(id)`, ids); err != nil {
		t.Fatal(err)
	}
	setPricingSwitch(t, "v2")
	healthy := ids[len(ids)-1]
	activation := api.NewPricingV2Activation(testPool, activationStripe{credit: map[string]float64{"cus_" + healthy.String(): 5}, unknownErrors: true}, "usw", testSystemTeamID.String())
	first, err := activation.ApplyBatch(ctx, "operator@example.com", "launch", 500)
	if err != nil || len(first.Assigned) != 0 || first.Next == nil {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	second, err := activation.ApplyBatchAfter(ctx, "operator@example.com", "launch", 500, first.Next)
	if err != nil || second.AssignedLegacyPAYG != 1 || !slices.Contains(second.Assigned, healthy) {
		t.Fatalf("healthy customer behind failed reads = %+v, %v", second, err)
	}
	var holds int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM billing_pricing_adoption_credit_hold WHERE team_id=ANY($1)`, ids).Scan(&holds); err != nil || holds != 200 {
		t.Fatalf("durable unknown holds=%d %v", holds, err)
	}
	recovered := api.NewPricingV2Activation(testPool, activationStripe{credit: map[string]float64{"cus_" + ids[0].String(): 0}, unknownErrors: true}, "usw", testSystemTeamID.String())
	batch, err := recovered.ApplyBatch(ctx, "operator@example.com", "verified provider recovery", 500)
	if err != nil || !slices.Contains(batch.Assigned, ids[0]) {
		t.Fatalf("verified recovery=%+v %v", batch, err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM billing_pricing_adoption_credit_hold WHERE team_id=$1`, ids[0]).Scan(&holds); err != nil || holds != 0 {
		t.Fatalf("verified recovery retained hold=%d %v", holds, err)
	}

}

func TestIntegration_TeamPauseAll_WorkerConsumesTargetsWhileSwitchOff(t *testing.T) {
	ctx := t.Context()
	team, _ := seedTeamAndKey(t)
	assignFreePlan(t, team, time.Now())
	sandbox := seedActiveSandbox(t, team, "pause-worker-target")
	if _, err := testQueries.RequestTeamPauseAll(ctx, db.RequestTeamPauseAllParams{TeamID: team, Reason: "plan_switch_free"}); err != nil {
		t.Fatal(err)
	}
	h := pauseHandlers(t, &stubVMD{})
	api.RefreshActiveTrialEligibilityForTest(h, ctx)
	if state := readPauseOp(t, sandbox); state.status != "paused" {
		t.Fatalf("worker target status = %s, want paused", state.status)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status='active' WHERE id=$1`, sandbox); err != nil {
		t.Fatal(err)
	}
	api.RefreshActiveTrialEligibilityForTest(h, ctx)
	if state := readPauseOp(t, sandbox); state.status != "active" {
		t.Fatalf("later resume status = %s, want active", state.status)
	}
}

func TestIntegration_TeamPauseAll_DeletionPreservesAssignmentAudit(t *testing.T) {
	ctx := t.Context()
	setPricingSwitch(t, "v2")
	team, err := testQueries.CreateTeam(ctx, "pause-delete-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.RequestTeamPauseAll(ctx, db.RequestTeamPauseAllParams{TeamID: team.ID, Reason: "plan_switch_free"}); err != nil {
		t.Fatal(err)
	}
	if err := testQueries.DeleteTeam(ctx, team.ID); err != nil {
		t.Fatal(err)
	}
	var assignments, requests int
	if err := testPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM team_plan_assignment WHERE team_id=$1),
        (SELECT count(*) FROM billing_team_pause_request WHERE team_id=$1)`, team.ID).Scan(&assignments, &requests); err != nil || assignments != 1 || requests != 0 {
		t.Fatalf("deleted team assignment audit=%d pause requests=%d, %v", assignments, requests, err)
	}
}

func TestIntegration_PricingV2Activation_RequiresSystemTeamBeforeApply(t *testing.T) {
	for _, value := range []string{"", "invalid", uuid.Nil.String()} {
		_, err := api.NewPricingV2Activation(testPool, nil, "usw", value).ApplyBatch(t.Context(), "operator@example.com", "launch", 10)
		if err == nil || !strings.Contains(err.Error(), "SYSTEM_TEAM_ID") {
			t.Fatalf("apply system team %q = %v", value, err)
		}
	}
}

func TestIntegration_FreeShape_CachedLegacyAdmissionCannotBypassDowngrade(t *testing.T) {
	ctx := t.Context()
	team, key := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES($1,5,5,'signup trial credit')`, team); err != nil {
		t.Fatal(err)
	}
	if err := testQueries.RefreshTeamTrialEligibility(ctx, team); err != nil {
		t.Fatal(err)
	}
	paused := seedPausedSandbox(t, team)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET vcpu_count=2,memory_mib=1024,disk_mib=4096 WHERE id=$1`, paused); err != nil {
		t.Fatal(err)
	}
	tpl, err := testQueries.CreateTemplate(ctx, db.CreateTemplateParams{TeamID: testSystemTeamID, Name: "shape-" + uuid.NewString(), BuildSpec: []byte(`{"from":"example/image:stable"}`), Vcpu: 2, MemoryMib: 1024, DiskMib: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE template SET status='ready',snapshot_path='/snapshots/shape.snap',mem_path='/snapshots/shape.mem',base_path='/snapshots/shape.ext4' WHERE id=$1`, tpl.ID); err != nil {
		t.Fatal(err)
	}
	h := pauseHandlers(t, &stubVMD{})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if !api.RequireBillingEligibleForTest(h, c, team) {
		t.Fatalf("legacy cache warmup: %d %s", w.Code, w.Body.String())
	}
	assignFreePlan(t, team, time.Now())
	setOwnerHeartbeat(t, testDefaultHostID, time.Now())
	r := api.SetupRouter(ctx, h, testPool)
	created := do(r, http.MethodPost, "/sandboxes", key, `{"name":"shape-cache-bypass","from_template":"`+tpl.ID.String()+`"}`)
	if created.Code != http.StatusPaymentRequired || !strings.Contains(created.Body.String(), "sandbox_exceeds_plan_limits") {
		t.Fatalf("cached create = %d %s", created.Code, created.Body.String())
	}
	resumed := do(r, http.MethodPost, "/sandboxes/"+paused.String()+"/resume", key, `{}`)
	if resumed.Code != http.StatusPaymentRequired || !strings.Contains(resumed.Body.String(), "sandbox_exceeds_plan_limits") {
		t.Fatalf("cached resume = %d %s", resumed.Code, resumed.Body.String())
	}
	if state := readPauseOp(t, paused); state.status != "paused" {
		t.Fatalf("rejected resume state = %s", state.status)
	}
}

func TestIntegration_FreeShape_DowngradeSerializesWithInFlightAdmission(t *testing.T) {
	ctx := t.Context()
	team, _ := seedTeamAndKey(t)
	admission, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Rollback(context.Background())
	var sandbox uuid.UUID
	if err := admission.QueryRow(ctx, `INSERT INTO sandbox(team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib)
        VALUES($1,'in-flight-shape','starting',$2,2,1024,4096) RETURNING id`, team, testDefaultHostID).Scan(&sandbox); err != nil {
		t.Fatal(err)
	}
	change, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer change.Rollback(context.Background())
	if _, err := change.Exec(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = change.Exec(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,terms,limits,effective_from,source,reason)
        VALUES($1,'free','free','{}','{"max_concurrent":1,"max_vcpu":1,"max_memory_mib":1024,"max_disk_mib":4096}',clock_timestamp(),'plan_change','downgrade')`, team)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("downgrade crossed uncommitted admission: %v", err)
	}
	if err := change.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := admission.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assignFreePlan(t, team, time.Now())
	if n, err := testQueries.RequestTeamPauseAll(ctx, db.RequestTeamPauseAllParams{TeamID: team, Reason: "plan_switch_free"}); err != nil || n != 1 {
		t.Fatalf("downgrade queued %d, %v; want the admission that committed first", n, err)
	}
	var targeted bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_team_pause_target WHERE sandbox_id=$1)`, sandbox).Scan(&targeted); err != nil || !targeted {
		t.Fatalf("in-flight admission targeted=%v, %v", targeted, err)
	}
}

func TestIntegration_FreeShape_AssignmentContentionFailsWithoutWaiting(t *testing.T) {
	for _, mode := range []string{"plan_change", "admin_import"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			team, key := seedTeamAndKey(t)
			assignFreePlan(t, team, time.Now())
			paused := seedPausedSandbox(t, team)
			h := pauseHandlers(t, &stubVMD{})
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			if !api.RequireBillingEligibleForTest(h, c, team) {
				t.Fatalf("cache warmup: %s", w.Body.String())
			}
			holder, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(context.Background())
			lock := `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`
			if mode == "admin_import" {
				lock = `SELECT id FROM team WHERE id=$1 FOR UPDATE`
			}
			if _, err := holder.Exec(ctx, lock, team); err != nil {
				t.Fatal(err)
			}
			if mode == "admin_import" {
				if _, err := holder.Exec(ctx, `LOCK TABLE team_plan_assignment IN SHARE ROW EXCLUSIVE MODE`); err != nil {
					t.Fatal(err)
				}
			}
			var durations []float64
			for i := 0; i < 30; i++ {
				attempt, cancel := context.WithTimeout(ctx, time.Second)
				start := time.Now()
				_, err := testPool.Exec(attempt, `INSERT INTO sandbox(team_id,name,status,host_id,vcpu_count,memory_mib,disk_mib) VALUES($1,$2,'starting',$3,1,1024,4096)`, team, "shape-contention-"+uuid.NewString(), testDefaultHostID)
				durations = append(durations, float64(time.Since(start))/float64(time.Millisecond))
				cancel()
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "SS003" {
					t.Fatalf("admission waited on assignment owner: %v", err)
				}
			}
			sort.Float64s(durations)
			t.Logf("samples=%d contention refusal p50=%.3fms p95=%.3fms", len(durations), durations[15], durations[28])
			r := api.SetupRouter(ctx, h, testPool)
			resumed := do(r, http.MethodPost, "/sandboxes/"+paused.String()+"/resume", key, `{}`)
			if resumed.Code != http.StatusServiceUnavailable || !strings.Contains(resumed.Body.String(), "service_unavailable") {
				t.Fatalf("contended resume: %d %s", resumed.Code, resumed.Body.String())
			}
			if state := readPauseOp(t, paused); state.status != "paused" {
				t.Fatalf("contended resume state=%s", state.status)
			}
			if err := holder.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status='resuming' WHERE id=$1`, paused); err != nil {
				t.Fatalf("admission did not recover after assignment release: %v", err)
			}
		})
	}
}

func TestIntegration_FreeAllowance_RetryQueueFairnessAndRecovery(t *testing.T) {
	ctx := t.Context()
	setPricingSwitch(t, "legacy")
	ids := make([]uuid.UUID, 11)
	for i := range ids {
		ids[i], _ = seedTeamAndKey(t)
		assignFreePlan(t, ids[i], time.Now())
		seedActiveSandbox(t, ids[i], "retry-queue")
		if err := testQueries.ScheduleFreeAllowanceRetry(ctx, ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM billing_free_allowance_retry WHERE team_id=ANY($1)`, ids)
	})
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	after := ids[0]
	for i := len(after) - 1; i >= 0; i-- {
		if after[i] > 0 {
			after[i]--
			break
		}
		after[i] = 255
	}
	params := db.ListFreeTeamsWithActiveSandboxesParams{AfterTeamID: pgtype.UUID{Bytes: after, Valid: true}, BatchLimit: 1}
	normal, err := testQueries.ListFreeTeamsWithActiveSandboxes(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(normal, ids[0]) {
		t.Fatal("queued team can still consume the whole normal sweep deadline")
	}
	first, err := testQueries.ClaimFreeAllowanceRetries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := testQueries.ClaimFreeAllowanceRetries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 10 || len(second) != 1 {
		t.Fatalf("eleventh retry postponed without dispatch capacity: %d/%d", len(first), len(second))
	}
	if err := testQueries.ClearFreeAllowanceRetry(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	normal, err = testQueries.ListFreeTeamsWithActiveSandboxes(ctx, params)
	if err != nil || len(normal) != 1 || normal[0] != ids[0] {
		t.Fatalf("recovered retry missing from normal work: %v %v", normal, err)
	}
}
