//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// trialTeam is a trial team with one paused sandbox and a cached verdict
// stamped at a chosen time, so a test can place compute usage before or
// after that verdict.
type trialTeam struct {
	id, sandbox uuid.UUID
}

func seedTrialVerdict(t *testing.T, eligible bool, verdictAt time.Time) trialTeam {
	t.Helper()
	team, _ := seedTeamAndKey(t)
	storageExec(t, `INSERT INTO team_credit_grant(team_id,reason,amount_usd,remaining_usd,created_at)
		VALUES($1,'signup trial credit',5,5,$2)`, team, verdictAt.Add(-time.Hour))
	var sandbox uuid.UUID
	if err := testPool.QueryRow(t.Context(), `INSERT INTO sandbox(team_id,name,status,vcpu_count,memory_mib,host_id)
		VALUES($1,$2,'paused',1,1024,$3) RETURNING id`, team, "trial-activity-"+uuid.NewString(), testDefaultHostID).Scan(&sandbox); err != nil {
		t.Fatal(err)
	}
	storageExec(t, `INSERT INTO team_trial_eligibility_cache(team_id,eligible,updated_at) VALUES($1,$2,$3)`, team, eligible, verdictAt)
	t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM sandbox_compute_billing_interval WHERE team_id=$1`,
			`DELETE FROM sandbox WHERE team_id=$1`,
			`DELETE FROM team_trial_eligibility_cache WHERE team_id=$1`,
			`DELETE FROM team_credit_grant WHERE team_id=$1`,
			`DELETE FROM team WHERE id=$1`,
		} {
			_, _ = testPool.Exec(ctx, q, team)
		}
	})
	return trialTeam{id: team, sandbox: sandbox}
}

// usage records one compute interval; a nil end leaves it running.
func (tt trialTeam) usage(t *testing.T, startedAt time.Time, endedAt *time.Time) {
	t.Helper()
	if endedAt == nil {
		storageExec(t, `INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at)
			VALUES($1,$2,1,1024,$3)`, tt.sandbox, tt.id, startedAt)
		return
	}
	storageExec(t, `INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason)
		VALUES($1,$2,1,1024,$3,$4,'paused')`, tt.sandbox, tt.id, startedAt, *endedAt)
}

// dueForRefresh pages the sweep's selection query the way the sweep does and
// returns every team it would refresh on a pass with the given idle window.
func dueForRefresh(t *testing.T, idleSeconds int32) map[uuid.UUID]bool {
	t.Helper()
	due := map[uuid.UUID]bool{}
	var after pgtype.UUID
	for {
		page, err := testQueries.ListTeamsWithTrialCredits(t.Context(), db.ListTeamsWithTrialCreditsParams{
			IdleSeconds: idleSeconds, AfterTeamID: after, BatchLimit: 1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range page {
			due[id] = true
		}
		if len(page) < 1000 {
			return due
		}
		after = pgtype.UUID{Bytes: page[len(page)-1], Valid: true}
	}
}

// The fast tick revisits a trial team only while it consumes compute; an idle
// team waits for the slow pass, a false verdict waits for a newer grant.
func TestIntegration_TrialEligibilitySweepRefreshesOnlyActiveTeamsEachTick(t *testing.T) {
	now := time.Now().UTC()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	ptr := func(v time.Time) *time.Time { return &v }
	const idle = int32(600)

	running := seedTrialVerdict(t, true, now)
	running.usage(t, ago(time.Minute), nil)

	usedSinceVerdict := seedTrialVerdict(t, true, ago(time.Minute))
	usedSinceVerdict.usage(t, ago(5*time.Minute), ptr(ago(30*time.Second)))

	idleFresh := seedTrialVerdict(t, true, now)
	idleFresh.usage(t, ago(2*time.Hour), ptr(ago(time.Hour)))

	idleStale := seedTrialVerdict(t, true, ago(11*time.Minute))
	idleStale.usage(t, ago(2*time.Hour), ptr(ago(time.Hour)))

	exhausted := seedTrialVerdict(t, false, now)
	exhausted.usage(t, ago(time.Minute), nil)

	renewed := seedTrialVerdict(t, false, ago(time.Hour))
	storageExec(t, `INSERT INTO team_credit_grant(team_id,reason,amount_usd,remaining_usd,created_at)
		VALUES($1,'signup trial credit',5,5,$2)`, renewed.id, now)

	fast := dueForRefresh(t, idle)
	for name, tc := range map[string]struct {
		team trialTeam
		want bool
	}{
		"running sandbox":           {running, true},
		"usage since verdict":       {usedSinceVerdict, true},
		"idle, fresh verdict":       {idleFresh, false},
		"idle, verdict past window": {idleStale, true},
		"exhausted, no new grant":   {exhausted, false},
		"exhausted, renewed grant":  {renewed, true},
	} {
		if fast[tc.team.id] != tc.want {
			t.Errorf("fast tick: %s listed=%v want %v", name, fast[tc.team.id], tc.want)
		}
	}

	// The slow pass takes every eligible team, idle or not, and still leaves
	// a settled false verdict alone.
	slow := dueForRefresh(t, 0)
	if !slow[idleFresh.id] || slow[exhausted.id] {
		t.Errorf("slow pass: idle listed=%v (want true), exhausted listed=%v (want false)", slow[idleFresh.id], slow[exhausted.id])
	}
}

// Per pass over a population of mostly idle trial teams, the fast tick does
// K refreshes instead of N; the numbers are the before/after for one pass.
func TestIntegration_TrialEligibilitySweepFastTickSkipsIdleTeams(t *testing.T) {
	now := time.Now().UTC()
	const idleCount, activeCount = 40, 5
	idle := make([]trialTeam, 0, idleCount)
	for range idleCount {
		tt := seedTrialVerdict(t, true, now)
		tt.usage(t, now.Add(-2*time.Hour), func() *time.Time { v := now.Add(-time.Hour); return &v }())
		idle = append(idle, tt)
	}
	active := make([]trialTeam, 0, activeCount)
	for range activeCount {
		tt := seedTrialVerdict(t, true, now)
		tt.usage(t, now.Add(-time.Minute), nil)
		active = append(active, tt)
	}
	count := func(due map[uuid.UUID]bool, teams []trialTeam) int {
		n := 0
		for _, tt := range teams {
			if due[tt.id] {
				n++
			}
		}
		return n
	}
	fast, slow := dueForRefresh(t, 600), dueForRefresh(t, 0)
	t.Logf("fast tick: %d of %d active and %d of %d idle teams refreshed; slow pass: %d of %d",
		count(fast, active), activeCount, count(fast, idle), idleCount, count(slow, active)+count(slow, idle), idleCount+activeCount)
	if count(fast, active) != activeCount || count(fast, idle) != 0 {
		t.Fatalf("fast tick refreshes %d active (want %d) and %d idle (want 0)", count(fast, active), activeCount, count(fast, idle))
	}
	if count(slow, idle) != idleCount {
		t.Fatalf("slow pass refreshes %d of %d idle teams", count(slow, idle), idleCount)
	}
}

// Through the real sweep, a consuming team's verdict is restamped and an idle
// team's verdict is left as it was.
func TestIntegration_TrialEligibilitySweepLeavesIdleVerdictsAlone(t *testing.T) {
	now := time.Now().UTC()
	running := seedTrialVerdict(t, true, now.Add(-time.Minute))
	running.usage(t, now.Add(-time.Minute), nil)
	idle := seedTrialVerdict(t, true, now.Add(-time.Minute))
	idle.usage(t, now.Add(-2*time.Hour), func() *time.Time { v := now.Add(-time.Hour); return &v }())

	h := api.NewHandlers(&stubVMD{}, testQueries, &config.Config{
		Port: "0", VMDAddress: "localhost:0",
		SystemTeamID: testSystemTeamID.String(), DefaultHostID: testDefaultHostID,
	})
	h.Pool = testPool
	verdictAt := func(team uuid.UUID) time.Time {
		var at time.Time
		if err := testPool.QueryRow(t.Context(), `SELECT updated_at FROM team_trial_eligibility_cache WHERE team_id=$1`, team).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	runningBefore, idleBefore := verdictAt(running.id), verdictAt(idle.id)
	// The shared cursor may start anywhere in the population; a pass per tick
	// reaches every due team within a bounded number of ticks.
	for tick := 0; tick < 40 && !verdictAt(running.id).After(runningBefore); tick++ {
		tickCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		api.RefreshActiveTrialEligibilityForTest(h, tickCtx)
		cancel()
	}
	if !verdictAt(running.id).After(runningBefore) {
		t.Fatal("the sweep never refreshed the consuming team")
	}
	if !verdictAt(idle.id).Equal(idleBefore) {
		t.Fatalf("the sweep restamped an idle team's fresh verdict: %s -> %s", idleBefore, verdictAt(idle.id))
	}
}

// The overdue count behind the sweep's gauge: a consuming team past the fast
// deadline and an idle team past the slow one count, fresh verdicts and a
// settled false verdict do not.
func TestIntegration_TrialEligibilityOverdueCount(t *testing.T) {
	now := time.Now()
	consumingLate := seedTrialVerdict(t, true, now.Add(-10*time.Minute))
	consumingLate.usage(t, now.Add(-5*time.Minute), nil)
	consumingFresh := seedTrialVerdict(t, true, now.Add(-30*time.Second))
	consumingFresh.usage(t, now.Add(-20*time.Second), nil)
	// Idle past the grace, active only moments ago: the fast tick has not
	// missed it yet. An interval already running at the verdict counts from
	// the verdict.
	justActive := seedTrialVerdict(t, true, now.Add(-20*time.Minute))
	justActive.usage(t, now.Add(-30*time.Second), nil)
	activeAtVerdict := seedTrialVerdict(t, true, now.Add(-10*time.Minute))
	activeAtVerdict.usage(t, now.Add(-15*time.Minute), nil)
	seedTrialVerdict(t, true, now.Add(-20*time.Minute)) // idle, past the slow deadline
	seedTrialVerdict(t, true, now.Add(-5*time.Minute))  // idle, within it
	seedTrialVerdict(t, false, now.Add(-time.Hour))     // settled false verdict
	// Due at once, so measured from the grant: no verdict yet, and a false
	// verdict with a newer grant behind it.
	uncached := seedTrialVerdict(t, true, now.Add(-10*time.Minute))
	storageExec(t, `DELETE FROM team_trial_eligibility_cache WHERE team_id=$1`, uncached.id)
	renewed := seedTrialVerdict(t, false, now.Add(-time.Hour))
	storageExec(t, `INSERT INTO team_credit_grant(team_id,reason,amount_usd,remaining_usd,created_at) VALUES($1,'signup trial credit',5,5,$2)`, renewed.id, now.Add(-10*time.Minute))
	// A second renewal moments ago does not reset the overdue clock.
	storageExec(t, `INSERT INTO team_credit_grant(team_id,reason,amount_usd,remaining_usd,created_at) VALUES($1,'signup trial credit',5,5,$2)`, renewed.id, now.Add(-30*time.Second))
	// Uncached but granted moments ago: due, not yet overdue.
	fresh := seedTrialVerdict(t, true, now.Add(-time.Minute))
	storageExec(t, `DELETE FROM team_trial_eligibility_cache WHERE team_id=$1`, fresh.id)
	storageExec(t, `UPDATE team_credit_grant SET created_at=$2 WHERE team_id=$1`, fresh.id, now.Add(-30*time.Second))
	overdue, err := testQueries.CountOverdueTrialEligibility(t.Context(), db.CountOverdueTrialEligibilityParams{ConsumingSeconds: 120, IdleSeconds: 720})
	if err != nil {
		t.Fatal(err)
	}
	if overdue.Consuming != 4 || overdue.Idle != 1 {
		t.Fatalf("overdue consuming=%d idle=%d, want 4 and 1", overdue.Consuming, overdue.Idle)
	}
}
