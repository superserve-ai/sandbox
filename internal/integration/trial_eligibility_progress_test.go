//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// slowEligibilityWrites makes each cache write cost real time, so a page
// outlasts its tick budget the way a large population does in production.
type slowEligibilityWrites struct {
	inner db.DBTX
	delay time.Duration
}

func (s slowEligibilityWrites) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "team_trial_eligibility_cache") {
		time.Sleep(s.delay)
	}
	return s.inner.Exec(ctx, sql, args...)
}
func (s slowEligibilityWrites) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return s.inner.Query(ctx, sql, args...)
}
func (s slowEligibilityWrites) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.inner.QueryRow(ctx, sql, args...)
}

// Dispatch stops at the tick deadline, so a pass that runs out of budget must
// still persist how far it got. Refreshed teams keep their positive balance
// and return in the next page, so a cursor that never advances hands back the
// same teams forever and the rest of the population is never visited.
func TestIntegration_TrialEligibilitySweepProgressesAcrossExpiredTicks(t *testing.T) {
	ctx := context.Background()
	// More teams than the sweep's fan-out width, and a budget that covers two
	// waves of it, so some work lands and the rest is cut off mid-page.
	const teamCount = 30
	seeded := make([]uuid.UUID, 0, teamCount)
	for range teamCount {
		teamID, _ := seedTeamAndKey(t)
		if _, err := testPool.Exec(ctx, `
			INSERT INTO team_credit_grant (team_id, reason, amount_usd, remaining_usd, created_at)
			VALUES ($1, 'signup trial credit', 5, 5, now())`, teamID); err != nil {
			t.Fatalf("seed grant: %v", err)
		}
		seeded = append(seeded, teamID)
	}

	// A full handler: the sweep pauses teams it finds ineligible, and the
	// population it walks includes whatever else the shared database holds.
	h := api.NewHandlers(&stubVMD{}, db.New(slowEligibilityWrites{inner: testPool, delay: 50 * time.Millisecond}), &config.Config{
		Port: "0", VMDAddress: "localhost:0",
		SystemTeamID: testSystemTeamID.String(), DefaultHostID: testDefaultHostID,
	})
	h.Pool = testPool
	refreshed := func(teamID uuid.UUID) bool {
		var exists bool
		_ = testPool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM team_trial_eligibility_cache WHERE team_id = $1)`, teamID).Scan(&exists)
		return exists
	}

	for tick := range teamCount {
		tickCtx, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		api.RefreshActiveTrialEligibilityForTest(h, tickCtx)
		cancel()
		done := 0
		for _, teamID := range seeded {
			if refreshed(teamID) {
				done++
			}
		}
		if done == len(seeded) {
			return
		}
		_ = tick
	}

	missed := 0
	for _, teamID := range seeded {
		if !refreshed(teamID) {
			missed++
		}
	}
	t.Fatalf("%d of %d teams never refreshed after %d expired ticks; the sweep is stuck on one page",
		missed, len(seeded), teamCount)
}

// A sweep that ends exactly on a full page leaves the cursor at its last UUID,
// and the following page comes back empty. Treating that as "no work done"
// strands the cursor at the maximum UUID and nothing is refreshed again.
func TestIntegration_TrialEligibilitySweepRestartsOnAnEmptyPage(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO team_credit_grant (team_id, reason, amount_usd, remaining_usd, created_at)
		VALUES ($1, 'signup trial credit', 5, 5, now())`, teamID); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	h := api.NewHandlers(&stubVMD{}, testQueries, &config.Config{
		Port: "0", VMDAddress: "localhost:0",
		SystemTeamID: testSystemTeamID.String(), DefaultHostID: testDefaultHostID,
	})
	h.Pool = testPool

	// Stand where a full final page would have left the cursor: past every
	// team, so the next page is empty.
	const sweepName = "billing-trial-eligibility"
	// An expired lease parked past every team: the handler wins it on its own
	// and inherits the position a full final page would have left behind.
	maxID := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO sweep_lease (name, locked_by, locked_until, cursor_id)
		VALUES ($1, 'previous-holder', now() - interval '1 second', $2)
		ON CONFLICT (name) DO UPDATE
		SET locked_by = EXCLUDED.locked_by, locked_until = EXCLUDED.locked_until,
		    cursor_id = EXCLUDED.cursor_id`, sweepName, maxID); err != nil {
		t.Fatalf("seed lease: %v", err)
	}

	api.RefreshActiveTrialEligibilityForTest(h, ctx)

	var cursor pgtype.UUID
	if err := testPool.QueryRow(ctx,
		`SELECT cursor_id FROM sweep_lease WHERE name = $1`, sweepName).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor.Valid {
		t.Fatalf("an empty page left the cursor at %s; later sweeps can never reach earlier teams",
			uuid.UUID(cursor.Bytes))
	}

	// And the restarted sweep reaches a team below that UUID.
	api.RefreshActiveTrialEligibilityForTest(h, ctx)
	var refreshed bool
	if err := testPool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM team_trial_eligibility_cache WHERE team_id = $1)`, teamID).Scan(&refreshed); err != nil {
		t.Fatal(err)
	}
	if !refreshed {
		t.Fatal("the sweep did not revisit an earlier team after restarting")
	}
}
