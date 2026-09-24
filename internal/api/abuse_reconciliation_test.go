package api

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func waitComputeSignal[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reconciliation signal")
		var zero T
		return zero
	}
}

func writeComputePolicy(t *testing.T, path, mode string, teams []uuid.UUID, trusted []uuid.UUID) {
	t.Helper()
	restrictions := make([]string, 0, len(teams))
	for _, team := range teams {
		restrictions = append(restrictions, fmt.Sprintf(`{"subject_type":"team","subject_id":%q,"actions":["create"]}`, team))
	}
	trust := make([]string, 0, len(trusted))
	for _, team := range trusted {
		trust = append(trust, fmt.Sprintf("%q", team))
	}
	content := fmt.Sprintf(`{"mode":%q,"trusted_teams":[%s],"restrictions":[%s]}`, mode, strings.Join(trust, ","), strings.Join(restrictions, ","))
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func computeCandidateRows(team uuid.UUID, ids []uuid.UUID) *scanRows {
	rows := &scanRows{}
	for _, candidateID := range ids {
		id := candidateID
		rows.rows = append(rows.rows, func(dest ...any) error {
			*dest[0].(*uuid.UUID) = team
			*dest[1].(*uuid.UUID) = id
			*dest[2].(*db.SandboxStatus) = db.SandboxStatusActive
			return nil
		})
	}
	return rows
}

func TestContainmentDispatchKeepsFinalizationInWorker(t *testing.T) {
	enteredFinalize := make(chan struct{})
	releaseFinalize := make(chan struct{})
	enteredActivity := make(chan struct{})
	releaseActivity := make(chan struct{})
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		switch {
		case strings.Contains(sql, "-- name: HasLegacySnapshotUnique"):
			return boolRow(true)
		case strings.Contains(sql, "-- name: FinalizePause :one"):
			close(enteredFinalize)
			<-releaseFinalize
			return finalizePauseRow(uuid.New())
		case strings.Contains(sql, "-- name: CreateActivity"):
			close(enteredActivity)
			<-releaseActivity
			return activityRow()
		default:
			return notFoundRow()
		}
	}}
	h := &Handlers{DB: db.New(mock), VMD: &stubVMD{}}
	trigger := "abuse"
	row := db.BeginPauseRow{
		ID: uuid.New(), TeamID: uuid.New(), Name: "example-sandbox",
		PauseOpID:           pgtype.UUID{Bytes: uuid.New(), Valid: true},
		PauseOpLeaseVersion: 1, PauseOpTrigger: &trigger,
	}
	done := make(chan pauseOutcome, 1)
	go func() {
		done <- h.dispatchContainmentPause(context.Background(), row, time.Now().Add(time.Minute), zerolog.Nop())
	}()
	waitComputeSignal(t, enteredFinalize)
	select {
	case <-done:
		t.Fatal("containment worker returned before finalization completed")
	default:
	}
	close(releaseFinalize)
	waitComputeSignal(t, enteredActivity)
	select {
	case <-done:
		t.Fatal("containment worker returned before activity bookkeeping completed")
	default:
	}
	close(releaseActivity)
	if got := waitComputeSignal(t, done); got != pauseFinalized {
		t.Fatalf("dispatch outcome = %v, want pauseFinalized", got)
	}
}

func TestContainmentDispatchUnresolvedHostKeepsPauseClaim(t *testing.T) {
	row := db.BeginPauseRow{
		ID: uuid.New(), TeamID: uuid.New(), HostID: "host-1",
		PauseOpID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PauseOpLeaseVersion: 1,
	}
	var released, reverted bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "-- name: RevertPauseToActive :one") {
				reverted = true
			}
			return notFoundRow()
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: ReleasePauseLease ") {
				released = true
				if args[1] != row.ID || args[2] != row.PauseOpID || args[3] != row.PauseOpLeaseVersion {
					t.Errorf("released lease args = %v, want containment claim", args)
				}
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	h := &Handlers{DB: db.New(mock), Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) {
		return nil, errors.New("host temporarily unavailable")
	}}}

	if got := h.dispatchContainmentPause(context.Background(), row, time.Now().Add(time.Minute), zerolog.Nop()); got != pauseUndecided {
		t.Fatalf("dispatch outcome = %v, want pending pause", got)
	}
	if !released || reverted {
		t.Fatalf("released = %t, reverted = %t; want the claim retained for reconciliation", released, reverted)
	}
}

func TestComputeSchedulerRefreshesBlockedSweepWithoutOverlapAndCancels(t *testing.T) {
	team := uuid.New()
	path := filepath.Join(t.TempDir(), "compute.json")
	writeComputePolicy(t, path, "enforce", []uuid.UUID{team}, nil)
	refreshes := make(chan abuse.ComputeMode, 4)
	var source *abuse.ConfigComputeSource
	source = abuse.NewConfigComputeSource(path, nil, func(_ context.Context, _ string) {
		refreshes <- (&abuse.ComputeEvaluator{Source: source}).Evaluate(team, abuse.ActionResume).Mode
	})
	source.Refresh(context.Background())
	if got := waitComputeSignal(t, refreshes); got != abuse.ModeEnforce {
		t.Fatalf("startup mode = %s", got)
	}
	ticks := make(chan time.Time)
	started := make(chan int, 2)
	sweepModes := make(chan abuse.ComputeMode, 2)
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runnerDone := make(chan struct{})
	var mu sync.Mutex
	active, calls, peak := 0, 0, 0
	h := &Handlers{}
	go func() {
		defer close(runnerDone)
		h.runComputeReconciliation(ctx, source, ticks, func(ctx context.Context, updates <-chan *abuse.ComputeSnapshot) {
			mu.Lock()
			calls++
			call := calls
			active++
			if active > peak {
				peak = active
			}
			mu.Unlock()
			sweepModes <- (&abuse.ComputeEvaluator{Source: source}).Evaluate(team, abuse.ActionResume).Mode
			started <- call
			if call == 1 {
			waitFirst:
				for {
					select {
					case <-firstDone:
						break waitFirst
					case <-updates:
					case <-ctx.Done():
						break waitFirst
					}
				}
			} else {
				for ctx.Err() == nil {
					select {
					case <-updates:
					case <-ctx.Done():
					}
				}
			}
			mu.Lock()
			active--
			mu.Unlock()
			if call == 2 {
				close(secondDone)
			}
		})
	}()
	if got := waitComputeSignal(t, started); got != 1 {
		t.Fatalf("first sweep = %d", got)
	}
	if got := waitComputeSignal(t, sweepModes); got != abuse.ModeEnforce {
		t.Fatalf("startup sweep mode = %s, want enforce", got)
	}
	select {
	case <-refreshes:
		t.Fatal("scheduler refreshed the startup snapshot before the first tick")
	default:
	}
	writeComputePolicy(t, path, "off", nil, nil)
	for i := 0; i < 2; i++ {
		ticks <- time.Time{}
		if got := waitComputeSignal(t, refreshes); got != abuse.ModeOff {
			t.Fatalf("refreshed mode = %s", got)
		}
	}
	mu.Lock()
	if calls != 1 || peak != 1 {
		t.Fatalf("blocked sweep: calls=%d peak=%d", calls, peak)
	}
	mu.Unlock()
	writeComputePolicy(t, path, "observe", []uuid.UUID{team}, nil)
	close(firstDone)
	// The next tick starts a new pass after the first sweep has exited.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ticks <- time.Time{}:
		case <-deadline:
			t.Fatal("next sweep did not start")
		}
		if got := waitComputeSignal(t, refreshes); got != abuse.ModeObserve {
			t.Fatalf("next refreshed mode = %s, want observe", got)
		}
		select {
		case call := <-started:
			if call != 2 {
				t.Fatalf("next sweep = %d", call)
			}
			if got := waitComputeSignal(t, sweepModes); got != abuse.ModeObserve {
				t.Fatalf("next sweep mode = %s, want refreshed observe", got)
			}
			goto cancelSweep
		default:
		}
	}
cancelSweep:
	cancel()
	waitComputeSignal(t, runnerDone)
	waitComputeSignal(t, secondDone)
	mu.Lock()
	defer mu.Unlock()
	if peak != 1 || calls != 2 {
		t.Fatalf("sweeps: calls=%d peak=%d", calls, peak)
	}
}

func TestComputeCandidateRechecksPublishedPolicyBeforeClaim(t *testing.T) {
	team, id := uuid.New(), uuid.New()
	path := filepath.Join(t.TempDir(), "compute.json")
	source := abuse.NewConfigComputeSource(path, nil, nil)
	rec := &computeReconcileCapture{Recorder: telemetry.NewNoopRecorder(), outcomes: map[string]int{}}
	previous := currentTelemetryRecorder()
	SetTelemetryRecorder(rec)
	t.Cleanup(func() { SetTelemetryRecorder(previous) })
	write := func(mode string, trusted bool) {
		t.Helper()
		trust := "[]"
		if trusted {
			trust = fmt.Sprintf(`[%q]`, team)
		}
		content := fmt.Sprintf(`{"mode":%q,"trusted_teams":%s,"restrictions":[{"subject_type":"team","subject_id":%q,"actions":["create"]}]}`, mode, trust, team)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		source.Refresh(context.Background())
	}
	claims := 0
	h := &Handlers{
		ComputeRestrictions: &abuse.ComputeEvaluator{Source: source},
		DB: db.New(&mockDBTX{queryRowFn: func(context.Context, string, ...any) pgx.Row {
			claims++
			return notFoundRow()
		}}),
	}
	candidate := db.ListComputePauseCandidatesRow{TeamID: team, ID: id, Status: db.SandboxStatusActive}
	write("enforce", false)
	// Discovery may have happened under enforce, while a newer publication
	// must still prevent this target from being claimed.
	for _, policy := range []struct {
		mode    string
		trusted bool
	}{
		{"enforce", true}, {"observe", false}, {"off", false},
	} {
		write(policy.mode, policy.trusted)
		h.reconcileComputeCandidate(context.Background(), candidate)
	}
	writeComputePolicy(t, path, "enforce", nil, nil)
	source.Refresh(context.Background())
	h.reconcileComputeCandidate(context.Background(), candidate)
	write("enforce", false)
	h.reconcileComputeCandidate(context.Background(), db.ListComputePauseCandidatesRow{TeamID: team, ID: id, Status: db.SandboxStatusResuming})
	if claims != 0 {
		t.Fatalf("non-enforcing policy or transition made %d claims", claims)
	}
	h.reconcileComputeCandidate(context.Background(), candidate)
	if claims != 1 {
		t.Fatalf("enforced active candidate made %d claims, want one", claims)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	want := map[string]int{
		"matched": 6, "no_op_trusted": 1, "would_pause": 1,
		"no_op_off": 1, "no_op_unrestricted": 1,
		"deferred_transition": 1, "no_op_state": 1,
	}
	if !maps.Equal(rec.outcomes, want) {
		t.Fatalf("reconciliation outcomes = %v, want bounded outcomes %v", rec.outcomes, want)
	}
}

func TestComputeSweepPagesAllCandidatesWithoutClaimsInObserve(t *testing.T) {
	team := uuid.New()
	path := filepath.Join(t.TempDir(), "compute.json")
	content := fmt.Sprintf(`{"mode":"observe","restrictions":[{"subject_type":"team","subject_id":%q,"actions":["resume"]}]}`, team)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	source := abuse.NewConfigComputeSource(path, nil, nil)
	source.Refresh(context.Background())
	ids := make([]uuid.UUID, 101)
	for i := range ids {
		ids[i] = uuid.New()
	}
	// The query's keyset ordering is exercised with a fixed increasing set.
	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			if ids[j].String() < ids[i].String() {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	pages, scanned, claims := 0, 0, 0
	mock := &mockDBTX{
		queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
			pages++
			if args[2].(int32) != computePageSize {
				t.Fatal("unbounded candidate page")
			}
			after := args[1].(uuid.UUID)
			rows := &scanRows{}
			for _, id := range ids {
				if id.String() <= after.String() {
					continue
				}
				if len(rows.rows) == computePageSize {
					break
				}
				id := id
				rows.rows = append(rows.rows, func(dest ...any) error {
					scanned++
					*dest[0].(*uuid.UUID) = team
					*dest[1].(*uuid.UUID) = id
					*dest[2].(*db.SandboxStatus) = db.SandboxStatusActive
					return nil
				})
			}
			return rows, nil
		},
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			claims++
			return notFoundRow()
		},
	}
	h := &Handlers{DB: db.New(mock), ComputeRestrictions: &abuse.ComputeEvaluator{Source: source}}
	h.ReconcileComputeOnce(context.Background())
	if pages != 2 || scanned != 101 || claims != 0 {
		t.Fatalf("pages=%d scanned=%d claims=%d", pages, scanned, claims)
	}
}

func TestComputeSweepDiscoversCanonicalOwnerTeamsOnceAndSkipsTrustedTeam(t *testing.T) {
	owner, otherOwner := uuid.New(), uuid.New()
	teamA, teamB, trustedTeam := uuid.UUID{15: 1}, uuid.UUID{15: 2}, uuid.UUID{15: 3}
	ids := map[uuid.UUID]uuid.UUID{
		teamA: uuid.New(), teamB: uuid.New(), trustedTeam: uuid.New(),
	}
	path := filepath.Join(t.TempDir(), "compute.json")
	content := fmt.Sprintf(`{"mode":"enforce","trusted_teams":[%q],"restrictions":[{"subject_type":"user","subject_id":%q,"actions":["create"]},{"subject_type":"team","subject_id":%q,"actions":["resume"]},{"subject_type":"team","subject_id":%q,"actions":["create"]}]}`, trustedTeam, owner, teamA, trustedTeam)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	ownerLoads := 0
	source := abuse.NewConfigComputeSource(path, func(_ context.Context, users []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
		ownerLoads++
		if len(users) != 1 || users[0] != owner {
			t.Fatalf("owner lookup users = %v, want only restricted owner", users)
		}
		return map[uuid.UUID][]uuid.UUID{
			teamA:       {otherOwner, owner},
			teamB:       {owner},
			trustedTeam: {owner},
		}, nil
	}, nil)
	source.Refresh(context.Background())

	queries := map[uuid.UUID]int{}
	claims := map[uuid.UUID]int{}
	var mu sync.Mutex
	mock := &mockDBTX{
		queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
			team := args[0].(uuid.UUID)
			queries[team]++
			return computeCandidateRows(team, []uuid.UUID{ids[team]}), nil
		},
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: BeginPause :one") {
				t.Errorf("unexpected query: %s", sql)
				return notFoundRow()
			}
			mu.Lock()
			claims[args[4].(uuid.UUID)]++
			mu.Unlock()
			return notFoundRow()
		},
	}
	h := &Handlers{DB: db.New(mock), ComputeRestrictions: &abuse.ComputeEvaluator{Source: source}}
	h.ReconcileComputeOnce(context.Background())

	if ownerLoads != 1 || len(queries) != 2 || queries[teamA] != 1 || queries[teamB] != 1 || queries[trustedTeam] != 0 {
		t.Fatalf("owner loads=%d candidate queries=%v, want each untrusted owner team once", ownerLoads, queries)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(claims) != 2 || claims[ids[teamA]] != 1 || claims[ids[teamB]] != 1 || claims[ids[trustedTeam]] != 0 {
		t.Fatalf("claims=%v, want each untrusted owner team's candidate once", claims)
	}
}

func TestComputeSweepContinuesAfterCandidateQueryFailure(t *testing.T) {
	failedTeam, laterTeam := uuid.UUID{15: 1}, uuid.UUID{15: 2}
	laterSandbox := uuid.New()
	path := filepath.Join(t.TempDir(), "compute.json")
	writeComputePolicy(t, path, "enforce", []uuid.UUID{failedTeam, laterTeam}, nil)
	source := abuse.NewConfigComputeSource(path, nil, nil)
	source.Refresh(context.Background())

	queries := map[uuid.UUID]int{}
	claims := 0
	mock := &mockDBTX{
		queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
			team := args[0].(uuid.UUID)
			queries[team]++
			if team == failedTeam {
				return nil, errors.New("candidate query failed")
			}
			return computeCandidateRows(laterTeam, []uuid.UUID{laterSandbox}), nil
		},
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: BeginPause :one") || args[4] != laterSandbox || args[5] != laterTeam {
				t.Errorf("unexpected pause claim: query=%s args=%v", sql, args)
			}
			claims++
			return notFoundRow()
		},
	}
	h := &Handlers{DB: db.New(mock), ComputeRestrictions: &abuse.ComputeEvaluator{Source: source}}
	h.ReconcileComputeOnce(context.Background())

	if queries[failedTeam] != 1 || queries[laterTeam] != 1 || claims != 1 {
		t.Fatalf("candidate queries=%v claims=%d, want both teams queried and later sandbox claimed once", queries, claims)
	}
}

type computeReconcileCapture struct {
	telemetry.Recorder
	mu       sync.Mutex
	outcomes map[string]int
}

func (r *computeReconcileCapture) RecordComputeReconciliation(_ context.Context, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outcomes[outcome]++
}

func TestComputeSweepDispatchesClaimsAndKeepsPendingSeparateFromCompleted(t *testing.T) {
	failedTeam, targetTeam := uuid.UUID{15: 1}, uuid.UUID{15: 2}
	failed, completed, pending := uuid.New(), uuid.New(), uuid.New()
	path := filepath.Join(t.TempDir(), "compute.json")
	writeComputePolicy(t, path, "enforce", []uuid.UUID{failedTeam, targetTeam}, nil)
	source := abuse.NewConfigComputeSource(path, nil, nil)
	source.Refresh(context.Background())

	rec := &computeReconcileCapture{Recorder: telemetry.NewNoopRecorder(), outcomes: map[string]int{}}
	previous := currentTelemetryRecorder()
	SetTelemetryRecorder(rec)
	t.Cleanup(func() { SetTelemetryRecorder(previous) })

	var mu sync.Mutex
	claims := map[uuid.UUID]int{}
	dispatches := map[uuid.UUID]int{}
	finalized := map[uuid.UUID]int{}
	activities := map[uuid.UUID]int{}
	released := map[uuid.UUID]int{}
	mock := &mockDBTX{
		queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
			if args[2].(int32) != computePageSize {
				t.Errorf("page limit = %v", args[2])
			}
			if args[0] == failedTeam {
				return computeCandidateRows(failedTeam, []uuid.UUID{failed}), nil
			}
			return computeCandidateRows(targetTeam, []uuid.UUID{completed, pending}), nil
		},
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: BeginPause :one"):
				id := args[4].(uuid.UUID)
				trigger := args[2].(*string)
				actor := args[3].(pgtype.UUID)
				if trigger == nil || *trigger != "abuse" || actor.Valid {
					t.Errorf("claim trigger=%v actor=%v, want abuse and system actor", trigger, actor)
				}
				mu.Lock()
				claims[id]++
				mu.Unlock()
				if id == failed {
					return errorRow(errors.New("claim failed"))
				}
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = id
					*dest[1].(*uuid.UUID) = targetTeam
					*dest[2].(*string) = "example-sandbox"
					*dest[3].(*db.SandboxStatus) = db.SandboxStatusPausing
					*dest[30].(*pgtype.UUID) = args[0].(pgtype.UUID)
					*dest[33].(*int64) = 1
					*dest[35].(**string) = trigger
					*dest[36].(*pgtype.UUID) = actor
					return nil
				}}
			case strings.Contains(sql, "-- name: FinalizePause :one"):
				id := args[0].(uuid.UUID)
				mu.Lock()
				finalized[id]++
				mu.Unlock()
				if id != completed || args[7] != "abuse" {
					t.Errorf("unexpected finalization: id=%s trigger=%v", id, args[7])
				}
				return finalizePauseRow(uuid.New())
			case strings.Contains(sql, "-- name: CreateActivity :one"):
				id := uuid.UUID(args[0].(pgtype.UUID).Bytes)
				if args[6].(pgtype.UUID).Valid || args[8] != "abuse_paused" {
					t.Errorf("activity actor=%v action=%v", args[6], args[8])
				}
				mu.Lock()
				activities[id]++
				mu.Unlock()
				return activityRow()
			default:
				return notFoundRow()
			}
		},
		execFn: func(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
			if !strings.Contains(sql, "-- name: ReleasePauseLease :execrows") {
				t.Errorf("unexpected Exec: %s", sql)
			}
			mu.Lock()
			released[args[1].(uuid.UUID)]++
			mu.Unlock()
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	vmd := &stubVMD{pauseFn: func(_ context.Context, id, _ string) (string, string, error) {
		parsed, err := uuid.Parse(id)
		if err != nil {
			t.Errorf("pause sandbox ID %q: %v", id, err)
		}
		mu.Lock()
		dispatches[parsed]++
		mu.Unlock()
		if parsed == pending {
			return "", "", errors.New("host response uncertain")
		}
		return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
	}}
	h := &Handlers{DB: db.New(mock), VMD: vmd, ComputeRestrictions: &abuse.ComputeEvaluator{Source: source}}
	h.ReconcileComputeOnce(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if claims[failed] != 1 || claims[completed] != 1 || claims[pending] != 1 {
		t.Fatalf("claims = %v, want one per candidate after the first failure", claims)
	}
	if dispatches[failed] != 0 || dispatches[completed] != 1 || dispatches[pending] == 0 {
		t.Fatalf("dispatches = %v", dispatches)
	}
	if finalized[completed] != 1 || finalized[pending] != 0 || activities[completed] != 1 || activities[pending] != 0 || released[pending] != 1 {
		t.Fatalf("finalized=%v activities=%v released=%v", finalized, activities, released)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.outcomes["attempted"] != 2 || rec.outcomes["completed"] != 1 || rec.outcomes["pending"] != 1 || rec.outcomes["failure"] != 1 {
		t.Fatalf("reconciliation outcomes = %v", rec.outcomes)
	}
}

func TestComputeSweepEnforceContinuesAcrossSlowAndFailedCandidatesAndPages(t *testing.T) {
	teamA, teamB := uuid.UUID{15: 1}, uuid.UUID{15: 2}
	path := filepath.Join(t.TempDir(), "compute.json")
	writeComputePolicy(t, path, "enforce", []uuid.UUID{teamA, teamB}, nil)
	source := abuse.NewConfigComputeSource(path, nil, nil)
	source.Refresh(context.Background())
	ids := make([]uuid.UUID, 101)
	for i := range ids {
		ids[i] = uuid.UUID{14: 1, 15: byte(i + 1)}
	}
	other := uuid.UUID{14: 2, 15: 1}
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	laterClaimed := make(chan struct{})
	otherClaimed := make(chan struct{})
	var mu sync.Mutex
	claims := map[uuid.UUID]int{}
	pages := map[uuid.UUID]int{}
	mock := &mockDBTX{
		queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
			team, after, limit := args[0].(uuid.UUID), args[1].(uuid.UUID), args[2].(int32)
			if limit != computePageSize {
				t.Errorf("page limit = %d", limit)
			}
			mu.Lock()
			pages[team]++
			mu.Unlock()
			teamIDs := ids
			if team == teamB {
				teamIDs = []uuid.UUID{other}
			}
			page := make([]uuid.UUID, 0, computePageSize)
			for _, id := range teamIDs {
				if strings.Compare(id.String(), after.String()) > 0 && len(page) < computePageSize {
					page = append(page, id)
				}
			}
			return computeCandidateRows(team, page), nil
		},
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: BeginPause :one") {
				return notFoundRow()
			}
			id := args[4].(uuid.UUID)
			mu.Lock()
			claims[id]++
			mu.Unlock()
			if id == ids[0] {
				close(slowStarted)
				select {
				case <-releaseSlow:
				case <-ctx.Done():
				}
			}
			if id == ids[99] {
				close(laterClaimed)
			}
			if id == other {
				close(otherClaimed)
			}
			if id == ids[1] {
				return errorRow(errors.New("claim failed"))
			}
			return notFoundRow()
		},
	}
	h := &Handlers{DB: db.New(mock), ComputeRestrictions: &abuse.ComputeEvaluator{Source: source}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); h.ReconcileComputeOnce(ctx) }()
	waitComputeSignal(t, slowStarted)
	// The second team must be reached while the first team's page is still busy.
	waitComputeSignal(t, otherClaimed)
	close(releaseSlow)
	waitComputeSignal(t, laterClaimed)
	waitComputeSignal(t, done)
	mu.Lock()
	defer mu.Unlock()
	if len(claims) != 102 || pages[teamA] != 2 || pages[teamB] != 1 {
		t.Fatalf("claims=%d pages=%v, want all candidates in two teams and three pages", len(claims), pages)
	}
	for id, count := range claims {
		if count != 1 {
			t.Fatalf("candidate %s claimed %d times", id, count)
		}
	}
}

func TestComputeSweepRechecksPolicyForQueuedCandidates(t *testing.T) {
	team := uuid.New()
	path := filepath.Join(t.TempDir(), "compute.json")
	writeComputePolicy(t, path, "enforce", []uuid.UUID{team}, nil)
	source := abuse.NewConfigComputeSource(path, nil, nil)
	source.Refresh(context.Background())
	ids := make([]uuid.UUID, 8)
	for i := range ids {
		ids[i] = uuid.UUID{15: byte(i + 1)}
	}
	claimed := make(chan uuid.UUID, computePauseWorkers)
	release := make(chan struct{})
	var mu sync.Mutex
	claims := map[uuid.UUID]bool{}
	mock := &mockDBTX{
		queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
			if args[2].(int32) != computePageSize {
				t.Errorf("page limit = %v", args[2])
			}

			return computeCandidateRows(team, ids), nil
		},
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: BeginPause :one") {
				return notFoundRow()
			}
			id := args[4].(uuid.UUID)
			mu.Lock()
			claims[id] = true
			mu.Unlock()
			claimed <- id
			select {
			case <-release:
			case <-ctx.Done():
			}
			return notFoundRow()
		},
	}
	h := &Handlers{DB: db.New(mock), ComputeRestrictions: &abuse.ComputeEvaluator{Source: source}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); h.ReconcileComputeOnce(ctx) }()
	for i := 0; i < computePauseWorkers; i++ {
		waitComputeSignal(t, claimed)
	}
	writeComputePolicy(t, path, "enforce", []uuid.UUID{team}, []uuid.UUID{team})
	source.Refresh(ctx)
	close(release)
	waitComputeSignal(t, done)
	mu.Lock()
	defer mu.Unlock()
	if len(claims) != computePauseWorkers {
		t.Fatalf("claims after trust publication = %d, want only %d in-flight claims", len(claims), computePauseWorkers)
	}
}

func TestComputeSchedulerAdmitsNewTeamBeforeOldBacklogDrains(t *testing.T) {
	testComputeSchedulerTeamAdmission(t, "new")
}

func TestComputeSchedulerReadmitsReturningTeamBeforeOldBacklogDrains(t *testing.T) {
	testComputeSchedulerTeamAdmission(t, "returning")
}

func TestComputeSchedulerRetriesFailedTeamBeforeOldBacklogDrains(t *testing.T) {
	testComputeSchedulerTeamAdmission(t, "query failure")
}

func TestComputeSchedulerRevisitsDeferredTeamBeforeOldBacklogDrains(t *testing.T) {
	testComputeSchedulerTeamAdmission(t, "deferred")
}

func TestComputeSchedulerRevisitsDeferredRowBeforeSameTeamBacklogDrains(t *testing.T) {
	testComputeSchedulerTeamAdmission(t, "same team deferred")
}

func TestComputeSchedulerDiscoversLateInsertBehindSameTeamCursor(t *testing.T) {
	testComputeSchedulerTeamAdmission(t, "late insert")
}

func testComputeSchedulerTeamAdmission(t *testing.T, scenario string) {
	sameTeam := scenario == "same team deferred" || scenario == "late insert"
	returning, queryFailure := scenario == "returning", scenario == "query failure"
	teamA, teamB := uuid.UUID{15: 1}, uuid.UUID{15: 2}
	path := filepath.Join(t.TempDir(), "compute.json")
	initialTeams := []uuid.UUID{teamA}
	if scenario != "new" && !sameTeam {
		initialTeams = append(initialTeams, teamB)
	}
	writeComputePolicy(t, path, "enforce", initialTeams, nil)
	refreshed := make(chan struct{}, 4)
	source := abuse.NewConfigComputeSource(path, nil, func(context.Context, string) { refreshed <- struct{}{} })
	source.Refresh(context.Background())
	waitComputeSignal(t, refreshed)
	started := make(chan uuid.UUID, 20)
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var firstB sync.Once
	var firstQueryB sync.Once
	var firstQueryA sync.Once
	mock := &mockDBTX{
		queryFn: func(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
			team := args[0].(uuid.UUID)
			if (queryFailure || scenario == "deferred") && team == teamB {
				fail := false
				firstQueryB.Do(func() { fail = true })
				if fail {
					if queryFailure {
						return nil, errors.New("temporary candidate query failure")
					}
					return &scanRows{rows: []func(...any) error{func(dest ...any) error {
						*dest[0].(*uuid.UUID) = teamB
						*dest[1].(*uuid.UUID) = uuid.UUID{14: 2, 15: 1}
						*dest[2].(*db.SandboxStatus) = db.SandboxStatusResuming
						return nil
					}}}, nil
				}
			}
			ids := []uuid.UUID{{14: 2, 15: 1}}
			if team == teamA {
				ids = nil
				for i := byte(1); i <= 12; i++ {
					ids = append(ids, uuid.UUID{14: 1, 15: i})
				}
			}
			if sameTeam && team == teamA {
				first := false
				firstQueryA.Do(func() { first = true })
				rows := computeCandidateRows(team, ids)
				if first && scenario == "late insert" {
					rows.rows = rows.rows[1:]
				} else if first {
					rows.rows[0] = func(dest ...any) error {
						*dest[0].(*uuid.UUID) = teamA
						*dest[1].(*uuid.UUID) = ids[0]
						*dest[2].(*db.SandboxStatus) = db.SandboxStatusResuming
						return nil
					}
				}
				return rows, nil
			}
			return computeCandidateRows(team, ids), nil
		},
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			if !strings.Contains(sql, "-- name: BeginPause :one") {
				return notFoundRow()
			}
			id := args[4].(uuid.UUID)
			started <- id
			if returning && id[14] == 2 {
				first := false
				firstB.Do(func() { first = true })
				if first {
					return notFoundRow()
				}
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return notFoundRow()
		},
	}
	h := &Handlers{DB: db.New(mock), ComputeRestrictions: &abuse.ComputeEvaluator{Source: source}}
	ticks := make(chan time.Time)
	done := make(chan struct{})
	sweepDone := make(chan struct{}, 2)
	go func() {
		defer close(done)
		h.runComputeReconciliation(ctx, source, ticks, func(ctx context.Context, updates <-chan *abuse.ComputeSnapshot) {
			h.reconcileComputeOnce(ctx, updates)
			sweepDone <- struct{}{}
		})
	}()
	for occupied := 0; occupied < computePauseWorkers; {
		if id := waitComputeSignal(t, started); id[14] == 1 {
			occupied++
		}
	}
	if returning {
		writeComputePolicy(t, path, "enforce", []uuid.UUID{teamA}, nil)
		ticks <- time.Time{}
		waitComputeSignal(t, refreshed)
	}
	if !sameTeam {
		writeComputePolicy(t, path, "enforce", []uuid.UUID{teamA, teamB}, nil)
	}
	ticks <- time.Time{}
	waitComputeSignal(t, refreshed)
	// Free exactly one worker. The refreshed team must take that slot, while
	// three old candidates and eight queued old candidates are still blocked.
	release <- struct{}{}
	id := waitComputeSignal(t, started)
	if sameTeam {
		if id != (uuid.UUID{14: 1, 15: 1}) {
			t.Fatalf("next claim %s, want the early deferred row", id)
		}
		// The revisit lane must preserve normal forward progress as well.
		release <- struct{}{}
		if next := waitComputeSignal(t, started); next != (uuid.UUID{14: 1, 15: 6}) {
			t.Fatalf("next forward claim %s, want sixth candidate", next)
		}
	} else if id[14] != 2 {
		t.Fatalf("next claim %s belongs to the old backlog, want newly restricted team", id)
	}
	cancel()
	waitComputeSignal(t, done)
	waitComputeSignal(t, sweepDone)
}
