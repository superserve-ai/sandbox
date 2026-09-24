package api

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

const (
	computeSweepInterval = 5 * time.Minute
	computePageSize      = 100
	computePauseWorkers  = 4
)

// RunComputeReconciliation is the sole periodic refresh owner. Refresh keeps
// its cadence even when a large sweep outlives one tick; sweeps never overlap.
func (h *Handlers) RunComputeReconciliation(ctx context.Context, source *abuse.ConfigComputeSource) {
	ticker := time.NewTicker(computeSweepInterval)
	defer ticker.Stop()
	h.runComputeReconciliation(ctx, source, ticker.C, h.reconcileComputeOnce)
}

func (h *Handlers) runComputeReconciliation(ctx context.Context, source *abuse.ConfigComputeSource, ticks <-chan time.Time, sweep func(context.Context, <-chan *abuse.ComputeSnapshot)) {
	done := make(chan struct{}, 1)
	running := false
	var updates chan *abuse.ComputeSnapshot
	initial := true
	for {
		if ctx.Err() != nil {
			return
		}
		if initial {
			initial = false
		} else {
			source.Refresh(ctx)
		}
		if running {
			select {
			case <-done:
				running = false
			default:
			}
		}
		if running {
			select {
			case updates <- source.Snapshot():
			case <-done:
				running = false
			case <-ctx.Done():
				return
			}
		}
		if !running {
			running = true
			updates = make(chan *abuse.ComputeSnapshot)
			go func() {
				defer func() { done <- struct{}{} }()
				sentrylog.RunSafe("compute-reconciliation", func() { sweep(ctx, updates) })
			}()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
	}
}

func recordComputeReconciliation(ctx context.Context, outcome string) {
	if rec, ok := currentTelemetryRecorder().(telemetry.ComputeReconcileRecorder); ok {
		rec.RecordComputeReconciliation(ctx, outcome)
	}
}

// ReconcileComputeOnce discovers each matching live sandbox once in bounded
// pages. Candidates from different teams share a bounded worker pool.
func (h *Handlers) ReconcileComputeOnce(ctx context.Context) {
	h.reconcileComputeOnce(ctx, nil)
}

func (h *Handlers) reconcileComputeOnce(ctx context.Context, updates <-chan *abuse.ComputeSnapshot) {
	recordComputeReconciliation(ctx, "run")
	if h.ComputeRestrictions == nil || h.ComputeRestrictions.Source == nil || h.DB == nil {
		return
	}
	type teamCursor struct {
		id        uuid.UUID
		page      []db.ListComputePauseCandidatesRow
		next      int
		exhausted bool
		through   uuid.UUID
	}
	type teamWork struct {
		team    uuid.UUID
		revisit bool
	}
	cursors := make(map[teamWork]teamCursor)
	retry := make(map[teamWork]bool)
	completed := make(map[teamWork]bool)
	// Retain the consumed prefix per team so refreshes also discover rows
	// inserted behind the cursor by lifecycle operations already underway.
	visited := make(map[uuid.UUID]uuid.UUID)
	var teams []teamWork
	var snapshot *abuse.ComputeSnapshot
	// Preserve existing cursors, but admit new teams ahead of the old backlog
	// whenever a refreshed policy is observed. Only this goroutine owns cursors.
	admitTeams := func(latest *abuse.ComputeSnapshot) {
		if latest == snapshot {
			return
		}
		// Returning teams and observe-to-enforce transitions need fresh cursors.
		if snapshot.Mode() != latest.Mode() {
			clear(cursors)
			clear(retry)
			clear(completed)
			clear(visited)
			teams = nil
		}
		snapshot = latest
		restricted := latest.RestrictedTeams()
		active := make(map[uuid.UUID]bool, len(restricted))
		for _, team := range restricted {
			active[team] = true
		}
		for team := range cursors {
			if !active[team.team] {
				delete(cursors, team)
				delete(retry, team)
				delete(completed, team)
			}
		}
		kept := teams[:0]
		for _, team := range teams {
			if active[team.team] {
				kept = append(kept, team)
			}
		}
		teams = kept
		for team := range visited {
			if !active[team] {
				delete(visited, team)
			}
		}
		var added, revisits []teamWork
		for _, team := range restricted {
			main := teamWork{team: team}
			if _, seen := cursors[main]; !seen || retry[main] || completed[main] {
				if !seen || completed[main] {
					cursors[main] = teamCursor{}
				}
				delete(retry, main)
				delete(completed, main)
				added = append(added, main)
			}
			revisit := teamWork{team: team, revisit: true}
			if through, needed := visited[team]; needed {
				if _, running := cursors[revisit]; !running {
					cursors[revisit] = teamCursor{through: through}
					revisits = append(revisits, revisit)
				} else if retry[revisit] {
					delete(retry, revisit)
					revisits = append(revisits, revisit)
				}
			} else if retry[revisit] {
				delete(retry, revisit)
				revisits = append(revisits, revisit)
			}
		}
		sort.SliceStable(added, func(i, j int) bool { return bytes.Compare(added[i].team[:], added[j].team[:]) < 0 })
		sort.Slice(revisits, func(i, j int) bool { return bytes.Compare(revisits[i].team[:], revisits[j].team[:]) < 0 })
		teams = append(append(added, revisits...), teams...)
	}
	admitTeams(h.ComputeRestrictions.Source.Snapshot())
	sem := make(chan struct{}, computePauseWorkers)
	var wg sync.WaitGroup
	var inFlight sync.Map
	defer wg.Wait()
	for len(teams) > 0 && ctx.Err() == nil {
		select {
		case latest := <-updates:
			admitTeams(latest)
			continue
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		// A slot can be occupied across several refreshes. Discover additions
		// after waiting, before assigning that slot to another old candidate.
		// The scheduler hands off every refresh before publishing the next one.
		// Drain that handoff before reading the latest snapshot or choosing work.
		select {
		case latest := <-updates:
			admitTeams(latest)
		default:
		}
		admitTeams(h.ComputeRestrictions.Source.Snapshot())
		if len(teams) == 0 {
			<-sem
			break
		}
		team := teams[0]
		teams = teams[1:]
		cursor := cursors[team]
		if cursor.next == len(cursor.page) {
			if cursor.exhausted {
				if team.revisit {
					delete(cursors, team)
				} else {
					completed[team] = true
				}
				<-sem
				continue
			}
			qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			page, err := h.DB.ListComputePauseCandidates(qctx, db.ListComputePauseCandidatesParams{
				TeamID: team.team, AfterID: cursor.id, PageLimit: computePageSize,
			})
			cancel()
			if err != nil {
				log.Error().Err(err).Str("team_id", team.team.String()).Msg("compute reconciliation: list candidates failed")
				recordComputeReconciliation(ctx, "failure")
				retry[team] = true
				<-sem
				continue
			}
			if team.revisit {
				for i, candidate := range page {
					if bytes.Compare(candidate.ID[:], cursor.through[:]) > 0 {
						page = page[:i]
						break
					}
				}
			}
			cursor.page = page
			cursor.next = 0
			cursor.exhausted = len(page) < computePageSize
			if len(page) > 0 {
				cursor.id = page[len(page)-1].ID
			}
		}
		if len(cursor.page) == 0 {
			if team.revisit {
				delete(cursors, team)
			} else {
				completed[team] = true
			}
			<-sem
			continue
		}
		candidate := cursor.page[cursor.next]
		cursor.next++
		cursors[team] = cursor
		teams = append(teams, team)
		if previous := visited[team.team]; bytes.Compare(candidate.ID[:], previous[:]) > 0 {
			visited[team.team] = candidate.ID
		}
		if _, busy := inFlight.LoadOrStore(candidate.ID, struct{}{}); busy {
			<-sem
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				inFlight.Delete(candidate.ID)
				<-sem
			}()
			itemCtx, itemCancel := context.WithTimeout(ctx, 2*time.Minute)
			defer itemCancel()
			h.reconcileComputeCandidate(itemCtx, candidate)
		}()
	}
}

func (h *Handlers) reconcileComputeCandidate(ctx context.Context, candidate db.ListComputePauseCandidatesRow) {
	l := log.With().Str("team_id", candidate.TeamID.String()).Str("sandbox_id", candidate.ID.String()).Logger()
	recordComputeReconciliation(ctx, "matched")
	if candidate.Status != db.SandboxStatusActive {
		recordComputeReconciliation(ctx, "deferred_transition")
		return
	}
	// The shared evaluator loads the latest published snapshot at this point.
	decision := h.ComputeRestrictions.Evaluate(candidate.TeamID, abuse.ActionResume)
	if decision.Outcome == "allowed" {
		switch decision.Reason {
		case "trusted":
			recordComputeReconciliation(ctx, "no_op_trusted")
		case "off":
			recordComputeReconciliation(ctx, "no_op_off")
		default:
			recordComputeReconciliation(ctx, "no_op_unrestricted")
		}
		return
	}
	if decision.Outcome == "would_deny" {
		recordComputeReconciliation(ctx, "would_pause")
		l.Info().Str("outcome", "would_pause").Msg("compute reconciliation candidate")
		return
	}
	claimedAt := time.Now()
	op := uuid.New()
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	row, err := h.DB.BeginPause(qctx, db.BeginPauseParams{
		ID: candidate.ID, TeamID: candidate.TeamID,
		PauseOpID: pgtype.UUID{Bytes: op, Valid: true}, LeaseSeconds: pauseLeaseSeconds,
		Trigger: computePauseTrigger(),
	})
	cancel()
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		// A lost reply may follow a committed claim. Its operation identity is
		// sufficient to recover while the original lease remains live.
		if confirmed, ok := h.claimedPause(ctx, candidate.ID, candidate.TeamID, op); ok {
			if time.Since(claimedAt) >= pauseClaimConfirmWindow {
				recordComputeReconciliation(ctx, "pending")
				return
			}
			row, err = confirmed, nil
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		recordComputeReconciliation(ctx, "no_op_state")
		return
	}
	if err != nil {
		l.Error().Err(err).Msg("compute reconciliation: pause claim failed")
		recordComputeReconciliation(ctx, "failure")
		return
	}
	recordComputeReconciliation(ctx, "attempted")
	leaseUntil := leaseDeadline(row.PauseOpLeaseUntil, claimedAt, pauseLeaseSeconds)
	// Use the ordinary dispatch and pending-pause recovery, with no user actor.
	outcome := h.dispatchContainmentPause(ctx, row, leaseUntil, l)
	switch outcome {
	case pauseFinalized:
		// Completion was recorded by the dispatch before this worker returned.
	case pauseDone:
		// The snapshot was taken, but finalization needs pending-pause recovery.
		recordComputeReconciliation(ctx, "pending")
	case pauseUndecided:
		recordComputeReconciliation(ctx, "pending")
	default:
		recordComputeReconciliation(ctx, "failure")
	}
}

func computePauseTrigger() *string {
	trigger := "abuse"
	return &trigger
}
