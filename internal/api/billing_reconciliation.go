package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	billingPauseWorkers                   = 10
	billingPauseCap                 int32 = 1000 // per pass; a follow-up pass picks up the rest
	billingTrialEligibilityPageSize int32 = 256
	// Long enough that a slow page cannot let a second replica in behind the
	// holder, short enough that a crashed one is replaced within a few ticks.
	trialEligibilityLeaseSeconds = 120
	trialEligibilitySweepName    = "billing-trial-eligibility"
)

func (h *Handlers) refreshActiveTrialEligibility(ctx context.Context) {
	h.scheduleTrialCreditWarningDiscovery(ctx)
	// One replica refreshes per tick. Run by every replica this fans out
	// once each, so the population is swept N times over with nothing
	// shared, and a page position held in process memory would restart a
	// successor at the UUID prefix. The lease elects the runner and carries
	// the cursor it advances, so a handover resumes mid-population.
	afterID, err := h.DB.ClaimSweepLease(ctx, db.ClaimSweepLeaseParams{
		Name: trialEligibilitySweepName, LockedBy: db.SweepHolderID(),
		LeaseSeconds: int32(trialEligibilityLeaseSeconds),
	})
	if err != nil {
		// No row means another replica holds the lease: this tick is theirs.
		if !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Msg("billing: claim trial eligibility sweep lease failed")
			return
		}
		h.reconcileBillingPauses(ctx)
		return
	}
	teams, err := h.DB.ListTeamsWithTrialCredits(ctx, db.ListTeamsWithTrialCreditsParams{AfterTeamID: afterID, BatchLimit: billingTrialEligibilityPageSize})
	if err != nil {
		log.Error().Err(err).Msg("billing: list active trial teams failed")
		return
	}
	next, advance := processSweepPage(ctx, teams, billingTrialEligibilityPageSize, func(teamID uuid.UUID) bool {
		if err := h.DB.RefreshTeamTrialEligibility(ctx, teamID); err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing: refresh trial eligibility failed")
			return false
		}
		h.pauseBillingTeam(ctx, teamID)
		return true
	})
	if advance {
		h.advanceSweepCursor(ctx, trialEligibilitySweepName, next)
	}
	h.reconcileBillingPauses(ctx)
}

func (h *Handlers) reconcileBillingPauses(ctx context.Context) {
	var after *uuid.UUID
	for {
		var afterID pgtype.UUID
		if after != nil {
			afterID = pgtype.UUID{Bytes: *after, Valid: true}
		}
		teams, err := h.DB.ListTeamsWithBillingPauseDue(ctx, db.ListTeamsWithBillingPauseDueParams{AfterTeamID: afterID, BatchLimit: 1000})
		if err != nil {
			log.Error().Err(err).Msg("billing: list teams with billing pauses due failed")
			return
		}
		if len(teams) == 0 {
			return
		}
		dispatchBounded(ctx, teams, 10, func(teamID uuid.UUID) {
			h.pauseBillingTeam(ctx, teamID)
		})
		last := teams[len(teams)-1]
		after = &last
		if len(teams) < 1000 {
			return
		}
	}
}

func (h *Handlers) reconcileActivatedSandbox(ctx context.Context, teamID uuid.UUID) {
	// Only the eligibility READ is coalesced: it is per-team, so a concurrent
	// create burst shares one fresh look (never the request-path cache; this
	// is the safety net) instead of one per sandbox. The pause claim stays
	// with each caller — inside the flight, a sandbox activating after the
	// leader's claim snapshot would join the flight and never be claimed
	// until the next sweep. Each caller runs after its own activation
	// committed, so its own claim always covers its own sandbox; concurrent
	// claims partition safely (FOR UPDATE SKIP LOCKED), and the ineligible
	// case is rare enough that their cost is irrelevant.
	verdict, err, _ := h.activationRecheck.Do(teamID.String(), func() (interface{}, error) {
		return h.DB.IsTeamSandboxBillingEligible(ctx, teamID)
	})
	if err != nil {
		// No per-team retry: reads fail here exactly when the DB is already
		// struggling, and high create churn would bank one untracked retry
		// per team, all firing together 30s later. The 30s sweep
		// re-covers every team on the same timescale a retry would, with
		// bounded, paced concurrency.
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing: activation eligibility check failed; 30s sweep will re-cover")
		return
	}
	if !verdict.(bool) {
		h.pauseBillingTeam(ctx, teamID)
	}
}

func (h *Handlers) pauseBillingTeam(ctx context.Context, teamID uuid.UUID) {
	// Claims stop with ctx; a pause already in flight finishes on its own
	// detached budget.
	cleanupCtx := context.WithoutCancel(ctx)
	claimed, err := claimBatch(ctx, billingPauseWorkers, billingPauseCap, func(ctx context.Context, limit int32) ([]uuid.UUID, error) {
		return h.DB.ListBillingPauseSandboxes(ctx, db.ListBillingPauseSandboxesParams{TeamID: teamID, Limit: limit})
	}, func(ctx context.Context, id uuid.UUID) (db.ClaimBillingPauseSandboxRow, error) {
		row, err := h.DB.ClaimBillingPauseSandbox(ctx, db.ClaimBillingPauseSandboxParams{ID: id, TeamID: teamID, LeaseSeconds: pauseLeaseSeconds})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			log.Error().Err(err).Str("sandbox_id", id.String()).Msg("billing: claim sandbox for billing pause failed")
		}
		return row, err
	}, func(sbx db.ClaimBillingPauseSandboxRow, claimedAt time.Time) {
		itemCtx, itemCancel := context.WithTimeout(cleanupCtx, 2*time.Minute)
		defer itemCancel()
		h.pauseForBilling(itemCtx, sbx, claimedAt, log.Logger)
	})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing: list sandboxes for billing pause failed")
		h.retryBillingEligibilityReconciliation(teamID)
		return
	}
	if claimed == 0 {
		if _, err := h.DB.SettleTeamPauseTargets(ctx, teamID); err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing: settle team pause targets failed")
		}
		return
	}
	if int32(claimed) >= billingPauseCap {
		log.Warn().Str("team_id", teamID.String()).Msg("billing: reconciliation batch limit reached")
	}
	// A follow-up pass re-covers rows that became ineligible meanwhile or
	// were left for the reconciler, rather than assuming this one was enough.
	h.retryBillingEligibilityReconciliation(teamID)
}

func (h *Handlers) retryBillingEligibilityReconciliation(teamID uuid.UUID) {
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		<-timer.C
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		h.pauseBillingTeam(ctx, teamID)
	}()
}

func (h *Handlers) scheduleBillingEligibilityReconciliation(ctx context.Context, event stripeEventEnvelope) {
	if h.DB == nil {
		return
	}
	var obj stripeSubscriptionObject
	if event.Type == "customer.subscription.deleted" {
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return
		}
		obj.Status = "canceled"
	} else if event.Type == "customer.subscription.updated" || event.Type == "customer.subscription.created" || event.Type == "customer.subscription.paused" || event.Type == "customer.subscription.resumed" {
		if err := json.Unmarshal(event.Data.Object, &obj); err != nil {
			return
		}
		if !strings.EqualFold(obj.Status, "unpaid") && !strings.EqualFold(obj.Status, "canceled") && !strings.EqualFold(obj.Status, "paused") {
			return
		}
	} else {
		return
	}
	if obj.Customer == "" {
		return
	}

	baseCtx := context.WithoutCancel(ctx)
	h.asyncBookkeeping("billing-ineligible-reconcile", func() {
		qctx, cancel := context.WithTimeout(baseCtx, 2*time.Minute)
		defer cancel()
		account, err := h.DB.GetTeamBillingAccountByStripeCustomerID(qctx, &obj.Customer)
		if err != nil {
			if err != pgx.ErrNoRows {
				log.Error().Err(err).Str("customer_id", obj.Customer).Msg("billing: lookup ineligible team failed")
			}
			return
		}
		h.pauseBillingTeam(qctx, account.TeamID)
	})
}

// The pass context carries the tick deadline and dispatch stops when it
// expires, so writing progress through it would fail exactly when there is
// progress worth keeping, and every later tick would restart at the same
// position. The holder fence still applies.
func (h *Handlers) advanceSweepCursor(ctx context.Context, name string, next pgtype.UUID) {
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := h.DB.AdvanceSweepCursor(saveCtx, db.AdvanceSweepCursorParams{
		Name: name, LockedBy: db.SweepHolderID(), CursorID: next,
	}); err != nil {
		log.Error().Err(err).Str("sweep", name).Msg("billing: advance sweep cursor failed")
	}
}

func processSweepPage(ctx context.Context, teams []uuid.UUID, pageSize int32, work func(uuid.UUID) bool) (next pgtype.UUID, advance bool) {
	done := make([]atomic.Bool, len(teams))
	dispatched := 0
	if len(teams) > 0 {
		sem := make(chan struct{}, 10)
		var wg sync.WaitGroup
	dispatch:
		for i, teamID := range teams {
			select {
			case <-ctx.Done():
				break dispatch
			case sem <- struct{}{}:
			}
			dispatched = i + 1
			wg.Add(1)
			go func(i int, teamID uuid.UUID) {
				defer wg.Done()
				defer func() { <-sem }()
				if work(teamID) {
					done[i].Store(true)
				}
			}(i, teamID)
		}
		wg.Wait()
	}
	progress := 0
	for progress < dispatched && done[progress].Load() {
		progress++
	}
	switch {
	case len(teams) == 0:
		return pgtype.UUID{}, true
	case progress == 0:
		return pgtype.UUID{}, false
	case progress == len(teams) && len(teams) < int(pageSize):
		return pgtype.UUID{}, true
	default:
		return pgtype.UUID{Bytes: teams[progress-1], Valid: true}, true
	}
}
