package api

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

const billingEligibilityPauseBatchSize int32 = 50

func (h *Handlers) refreshActiveTrialEligibility(ctx context.Context) {
	var after *uuid.UUID
	for {
		var afterID pgtype.UUID
		if after != nil {
			afterID = pgtype.UUID{Bytes: *after, Valid: true}
		}
		teams, err := h.DB.ListTeamsWithActiveTrialSandboxes(ctx, db.ListTeamsWithActiveTrialSandboxesParams{AfterTeamID: afterID, BatchLimit: 1000})
		if err != nil {
			log.Error().Err(err).Msg("billing: list active trial teams failed")
			return
		}
		if len(teams) == 0 {
			break
		}
		dispatchBounded(ctx, teams, 10, func(teamID uuid.UUID) {
			if err := h.DB.RefreshTeamTrialEligibility(ctx, teamID); err != nil {
				log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing: refresh trial eligibility failed")
				return
			}
			h.pauseBillingIneligibleTeam(ctx, teamID)
		})
		last := teams[len(teams)-1]
		after = &last
		if len(teams) < 1000 {
			break
		}
	}
	h.reconcileActiveIneligibleTeams(ctx)
}

// reconcileActiveIneligibleTeams is the durable safety net for terminal
// subscription transitions. It scans all active teams, not just trials, so a
// restart or a failed webhook goroutine cannot leave paid sandboxes running.
func (h *Handlers) reconcileActiveIneligibleTeams(ctx context.Context) {
	var after *uuid.UUID
	for {
		var afterID pgtype.UUID
		if after != nil {
			afterID = pgtype.UUID{Bytes: *after, Valid: true}
		}
		teams, err := h.DB.ListTeamsWithActiveIneligibleSandboxes(ctx, db.ListTeamsWithActiveIneligibleSandboxesParams{AfterTeamID: afterID, BatchLimit: 1000})
		if err != nil {
			log.Error().Err(err).Msg("billing: list active ineligible teams failed")
			return
		}
		if len(teams) == 0 {
			return
		}
		dispatchBounded(ctx, teams, 10, func(teamID uuid.UUID) {
			h.pauseBillingIneligibleTeam(ctx, teamID)
		})
		last := teams[len(teams)-1]
		after = &last
		if len(teams) < 1000 {
			return
		}
	}
}

func (h *Handlers) reconcileActivatedSandbox(ctx context.Context, teamID uuid.UUID) {
	eligible, err := h.DB.IsTeamSandboxBillingEligible(ctx, teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing: activation eligibility check failed")
		return
	}
	if !eligible {
		h.pauseBillingIneligibleTeam(ctx, teamID)
	}
}

// pauseBillingIneligibleTeam claims and pauses active sandboxes after Stripe
// reports a terminal subscription state. Claiming is DB-atomic and the VMD
// saga runs in the background so webhook acknowledgement is not held on host
// work. A later reconciliation can safely pick up any rows beyond the batch.
func (h *Handlers) pauseBillingIneligibleTeam(ctx context.Context, teamID uuid.UUID) {
	for batch := 0; ; batch++ {
		rows, err := h.DB.ClaimBillingIneligibleSandboxes(ctx, db.ClaimBillingIneligibleSandboxesParams{
			TeamID: teamID,
			Limit:  billingEligibilityPauseBatchSize,
		})
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("billing: claim ineligible sandboxes failed")
			h.retryBillingEligibilityReconciliation(teamID)
			return
		}
		if len(rows) == 0 {
			return
		}
		cleanupCtx := context.WithoutCancel(ctx)
		dispatchBounded(cleanupCtx, rows, 10, func(sbx db.ClaimBillingIneligibleSandboxesRow) {
			itemCtx, itemCancel := context.WithTimeout(cleanupCtx, 2*time.Minute)
			defer itemCancel()
			h.pauseBillingIneligible(itemCtx, sbx, log.Logger)
		})
		if len(rows) < int(billingEligibilityPauseBatchSize) || batch >= 99 {
			if len(rows) > 0 {
				h.retryBillingEligibilityReconciliation(teamID)
			}
			if batch >= 99 && len(rows) == int(billingEligibilityPauseBatchSize) {
				log.Warn().Str("team_id", teamID.String()).Msg("billing: reconciliation batch limit reached")
			}
			return
		}
	}
}

func (h *Handlers) retryBillingEligibilityReconciliation(teamID uuid.UUID) {
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		<-timer.C
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		h.pauseBillingIneligibleTeam(ctx, teamID)
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
		h.pauseBillingIneligibleTeam(qctx, account.TeamID)
	})
}
