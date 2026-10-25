package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/db"
)

// A downgrade can be undone until shortly before it takes effect.
const planChangeUndoCutoff = 10 * time.Minute

// A downgrade that would end the current period within this window waits for
// the next one, leaving time to tell Stripe not to renew.
const planChangeMinNotice = time.Hour

var errTeamPlanChangeConflict = errors.New("plan change conflicts with the team's billing state")

type teamPlanChangeConflictError struct{ reason string }

func (e teamPlanChangeConflictError) Error() string { return e.reason }
func (e teamPlanChangeConflictError) Unwrap() error { return errTeamPlanChangeConflict }

func teamPlanChangeConflict(reason string) error { return teamPlanChangeConflictError{reason} }

type teamPlanChange struct {
	ID                 uuid.UUID       `json:"id"`
	Team               uuid.UUID       `json:"team_id"`
	FromAssignment     uuid.UUID       `json:"from_assignment_id"`
	TargetPlanKey      string          `json:"target_plan_key"`
	TargetKind         string          `json:"target_kind"`
	TargetTerms        frozenPlanTerms `json:"target_terms"`
	TargetLimits       planLimits      `json:"target_limits"`
	EffectiveAt        time.Time       `json:"effective_at"`
	PausesRunning      bool            `json:"pauses_running"`
	Subscription       *string         `json:"subscription_id"`
	RequestedBy        uuid.UUID       `json:"requested_by"`
	RequestedVia       string          `json:"requested_via"`
	Reason             string          `json:"reason"`
	Key                string          `json:"idempotency_key"`
	RequestedAt        time.Time       `json:"requested_at"`
	State              string          `json:"state"`
	CancelRequestedAt  *time.Time      `json:"provider_cancel_requested_at"`
	CancelPreexisting  bool            `json:"provider_cancel_preexisting"`
	ProviderCancelAt   *time.Time      `json:"provider_cancel_at"`
	ProviderRenewedAt  *time.Time      `json:"provider_renewed_at"`
	UndoneAt           *time.Time      `json:"undone_at"`
	UndoneBy           *uuid.UUID      `json:"undone_by"`
	UndoReason         *string         `json:"undo_reason"`
	AppliedAt          *time.Time      `json:"applied_at"`
	AppliedPlan        *uuid.UUID      `json:"applied_assignment_id"`
	CompletedAt        *time.Time      `json:"completed_at"`
	Failures           int             `json:"-"`
	LastError          *string         `json:"last_error"`
	terminalUndoOf     *uuid.UUID
	leaseHeldElsewhere bool
	lease              uuid.UUID
}

// Undoable reports whether the change can still be undone.
func (c teamPlanChange) Undoable(now time.Time) bool {
	return c.State == "scheduled" && now.Before(c.EffectiveAt.Add(-planChangeUndoCutoff))
}

func (c teamPlanChange) needsUndoReconciliation() bool {
	return c.State == "undone" && c.Subscription != nil && c.ProviderRenewedAt == nil
}

const teamPlanChangeColumns = `id,team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,subscription_id,
requested_by,requested_via,reason,idempotency_key,requested_at,state,provider_cancel_requested_at,provider_cancel_preexisting,provider_cancel_at,provider_renewed_at,
undone_at,undone_by,undo_reason,applied_at,applied_assignment_id,completed_at,failures,last_error,lease_until IS NOT NULL AND lease_until>clock_timestamp(),terminal_undo_of`

func scanTeamPlanChange(row pgx.Row) (teamPlanChange, error) {
	var c teamPlanChange
	var terms, limits []byte
	err := row.Scan(&c.ID, &c.Team, &c.FromAssignment, &c.TargetPlanKey, &c.TargetKind, &terms, &limits, &c.EffectiveAt, &c.PausesRunning, &c.Subscription,
		&c.RequestedBy, &c.RequestedVia, &c.Reason, &c.Key, &c.RequestedAt, &c.State, &c.CancelRequestedAt, &c.CancelPreexisting, &c.ProviderCancelAt, &c.ProviderRenewedAt,
		&c.UndoneAt, &c.UndoneBy, &c.UndoReason, &c.AppliedAt, &c.AppliedPlan, &c.CompletedAt, &c.Failures, &c.LastError, &c.leaseHeldElsewhere, &c.terminalUndoOf)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(terms, &c.TargetTerms); err != nil {
		return c, err
	}
	return c, json.Unmarshal(limits, &c.TargetLimits)
}

func getTeamPlanChange(ctx context.Context, q db.DBTX, id uuid.UUID) (teamPlanChange, error) {
	return scanTeamPlanChange(q.QueryRow(ctx, `SELECT `+teamPlanChangeColumns+` FROM team_plan_change WHERE id=$1`, id))
}

func pendingTeamPlanChange(ctx context.Context, q db.DBTX, team uuid.UUID) (teamPlanChange, bool, error) {
	c, err := scanTeamPlanChange(q.QueryRow(ctx, `SELECT `+teamPlanChangeColumns+` FROM team_plan_change WHERE team_id=$1 AND state='scheduled'`, team))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, false, nil
	}
	return c, err == nil, err
}

func pendingCustomerPlanChange(ctx context.Context, q db.DBTX, team uuid.UUID, via string) (*customerPendingPlanChange, error) {
	change, ok, err := pendingTeamPlanChange(ctx, q, team)
	if err != nil || !ok {
		return nil, err
	}
	return &customerPendingPlanChange{ID: change.ID, TargetPlanKey: change.TargetPlanKey, TargetDisplayName: change.TargetTerms.DisplayName,
		EffectiveAt: change.EffectiveAt, Undoable: change.Undoable(time.Now()) && (via == "staff" || via == "customer" && change.RequestedVia == "customer"), PausesRunning: change.PausesRunning}, nil
}

// teamPlanChangeRequest asks to move a team to a self-serve plan.
type teamPlanChangeRequest struct {
	Team                 uuid.UUID
	Target               string
	Key                  string
	Actor                uuid.UUID
	Via                  string
	Reason               string
	PreviewToken         string
	ExpectedEffectiveAt  *time.Time
	ConfirmPausesRunning bool
}

func planChangeConsentToken(current teamPlan, terms planTerms, timing string, effective time.Time) (string, error) {
	var boundary *time.Time
	if timing != planChangeNow {
		at := effective.UTC()
		boundary = &at
	}
	payload := struct {
		Team          uuid.UUID       `json:"team_id"`
		Assignment    uuid.UUID       `json:"assignment_id"`
		Terms         frozenPlanTerms `json:"terms"`
		Limits        planLimits      `json:"limits"`
		Timing        string          `json:"timing"`
		EffectiveAt   *time.Time      `json:"effective_at"`
		PausesRunning bool            `json:"pauses_running"`
	}{current.TeamID, current.ID, freezePlanTerms(terms), terms.Limits, timing, boundary, terms.Kind == planKindFree}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded)), nil
}

// scheduleTeamPlanChange records a downgrade or a move to Free. Moves that
// apply now are applied by the worker straight away; the rest wait for the
// end of the billing period and can be undone until shortly before.
func (h *Handlers) scheduleTeamPlanChange(ctx context.Context, req teamPlanChangeRequest) (teamPlanChange, error) {
	if !selfServePlans[req.Target] {
		return teamPlanChange{}, errUnknownPlan
	}
	if prior, err := replayTeamPlanChange(ctx, h.Pool, req); !errors.Is(err, pgx.ErrNoRows) {
		return prior, err
	}
	if req.Target == "free" {
		ready, err := planChangePausesReady(ctx, h.Pool)
		if err != nil {
			return teamPlanChange{}, err
		}
		if !ready {
			return teamPlanChange{}, teamPlanChangeConflict(planChangePausesUnavailable)
		}
	}
	terms, err := h.planTermsForPricingVersion(ctx, req.Target, "v2")
	if err != nil {
		return teamPlanChange{}, err
	}
	return h.scheduleTeamPlanChangeTo(ctx, req, terms)
}

const planChangePausesUnavailable = "moves to Free are temporarily unavailable until pause support is deployed"

func planChangePausesReady(ctx context.Context, q db.DBTX) (bool, error) {
	var ready bool
	err := q.QueryRow(ctx, `SELECT to_regprocedure('request_team_pause_all(uuid,text)') IS NOT NULL
        AND to_regclass('billing_team_pause_target') IS NOT NULL
        AND CASE WHEN to_regclass('billing_team_pause_target') IS NULL THEN false
        ELSE to_regprocedure('billing_pause_target_settled(billing_team_pause_target)') IS NOT NULL END`).Scan(&ready)
	return ready, err
}

func replayTeamPlanChange(ctx context.Context, q db.DBTX, req teamPlanChangeRequest) (teamPlanChange, error) {
	prior, err := scanTeamPlanChange(q.QueryRow(ctx, `SELECT `+teamPlanChangeColumns+` FROM team_plan_change WHERE team_id=$1 AND idempotency_key=$2`, req.Team, req.Key))
	if err == nil && prior.TargetPlanKey != req.Target {
		err = teamPlanChangeConflict("idempotency key was used for a different plan change")
	}
	return prior, err
}

func (h *Handlers) scheduleTeamPlanChangeTo(ctx context.Context, req teamPlanChangeRequest, terms planTerms) (teamPlanChange, error) {
	if prior, err := replayTeamPlanChange(ctx, h.Pool, req); !errors.Is(err, pgx.ErrNoRows) {
		return prior, err
	}
	current, assigned, err := currentTeamPlan(ctx, h.Pool, req.Team)
	if err != nil {
		return teamPlanChange{}, err
	}
	var subscription *string
	var periodEnd time.Time
	if assigned && (current.Kind == planKindSubscription || current.Kind == planKindCustom) {
		if subscription, periodEnd, err = h.planChangeBoundary(ctx, req.Team, current, time.Now()); err != nil {
			return teamPlanChange{}, err
		}
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return teamPlanChange{}, err
	}
	defer tx.Rollback(ctx)
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp() FROM team WHERE id=$1 FOR NO KEY UPDATE`, req.Team).Scan(&now); err != nil {
		return teamPlanChange{}, err
	}
	if prior, err := replayTeamPlanChange(ctx, tx, req); !errors.Is(err, pgx.ErrNoRows) {
		return prior, err
	}
	if terms.VersionID != uuid.Nil {
		version, err := scanPlanVersion(tx.QueryRow(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1 FOR SHARE`, terms.VersionID))
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (version.State != "published" || version.PricingVersion != "v2") {
			return teamPlanChange{}, teamPlanChangeConflict("this plan is no longer offered; reload the preview")
		}
		if err != nil {
			return teamPlanChange{}, err
		}
		catalog := &Handlers{DB: db.New(tx)}
		terms, err = catalog.termsOfVersion(ctx, version, terms.IntervalMonths)
		if err != nil {
			return teamPlanChange{}, err
		}
		if terms.OfferKey != req.Target {
			return teamPlanChange{}, errUnknownPlan
		}
	}
	if terms.Limits.MaxConcurrent == nil {
		return teamPlanChange{}, errors.New("target plan has no limits")
	}
	if terms.Retired {
		return teamPlanChange{}, teamPlanChangeConflict("this plan is no longer offered")
	}
	locked, assigned, err := currentTeamPlan(ctx, tx, req.Team)
	if err != nil {
		return teamPlanChange{}, err
	}
	if !assigned {
		return teamPlanChange{}, teamPlanChangeConflict("plan changes are not available for this team yet")
	}
	if locked.ID != current.ID {
		return teamPlanChange{}, teamPlanChangeConflict("the team's plan changed; reload and try again")
	}
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_plan_change WHERE team_id=$1 AND
        (state='scheduled' OR (state='undone' AND subscription_id IS NOT NULL AND provider_renewed_at IS NULL)))`, req.Team).Scan(&pending); err != nil || pending {
		if err == nil {
			err = teamPlanChangeConflict("the team already has a pending plan change; wait for it to finish or undo it")
		}
		return teamPlanChange{}, err
	}
	timing, blocked := planChangeRule(current.Kind, terms.Kind)
	if blocked != "" {
		return teamPlanChange{}, teamPlanChangeConflict(blocked)
	}
	if timing == planChangeAfterPurchase {
		return teamPlanChange{}, teamPlanChangeConflict("upgrades take effect when the plan is purchased")
	}
	effective := now
	if timing == planChangeEndOfPeriod {
		if current.Kind == planKindSubscription && subscription == nil {
			return teamPlanChange{}, teamPlanChangeConflict("the team's subscription could not be found")
		}
		effective = periodEnd
	}
	if req.Via == "customer" || req.PreviewToken != "" || req.ExpectedEffectiveAt != nil {
		if terms.Kind == planKindFree && !req.ConfirmPausesRunning {
			return teamPlanChange{}, teamPlanChangeConflict("confirm that all running compute will be paused before continuing")
		}
		token, err := planChangeConsentToken(locked, terms, timing, effective)
		if err != nil {
			return teamPlanChange{}, err
		}
		dateMatches := timing == planChangeNow && req.ExpectedEffectiveAt == nil || timing == planChangeEndOfPeriod && req.ExpectedEffectiveAt != nil && req.ExpectedEffectiveAt.Equal(effective)
		if !dateMatches || req.PreviewToken == "" || token != req.PreviewToken || timing == planChangeEndOfPeriod && effective.Sub(now) < planChangeMinNotice {
			return teamPlanChange{}, teamPlanChangeConflict("the plan change preview changed; reload it and confirm again")
		}
	}
	frozen, limits, _, err := planAssignment{Terms: terms}.frozen()
	if err != nil {
		return teamPlanChange{}, err
	}
	c, err := scanTeamPlanChange(tx.QueryRow(ctx, `INSERT INTO team_plan_change(team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,
        subscription_id,requested_by,requested_via,reason,idempotency_key,next_check_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CASE WHEN $9::text IS NULL THEN $7 ELSE clock_timestamp() END) RETURNING `+teamPlanChangeColumns,
		req.Team, current.ID, req.Target, terms.Kind, frozen, limits, effective, terms.Kind == planKindFree, subscription, req.Actor, req.Via, req.Reason, req.Key))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return teamPlanChange{}, teamPlanChangeConflict("the team already has a pending plan change; wait for it to finish or undo it")
	}
	if err != nil {
		return teamPlanChange{}, err
	}
	return c, tx.Commit(ctx)
}

func (h *Handlers) planChangeBoundary(ctx context.Context, team uuid.UUID, current teamPlan, now time.Time) (*string, time.Time, error) {
	var err error
	var subscription *string
	var periodEnd time.Time
	if current.Kind == planKindSubscription && current.ContractID != nil {
		if subscription, periodEnd, err = h.planChangeSubscription(ctx, team, *current.ContractID); err != nil {
			return nil, time.Time{}, err
		}
	}
	if current.Kind == planKindCustom || current.Kind == planKindSubscription && periodEnd.Sub(now) < planChangeMinNotice {
		var anchor pgtype.Timestamptz
		if err = h.Pool.QueryRow(ctx, `SELECT commercial_billing_anchor FROM team_billing_account WHERE team_id=$1`, team).Scan(&anchor); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, time.Time{}, err
		}
		from := now
		if current.Kind == planKindSubscription {
			from = periodEnd.Add(time.Second)
		}
		if periodEnd, err = h.planChangePeriodEnd(ctx, team, anchor, from); err != nil {
			return nil, time.Time{}, err
		}
	}
	if current.Kind == planKindSubscription && subscription == nil {
		return nil, time.Time{}, teamPlanChangeConflict("the team's subscription could not be found")
	}
	return subscription, periodEnd, nil
}

// planChangeSubscription is the live Stripe subscription billing a team's
// subscription plan and the end of its current period.
func (h *Handlers) planChangeSubscription(ctx context.Context, team, contract uuid.UUID) (*string, time.Time, error) {
	var subscription string
	err := h.Pool.QueryRow(ctx, `SELECT subscription_id FROM billing_commercial_contract WHERE id=$1 AND team_id=$2 AND status='active' AND subscription_id IS NOT NULL`, contract, team).Scan(&subscription)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, time.Time{}, teamPlanChangeConflict("the team's subscription could not be found")
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return nil, time.Time{}, errors.New("plan changes require the Stripe provider")
	}
	sub, err := client.invoiceSubscription(ctx, subscription)
	if err != nil {
		return nil, time.Time{}, err
	}
	if subscriptionEnded(sub) {
		return nil, time.Time{}, teamPlanChangeConflict("the team's subscription has already ended")
	}
	end := subscriptionPeriodEnd(sub)
	if sub.CancelAt != 0 && !time.Unix(sub.CancelAt, 0).Equal(end) {
		return nil, time.Time{}, teamPlanChangeConflict("the subscription cancellation does not match the billing period; reconcile its cancellation date before changing plans")
	}
	if subscriptionWillEnd(sub) && end.Sub(time.Now()) < planChangeMinNotice {
		return nil, time.Time{}, teamPlanChangeConflict("the subscription is already ending too soon to schedule a plan change")
	}
	return &subscription, end, nil
}

// planChangePeriodEnd is the end of the team's billing period, or of the next
// one when the current period ends too soon to stop a renewal.
func (h *Handlers) planChangePeriodEnd(ctx context.Context, team uuid.UUID, anchor pgtype.Timestamptz, now time.Time) (time.Time, error) {
	_, end, err := h.currentBillingPeriod(ctx, team, anchor, now)
	if err != nil || end.Sub(now) >= planChangeMinNotice {
		return end, err
	}
	_, end, err = h.currentBillingPeriod(ctx, team, anchor, end.Add(time.Second))
	return end, err
}

// undoTeamPlanChange withdraws a scheduled change. It only records the undo;
// the worker then turns the subscription's renewal back on if this change had
// turned it off, so Stripe never ends up contradicting the plan.
func (h *Handlers) undoTeamPlanChange(ctx context.Context, team, id, actor uuid.UUID, reason, via string) (teamPlanChange, error) {
	c, err := scanTeamPlanChange(h.Pool.QueryRow(ctx, `SELECT `+teamPlanChangeColumns+` FROM team_plan_change WHERE id=$1 AND team_id=$2 AND ($3='staff' OR ($3='customer' AND requested_via='customer'))`, id, team, via))
	if err != nil {
		return c, err
	}
	if c.State == "undone" {
		return c, nil
	}
	if c.Subscription != nil && c.State == "scheduled" {
		client, ok := h.Stripe.(*stripeHTTPClient)
		if !ok {
			return c, errors.New("plan changes require the Stripe provider")
		}
		sub, err := client.invoiceSubscription(ctx, *c.Subscription)
		if err != nil {
			return c, err
		}
		if subscriptionEnded(sub) {
			_, err = h.Pool.Exec(ctx, `UPDATE team_plan_change SET next_check_at=clock_timestamp() WHERE id=$1 AND state='scheduled'`, c.ID)
			if err != nil {
				return c, err
			}
			return c, teamPlanChangeConflict("the subscription has ended; the committed plan change must finish")
		}
	}
	tag, err := h.Pool.Exec(ctx, `UPDATE team_plan_change SET state='undone',undone_at=clock_timestamp(),undone_by=$2,undo_reason=$4,
        next_check_at=CASE WHEN subscription_id IS NOT NULL THEN clock_timestamp() ELSE 'infinity'::timestamptz END
        WHERE id=$1 AND state='scheduled' AND effective_at>clock_timestamp()+$3::interval AND (lease_until IS NULL OR lease_until<clock_timestamp())
        AND ($5='staff' OR ($5='customer' AND requested_via='customer'))`,
		c.ID, actor, planChangeUndoCutoff.String(), reason, via)
	if err != nil {
		return c, err
	}
	if tag.RowsAffected() == 0 {
		if c, err = getTeamPlanChange(ctx, h.Pool, c.ID); err != nil || c.State == "undone" {
			return c, err
		}
		if c.leaseHeldElsewhere && c.Undoable(time.Now()) {
			return c, teamPlanChangeConflict("this plan change is being updated; try again in a moment")
		}
		return c, teamPlanChangeConflict("this plan change can no longer be undone")
	}
	return getTeamPlanChange(ctx, h.Pool, c.ID)
}

// setSubscriptionRenewal tells Stripe whether a subscription renews at the end
// of its current period, and checks that it took. Setting the flag is
// naturally repeatable, so each attempt is a fresh request: a cached failure
// can never be replayed in place of the real state.
func (h *Handlers) setSubscriptionRenewal(ctx context.Context, subscription string, change uuid.UUID, renew bool) error {
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return errors.New("plan changes require the Stripe provider")
	}
	var sub invoiceSubscription
	owner := change.String()
	if renew {
		owner = ""
	}
	form := url.Values{"cancel_at_period_end": {fmt.Sprint(!renew)}, "proration_behavior": {"none"}, "metadata[plan_change_cancellation]": {owner}}
	if err := client.doForm(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(subscription), form, &sub, ""); err != nil {
		return err
	}
	if sub.ID != subscription || sub.CancelAtPeriodEnd == renew || renew && sub.CancelAt != 0 || sub.Metadata["plan_change_cancellation"] != owner {
		return errors.New("subscription renewal did not change as requested")
	}
	return nil
}

func subscriptionPeriodEnd(sub invoiceSubscription) time.Time {
	var end int64
	for _, item := range sub.Items.Data {
		end = max(end, item.End)
	}
	return time.Unix(end, 0).UTC()
}

func subscriptionEnded(sub invoiceSubscription) bool {
	return sub.Status == "canceled" || sub.Status == "incomplete_expired" || sub.EndedAt != 0
}

func subscriptionWillEnd(sub invoiceSubscription) bool {
	return subscriptionEnded(sub) || sub.CancelAtPeriodEnd || sub.CancelAt != 0
}

func subscriptionStopsBy(sub invoiceSubscription, boundary time.Time) bool {
	if subscriptionEnded(sub) {
		return true
	}
	if sub.CancelAt != 0 {
		return time.Unix(sub.CancelAt, 0).Equal(boundary)
	}
	return sub.CancelAtPeriodEnd && !subscriptionPeriodEnd(sub).After(boundary)
}

const teamPlanChangeReviewFailures = 6

func teamPlanChangeRetryDelay(failures int) time.Duration {
	return time.Duration(math.Min(float64(time.Hour), float64(30*time.Second)*math.Pow(2, float64(min(failures, 10)))))
}

// teamPlanChangeTick advances existing commitments regardless of the entry switch.
func (h *Handlers) teamPlanChangeTick(ctx context.Context) (bool, error) {
	return h.runDueTeamPlanChange(ctx, uuid.Nil)
}

// runDueTeamPlanChange leases one due change, of the given team unless team is
// uuid.Nil, for longer than a job may run; every state write is fenced by the
// lease token.
func (h *Handlers) runDueTeamPlanChange(ctx context.Context, team uuid.UUID) (bool, error) {
	token := uuid.New()
	c, err := scanTeamPlanChange(h.Pool.QueryRow(ctx, `WITH due AS (SELECT id AS due_id FROM team_plan_change WHERE next_check_at<=clock_timestamp()
        AND (state IN ('scheduled','applied') OR (state='undone' AND subscription_id IS NOT NULL AND provider_renewed_at IS NULL))
        AND (lease_until IS NULL OR lease_until<clock_timestamp()) AND ($2::uuid=$3::uuid OR team_id=$2::uuid)
        ORDER BY next_check_at,id FOR UPDATE SKIP LOCKED LIMIT 1)
        UPDATE team_plan_change p SET lease_token=$1,lease_until=clock_timestamp()+interval '3 minutes' FROM due WHERE p.id=due.due_id
        RETURNING `+teamPlanChangeColumns, token, team, uuid.Nil))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	c.lease = token
	jobCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	next, err := h.advanceTeamPlanChange(jobCtx, c)
	cancel()
	msg := ""
	if err != nil {
		msg = err.Error()
		next = time.Now().Add(teamPlanChangeRetryDelay(c.Failures))
		event := log.Warn()
		if c.Failures+1 >= teamPlanChangeReviewFailures {
			event = log.Error()
		}
		event.Err(err).Str("plan_change_id", c.ID.String()).Str("team_id", c.Team.String()).Int("failures", c.Failures+1).Msg("plan change pending")
	}
	ack, cancelAck := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelAck()
	_, err = h.Pool.Exec(ack, `UPDATE team_plan_change SET lease_token=NULL,lease_until=NULL,
        next_check_at=CASE WHEN state='completed' OR (state='undone' AND (subscription_id IS NULL OR provider_renewed_at IS NOT NULL))
         THEN 'infinity'::timestamptz ELSE $3::timestamptz END,
        failures=CASE WHEN $4='' THEN 0 ELSE failures+1 END,last_error=NULLIF($4,'') WHERE id=$1 AND lease_token=$2`, c.ID, token, next, msg)
	return true, err
}

// advanceTeamPlanChange moves one change forward and returns when to look
// again: stop the subscription renewing, apply the plan when it takes effect,
// then pause the team's running sandboxes if the new plan is Free. An undone
// change only puts the subscription's renewal back.
func (h *Handlers) advanceTeamPlanChange(ctx context.Context, c teamPlanChange) (time.Time, error) {
	now := time.Now()
	switch {
	case c.State == "undone":
		return now, h.restorePlanChangeRenewal(ctx, c)
	case c.State == "scheduled" && c.Subscription != nil && (c.ProviderCancelAt == nil || now.Before(c.EffectiveAt)):
		next, err := h.stopPlanChangeRenewal(ctx, c, now)
		if err != nil {
			return now, err
		}
		if !next.After(now) {
			lease := c.lease
			c, err = getTeamPlanChange(ctx, h.Pool, c.ID)
			if err != nil {
				return now, err
			}
			c.lease = lease
			return h.applyTeamPlanChange(ctx, c)
		}
		if next.After(now.Add(time.Minute)) {
			next = now.Add(time.Minute)
		}
		return next, nil
	case c.State == "scheduled" && now.Before(c.EffectiveAt):
		return c.EffectiveAt, nil
	case c.State == "scheduled":
		return h.applyTeamPlanChange(ctx, c)
	case c.State == "applied":
		if err := h.waitForPlanChangePauses(ctx, c.Team); err != nil {
			return now, err
		}
		_, err := h.Pool.Exec(ctx, `UPDATE team_plan_change SET state='completed',completed_at=clock_timestamp() WHERE id=$1 AND lease_token=$2 AND state='applied'`, c.ID, c.lease)
		return now, err
	}
	return now, nil
}

// fencedPlanChangeUpdate runs one state write that must still find the change as this
// lease left it.
func fencedPlanChangeUpdate(ctx context.Context, q db.DBTX, c teamPlanChange, set string, args ...any) error {
	tag, err := q.Exec(ctx, `UPDATE team_plan_change SET `+set+` WHERE id=$1 AND lease_token=$2`, append([]any{c.ID, c.lease}, args...)...)
	if err == nil && tag.RowsAffected() == 0 {
		err = errors.New("plan change moved on during this step")
	}
	return err
}

// stopPlanChangeRenewal tells Stripe not to renew the Pro subscription at the
// period end the change takes effect, recording the intent first. If that
// period has already renewed, the change waits for the next period end
// instead of cutting a paid month short.
func (h *Handlers) stopPlanChangeRenewal(ctx context.Context, c teamPlanChange, now time.Time) (time.Time, error) {
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return now, errors.New("plan changes require the Stripe provider")
	}
	if c.CancelRequestedAt == nil {
		sub, err := client.invoiceSubscription(ctx, *c.Subscription)
		if err != nil {
			return now, err
		}
		if err = fencedPlanChangeUpdate(ctx, h.Pool, c, `provider_cancel_requested_at=clock_timestamp(),provider_cancel_preexisting=$3`, subscriptionWillEnd(sub)); err != nil {
			return now, err
		}
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return now, err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `SELECT 1 FROM team WHERE id=$1 FOR NO KEY UPDATE`, c.Team).Scan(new(int)); err != nil {
		return now, err
	}
	current, assigned, err := currentTeamPlan(ctx, tx, c.Team)
	if err != nil {
		return now, err
	}
	if !assigned || current.ID != c.FromAssignment {
		if err = fencedPlanChangeUpdate(ctx, tx, c, `state='undone',undone_at=clock_timestamp(),undo_reason='the team changed plans first',provider_renewed_at=clock_timestamp()`); err != nil {
			return now, err
		}
		return now, tx.Commit(ctx)
	}
	sub, err := client.invoiceSubscription(ctx, *c.Subscription)
	if err != nil {
		return now, err
	}
	if c.terminalUndoOf != nil && !subscriptionEnded(sub) {
		return now, errors.New("terminal undo settlement cannot cancel a live subscription")
	}
	if !subscriptionEnded(sub) {
		end := subscriptionPeriodEnd(sub)
		if end.After(c.EffectiveAt) {
			if err = fencedPlanChangeUpdate(ctx, tx, c, `effective_at=$3`, end); err != nil {
				return now, err
			}
			c.EffectiveAt = end
		} else if !end.Equal(c.EffectiveAt) {
			return now, errors.New("subscription period does not end when the plan change takes effect")
		}
	}
	if subscriptionWillEnd(sub) && !subscriptionStopsBy(sub, c.EffectiveAt) {
		return now, errors.New("the subscription cancellation does not match the confirmed plan change")
	}
	if !subscriptionWillEnd(sub) {
		if err = h.setSubscriptionRenewal(ctx, *c.Subscription, c.ID, false); err != nil {
			return now, err
		}
	}
	sub, err = client.invoiceSubscription(ctx, *c.Subscription)
	if err != nil {
		return now, err
	}
	if !subscriptionWillEnd(sub) {
		return now, errors.New("subscription cancellation was not confirmed")
	}
	if end := subscriptionPeriodEnd(sub); !subscriptionEnded(sub) && end.After(c.EffectiveAt) {
		if err = fencedPlanChangeUpdate(ctx, tx, c, `effective_at=$3`, end); err != nil {
			return now, err
		}
		c.EffectiveAt = end
	}
	if !subscriptionStopsBy(sub, c.EffectiveAt) {
		return now, errors.New("the subscription would continue beyond the confirmed plan change")
	}
	if c.ProviderCancelAt == nil {
		if err = fencedPlanChangeUpdate(ctx, tx, c, `provider_cancel_at=clock_timestamp()`); err != nil {
			return now, err
		}
	}
	next := c.EffectiveAt
	if subscriptionEnded(sub) {
		next = now
	}
	return next, tx.Commit(ctx)
}

// restorePlanChangeRenewal turns renewal back on for a subscription an undone
// change had told Stripe not to renew.
func (h *Handlers) restorePlanChangeRenewal(ctx context.Context, c teamPlanChange) error {
	if !c.needsUndoReconciliation() {
		return nil
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `SELECT 1 FROM team WHERE id=$1 FOR NO KEY UPDATE`, c.Team).Scan(new(int)); err != nil {
		return err
	}
	current, assigned, err := currentTeamPlan(ctx, tx, c.Team)
	if err != nil {
		return err
	}
	if assigned && current.ID == c.FromAssignment {
		client, ok := h.Stripe.(*stripeHTTPClient)
		if !ok {
			return errors.New("plan changes require the Stripe provider")
		}
		sub, err := client.invoiceSubscription(ctx, *c.Subscription)
		if err != nil {
			return err
		}
		if subscriptionEnded(sub) {
			ended := time.Now()
			if sub.EndedAt > 0 && !time.Unix(sub.EndedAt, 0).After(ended) {
				ended = time.Unix(sub.EndedAt, 0)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO team_plan_change(team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,effective_at,pauses_running,
                subscription_id,requested_by,requested_via,reason,idempotency_key,terminal_undo_of)
                SELECT team_id,from_assignment_id,target_plan_key,target_kind,target_terms,target_limits,$2,pauses_running,subscription_id,requested_by,requested_via,
                'the subscription ended before renewal could be restored','terminal-undo:'||gen_random_uuid()::text,id FROM team_plan_change WHERE id=$1
                ON CONFLICT(terminal_undo_of) DO NOTHING`, c.ID, ended); err != nil {
				return err
			}
		} else if c.CancelRequestedAt != nil && sub.CancelAtPeriodEnd && sub.Metadata["plan_change_cancellation"] == c.ID.String() &&
			(sub.CancelAt == 0 || sub.CancelAt == subscriptionPeriodEnd(sub).Unix()) {
			if err = h.setSubscriptionRenewal(ctx, *c.Subscription, c.ID, true); err != nil {
				return err
			}
		}
	}
	if err = fencedPlanChangeUpdate(ctx, tx, c, `provider_renewed_at=clock_timestamp()`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// applyTeamPlanChange moves the team onto the target plan once Stripe will not
// renew its subscription. A change whose team has moved plans since it was
// requested is withdrawn instead, leaving the subscription to the new plan.
func (h *Handlers) applyTeamPlanChange(ctx context.Context, c teamPlanChange) (time.Time, error) {
	now := time.Now()
	lease, err := h.planChangeProcessingLease(ctx, c)
	if err != nil {
		return now, err
	}
	if lease != nil {
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			_ = h.DB.ReleaseStripeWebhookProcessingLease(cleanup, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: lease.CustomerID, Token: lease.Token})
		}()
	}
	var terminal invoiceSubscription
	if c.Subscription != nil {
		client, ok := h.Stripe.(*stripeHTTPClient)
		if !ok {
			return now, errors.New("plan changes require the Stripe provider")
		}
		sub, err := client.invoiceSubscription(ctx, *c.Subscription)
		if err != nil {
			return now, err
		}
		if c.ProviderCancelAt == nil || !subscriptionWillEnd(sub) {
			return now, errors.New("the subscription would still renew; not applying the plan change")
		}
		if end := subscriptionPeriodEnd(sub); !subscriptionEnded(sub) && end.After(c.EffectiveAt) {
			return end, fencedPlanChangeUpdate(ctx, h.Pool, c, `effective_at=$3`, end)
		}
		if !subscriptionEnded(sub) {
			return now.Add(time.Minute), nil
		}
		closed, err := h.proInvoicesClosed(ctx, client, c.Team, sub.Customer, sub.ID, nil)
		if err != nil {
			return now, err
		}
		if !closed {
			_, err = h.Pool.Exec(ctx, `UPDATE billing_signup_choice SET next_check_at=LEAST(next_check_at,clock_timestamp()) WHERE team_id=$1 AND subscription_id=$2`, c.Team, sub.ID)
			return now.Add(time.Minute), err
		}
		terminal = sub
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return now, err
	}
	defer tx.Rollback(ctx)
	if err = lease.lock(ctx, h.DB.WithTx(tx)); err != nil {
		return now, err
	}
	if err = tx.QueryRow(ctx, `SELECT 1 FROM team WHERE id=$1 FOR NO KEY UPDATE`, c.Team).Scan(new(int)); err != nil {
		return now, err
	}
	if err = tx.QueryRow(ctx, `SELECT 1 FROM team_plan_change WHERE id=$1 AND lease_token=$2 AND state='scheduled' FOR UPDATE`, c.ID, c.lease).Scan(new(int)); err != nil {
		return now, err
	}
	current, assigned, err := currentTeamPlan(ctx, tx, c.Team)
	if err != nil {
		return now, err
	}
	if !assigned || current.ID != c.FromAssignment {
		if _, err = tx.Exec(ctx, `UPDATE team_plan_change SET state='undone',undone_at=clock_timestamp(),undo_reason='the team changed plans first',
            provider_renewed_at=CASE WHEN subscription_id IS NULL THEN NULL ELSE clock_timestamp() END WHERE id=$1`, c.ID); err != nil {
			return now, err
		}
		log.Warn().Str("plan_change_id", c.ID.String()).Str("team_id", c.Team.String()).Msg("plan change withdrawn: the team changed plans first")
		return now, tx.Commit(ctx)
	}
	if c.Subscription != nil {
		if err = h.releasePlanChangeSubscription(ctx, tx, c, current, terminal); err != nil {
			return now, err
		}
		ended := now
		if terminal.EndedAt > 0 && !time.Unix(terminal.EndedAt, 0).After(now) {
			ended = time.Unix(terminal.EndedAt, 0)
		}
		if ended.Before(c.EffectiveAt) {
			c.EffectiveAt = ended
		}
	}
	terms := planTerms{OfferKey: c.TargetPlanKey, DisplayName: c.TargetTerms.DisplayName, FeeCents: c.TargetTerms.FeeCents, IntervalMonths: c.TargetTerms.IntervalMonths,
		MonthlyCreditCents: c.TargetTerms.MonthlyCreditCents, VersionID: c.TargetTerms.VersionID, Version: c.TargetTerms.Version, Family: c.TargetTerms.Family,
		PricingVersion: c.TargetTerms.PricingVersion, Kind: c.TargetKind, Grants: c.TargetTerms.Grants, Matching: c.TargetTerms.Matching,
		Allowance: c.TargetTerms.Allowance, Limits: c.TargetLimits}
	actor := c.RequestedBy
	plan, err := assignTeamPlan(ctx, tx, planAssignment{Team: c.Team, Terms: terms, Source: planSourcePlanChange, Actor: &actor,
		Reason: c.Reason, Key: "plan-change:" + c.ID.String()})
	if err != nil {
		return now, err
	}
	if c.PausesRunning {
		if err = tx.QueryRow(ctx, `SELECT request_team_pause_all($1,'plan_switch_free')`, c.Team).Scan(new(int32)); err != nil {
			return now, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE team_plan_change SET state='applied',effective_at=$3,applied_at=clock_timestamp(),applied_assignment_id=$2 WHERE id=$1`, c.ID, plan.ID, c.EffectiveAt); err != nil {
		return now, err
	}
	if !c.PausesRunning {
		if _, err = tx.Exec(ctx, `UPDATE team_plan_change SET state='completed',completed_at=clock_timestamp() WHERE id=$1`, c.ID); err != nil {
			return now, err
		}
	}
	return now, tx.Commit(ctx)
}

func (h *Handlers) waitForPlanChangePauses(ctx context.Context, team uuid.UUID) error {
	var pending bool
	if err := h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_team_pause_target t
        WHERE team_id=$1 AND reason='plan_switch_free' AND done_at IS NULL AND NOT billing_pause_target_settled(t))`, team).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return errors.New("waiting for the team's running sandboxes to pause")
	}
	return nil
}

type teamPlanChangeBody struct {
	TargetPlan           string     `json:"target_plan"`
	Key                  string     `json:"idempotency_key"`
	Reason               string     `json:"reason"`
	PreviewToken         string     `json:"preview_token"`
	ExpectedEffectiveAt  *time.Time `json:"expected_effective_at"`
	ConfirmPausesRunning bool       `json:"confirm_pauses_running"`
}

func decodeTeamPlanChange(c *gin.Context) (teamPlanChangeBody, bool) {
	var body teamPlanChangeBody
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		respondErrorMsg(c, "bad_request", "target_plan and idempotency_key are required", http.StatusBadRequest)
		return body, false
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if !selfServePlans[body.TargetPlan] {
		respondErrorMsg(c, "invalid_plan", "target_plan must be free, starter or pro_monthly", http.StatusBadRequest)
		return body, false
	}
	if strings.TrimSpace(body.Key) == "" || utf8.RuneCountInString(body.Key) > 200 || utf8.RuneCountInString(body.Reason) > 2000 || len(body.PreviewToken) > 64 {
		respondErrorMsg(c, "bad_request", "idempotency_key (up to 200 characters) is required and reason is at most 2000 characters", http.StatusBadRequest)
		return body, false
	}
	return body, true
}

func (h *Handlers) respondTeamPlanChange(c *gin.Context, team uuid.UUID, change teamPlanChange, err error) {
	var conflict teamPlanChangeConflictError
	switch {
	case errors.As(err, &conflict):
		respondErrorMsg(c, "conflict", conflict.reason, http.StatusConflict)
	case errors.Is(err, errUnknownPlan):
		respondErrorMsg(c, "invalid_plan", "this plan is not available", http.StatusBadRequest)
	case errors.Is(err, pgx.ErrNoRows):
		respondErrorMsg(c, "not_found", "plan change not found", http.StatusNotFound)
	case err != nil:
		log.Error().Err(err).Str("team_id", team.String()).Msg("plan change failed")
		respondErrorMsg(c, "unavailable", "the plan change could not be completed; retry with the same request", http.StatusServiceUnavailable)
	default:
		c.JSON(http.StatusOK, teamPlanChangeJSON(change, time.Now()))
	}
}

func teamPlanChangeJSON(c teamPlanChange, now time.Time) gin.H {
	return gin.H{"id": c.ID, "target_plan_key": c.TargetPlanKey, "target_display_name": c.TargetTerms.DisplayName, "target_kind": c.TargetKind,
		"effective_at": c.EffectiveAt, "pauses_running": c.PausesRunning, "state": c.State, "undoable": c.Undoable(now), "limits": c.TargetLimits}
}

// RequestBillingPlanChange lets a team downgrade or switch to Free.
func (h *Handlers) RequestBillingPlanChange(c *gin.Context) {
	team, err := customerContextTeamID(c)
	if err != nil || !h.requireCustomerTeamPermission(c, team, "billing:write") {
		return
	}
	actor, err := customerActorID(c)
	if err != nil {
		return
	}
	body, ok := decodeTeamPlanChange(c)
	if !ok {
		return
	}
	if len(body.PreviewToken) != 64 || body.TargetPlan == "free" && !body.ConfirmPausesRunning {
		respondErrorMsg(c, "bad_request", "preview_token is required and moves to Free require confirm_pauses_running", http.StatusBadRequest)
		return
	}
	reason := body.Reason
	if reason == "" {
		reason = "requested by the team"
	}
	change, err := h.scheduleTeamPlanChange(c.Request.Context(), teamPlanChangeRequest{Team: team, Target: body.TargetPlan, Key: body.Key, Actor: actor, Via: "customer", Reason: reason, PreviewToken: body.PreviewToken, ExpectedEffectiveAt: body.ExpectedEffectiveAt, ConfirmPausesRunning: body.ConfirmPausesRunning})
	h.respondTeamPlanChange(c, team, change, err)
}

// UndoBillingPlanChange withdraws the team's scheduled plan change.
func (h *Handlers) UndoBillingPlanChange(c *gin.Context) {
	team, err := customerContextTeamID(c)
	if err != nil || !h.requireCustomerTeamPermission(c, team, "billing:write") {
		return
	}
	actor, err := customerActorID(c)
	if err != nil {
		return
	}
	id, err := uuid.Parse(c.Param("change_id"))
	if err != nil {
		respondErrorMsg(c, "not_found", "plan change not found", http.StatusNotFound)
		return
	}
	change, err := h.undoTeamPlanChange(c.Request.Context(), team, id, actor, "requested by the team", "customer")
	h.respondTeamPlanChange(c, team, change, err)
}

// RequestTeamPlanChange lets staff downgrade a team or move it to Free, with a
// recorded reason.
func (h *Handlers) RequestTeamPlanChange(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	body, ok := decodeTeamPlanChange(c)
	if !ok {
		return
	}
	if body.Reason == "" {
		respondErrorMsg(c, "bad_request", "reason is required", http.StatusBadRequest)
		return
	}
	change, err := h.scheduleTeamPlanChange(c.Request.Context(), teamPlanChangeRequest{Team: team, Target: body.TargetPlan, Key: body.Key, Actor: actor, Via: "staff", Reason: body.Reason, PreviewToken: body.PreviewToken, ExpectedEffectiveAt: body.ExpectedEffectiveAt, ConfirmPausesRunning: body.ConfirmPausesRunning})
	h.respondTeamPlanChange(c, team, change, err)
}

// UndoTeamPlanChange lets staff withdraw a team's scheduled plan change.
func (h *Handlers) UndoTeamPlanChange(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("change_id"))
	if err != nil {
		respondErrorMsg(c, "not_found", "plan change not found", http.StatusNotFound)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(body.Reason) == "" || utf8.RuneCountInString(body.Reason) > 2000 {
		respondErrorMsg(c, "bad_request", "reason (up to 2000 characters) is required", http.StatusBadRequest)
		return
	}
	change, err := h.undoTeamPlanChange(c.Request.Context(), team, id, actor, strings.TrimSpace(body.Reason), "staff")
	h.respondTeamPlanChange(c, team, change, err)
}

// StartTeamPlanChangeService applies scheduled plan changes as they fall due.
func (h *Handlers) StartTeamPlanChangeService(ctx context.Context) {
	if h.Pool == nil {
		return
	}
	go func() {
		for {
			worked, err := h.teamPlanChangeTick(ctx)
			if err != nil && ctx.Err() == nil {
				log.Warn().Err(err).Msg("plan change tick failed")
			}
			delay := 5 * time.Second
			if worked {
				delay = time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()
}
