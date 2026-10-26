package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

// Plan kinds: how a plan is paid for, whatever its name.
const (
	planKindFree         = "free"
	planKindPrepaid      = "prepaid"
	planKindSubscription = "subscription"
	planKindLegacyPAYG   = "legacy_payg"
	planKindCustom       = "custom"
)

// Where an assignment came from.
const (
	planSourceSignup         = "signup"
	planSourceMigration      = "migration"
	planSourceCheckout       = "checkout"
	planSourceCreditPurchase = "credit_purchase"
	planSourcePlanChange     = "plan_change"
	planSourceStaff          = "staff"
)

var (
	errPlanRetired          = errors.New("plan is retired")
	errPlanAssignmentReused = errors.New("idempotency key was used for a different plan assignment")
)

// frozenPlanTerms is the copy of a plan's terms an assignment keeps, so later
// catalog versions never change what a team was given.
type frozenPlanTerms struct {
	OfferKey           string         `json:"offer_key"`
	DisplayName        string         `json:"display_name"`
	FeeCents           int64          `json:"fee_cents"`
	IntervalMonths     int32          `json:"interval_months"`
	MonthlyCreditCents int64          `json:"monthly_credit_cents"`
	VersionID          uuid.UUID      `json:"version_id"`
	Version            int32          `json:"version"`
	Family             string         `json:"family"`
	PricingVersion     string         `json:"pricing_version"`
	Kind               string         `json:"kind"`
	Grants             []planGrant    `json:"grants"`
	Matching           *planMatching  `json:"matching"`
	Allowance          *planAllowance `json:"allowance"`
}

// freezePlanTerms keeps a compute allowance as its compute basis, not as an
// amount priced at today's rate card.
func freezePlanTerms(t planTerms) frozenPlanTerms {
	allowance := t.Allowance
	if allowance != nil && allowance.Compute != nil {
		basis := *allowance
		basis.AmountCents = 0
		basis.AmountUSD = ""
		allowance = &basis
	}
	grants := t.Grants
	if grants == nil {
		grants = []planGrant{}
	}
	return frozenPlanTerms{OfferKey: t.OfferKey, DisplayName: t.DisplayName, FeeCents: t.FeeCents, IntervalMonths: t.IntervalMonths,
		MonthlyCreditCents: t.MonthlyCreditCents, VersionID: t.VersionID, Version: t.Version, Family: t.Family, PricingVersion: t.PricingVersion, Kind: t.Kind,
		Grants: grants, Matching: t.Matching, Allowance: allowance}
}

// planAssignment asks for a team to be on a plan from now on.
type planAssignment struct {
	Team       uuid.UUID
	Terms      planTerms
	Source     string
	Actor      *uuid.UUID
	Reason     string
	ContractID *uuid.UUID
	Key        string
}

// teamPlan is one stretch of a team's plan history.
type teamPlan struct {
	ID            uuid.UUID       `json:"id"`
	TeamID        uuid.UUID       `json:"team_id"`
	PlanKey       string          `json:"plan_key"`
	Kind          string          `json:"kind"`
	VersionID     *uuid.UUID      `json:"plan_version_id"`
	Terms         frozenPlanTerms `json:"terms"`
	Limits        planLimits      `json:"limits"`
	EffectiveFrom time.Time       `json:"effective_from"`
	EffectiveTo   *time.Time      `json:"effective_to"`
	ContractID    *uuid.UUID      `json:"contract_id"`
	Source        string          `json:"source"`
	AssignedBy    *uuid.UUID      `json:"assigned_by"`
	Reason        string          `json:"reason"`
	Key           *string         `json:"idempotency_key"`
}

const teamPlanColumns = `id,team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,effective_to,contract_id,source,assigned_by,reason,idempotency_key`

func scanTeamPlan(row pgx.Row) (teamPlan, error) {
	var p teamPlan
	var terms, limits []byte
	if err := row.Scan(&p.ID, &p.TeamID, &p.PlanKey, &p.Kind, &p.VersionID, &terms, &limits, &p.EffectiveFrom, &p.EffectiveTo, &p.ContractID, &p.Source, &p.AssignedBy, &p.Reason, &p.Key); err != nil {
		return p, err
	}
	if err := json.Unmarshal(terms, &p.Terms); err != nil {
		return p, err
	}
	return p, json.Unmarshal(limits, &p.Limits)
}

// currentTeamPlan returns the plan a team is on now; ok is false for a team
// that has never been assigned one.
func currentTeamPlan(ctx context.Context, q db.DBTX, team uuid.UUID) (teamPlan, bool, error) {
	p, err := scanTeamPlan(q.QueryRow(ctx, `SELECT `+teamPlanColumns+` FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL`, team))
	if errors.Is(err, pgx.ErrNoRows) {
		return p, false, nil
	}
	return p, err == nil, err
}

func teamPlanHistory(ctx context.Context, q db.DBTX, team uuid.UUID, limit int) ([]teamPlan, error) {
	rows, err := q.Query(ctx, `SELECT `+teamPlanColumns+` FROM team_plan_assignment WHERE team_id=$1 ORDER BY effective_from DESC, created_at DESC LIMIT $2`, team, limit)
	if err != nil {
		return nil, err
	}
	plans, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (teamPlan, error) { return scanTeamPlan(row) })
	if plans == nil {
		plans = []teamPlan{}
	}
	return plans, err
}

func validPlanKind(kind string) bool {
	switch kind {
	case planKindFree, planKindPrepaid, planKindSubscription, planKindLegacyPAYG, planKindCustom:
		return true
	}
	return false
}

func (a planAssignment) validate() error {
	if a.Terms.Retired {
		return errPlanRetired
	}
	if !validPlanKind(a.Terms.Kind) || a.Terms.OfferKey == "" || a.Terms.Limits.MaxConcurrent == nil || a.Reason == "" {
		return errors.New("plan assignment needs a plan, kind, limits and reason")
	}
	return nil
}

func (a planAssignment) frozen() (terms, limits []byte, version *uuid.UUID, err error) {
	if terms, err = json.Marshal(freezePlanTerms(a.Terms)); err != nil {
		return
	}
	if limits, err = json.Marshal(a.Terms.Limits); err != nil {
		return
	}
	if a.Terms.VersionID != uuid.Nil {
		version = &a.Terms.VersionID
	}
	return
}

// assignInitialTeamPlans gives teams their first plan in one statement, for
// bulk backfills. Teams that already have a plan are left alone, so it can be
// re-run, and teams whose row is busy right now are skipped for a later pass
// rather than waited on. It returns the teams it assigned.
func assignInitialTeamPlans(ctx context.Context, tx pgx.Tx, as []planAssignment) ([]uuid.UUID, error) {
	byTeam := make(map[uuid.UUID]planAssignment, len(as))
	ids := make([]uuid.UUID, 0, len(as))
	for _, a := range as {
		if err := a.validate(); err != nil {
			return nil, err
		}
		if _, dup := byTeam[a.Team]; !dup {
			ids = append(ids, a.Team)
		}
		byTeam[a.Team] = a
	}
	rows, err := tx.Query(ctx, `SELECT t.id FROM team t WHERE t.id=ANY($1)
        AND NOT EXISTS(SELECT 1 FROM team_plan_assignment a WHERE a.team_id=t.id) FOR NO KEY UPDATE OF t SKIP LOCKED`, ids)
	if err != nil {
		return nil, err
	}
	free, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(free) == 0 {
		return nil, err
	}
	var (
		versions, contracts  []*uuid.UUID
		keys, kinds, sources []string
		reasons              []string
		terms, limits        [][]byte
		actors               []*uuid.UUID
	)
	for _, id := range free {
		a := byTeam[id]
		t, l, v, err := a.frozen()
		if err != nil {
			return nil, err
		}
		versions, contracts, actors = append(versions, v), append(contracts, a.ContractID), append(actors, a.Actor)
		keys, kinds, sources, reasons = append(keys, a.Terms.OfferKey), append(kinds, a.Terms.Kind), append(sources, a.Source), append(reasons, a.Reason)
		terms, limits = append(terms, t), append(limits, l)
	}
	rows, err = tx.Query(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,contract_id,source,assigned_by,reason)
        SELECT t,k,kd,v,tm,l,clock_timestamp(),c,s,a,r FROM unnest($1::uuid[],$2::text[],$3::text[],$4::uuid[],$5::jsonb[],$6::jsonb[],$7::uuid[],$8::text[],$9::uuid[],$10::text[]) AS x(t,k,kd,v,tm,l,c,s,a,r)
        WHERE NOT EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=x.t)
        RETURNING team_id`, free, keys, kinds, versions, terms, limits, contracts, sources, actors, reasons)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// assignTeamPlan moves a team onto a plan within tx: it closes the open
// assignment and opens the new one at the same instant, and the team takes the
// new plan's frozen limits. A repeated idempotency key returns the assignment
// it created.
func assignTeamPlan(ctx context.Context, tx pgx.Tx, a planAssignment) (teamPlan, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp() FROM team WHERE id=$1 FOR NO KEY UPDATE`, a.Team).Scan(&now); err != nil {
		return teamPlan{}, err
	}
	var key *string
	if a.Key != "" {
		key = &a.Key
		prior, err := scanTeamPlan(tx.QueryRow(ctx, `SELECT `+teamPlanColumns+` FROM team_plan_assignment WHERE team_id=$1 AND idempotency_key=$2`, a.Team, a.Key))
		if err == nil {
			if prior.PlanKey != a.Terms.OfferKey || prior.Terms.VersionID != a.Terms.VersionID || prior.Kind != a.Terms.Kind {
				return teamPlan{}, errPlanAssignmentReused
			}
			return prior, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return teamPlan{}, err
		}
	}
	if err := a.validate(); err != nil {
		return teamPlan{}, err
	}
	terms, limits, version, err := a.frozen()
	if err != nil {
		return teamPlan{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE team_plan_assignment SET effective_to=$2 WHERE team_id=$1 AND effective_to IS NULL`, a.Team, now); err != nil {
		return teamPlan{}, err
	}
	return scanTeamPlan(tx.QueryRow(ctx, `INSERT INTO team_plan_assignment(team_id,plan_key,kind,plan_version_id,terms,limits,effective_from,contract_id,source,assigned_by,reason,idempotency_key)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING `+teamPlanColumns,
		a.Team, a.Terms.OfferKey, a.Terms.Kind, version, terms, limits, now, a.ContractID, a.Source, a.Actor, a.Reason, key))
}

// GetTeamPlanAssignments shows staff the plan a team is on and its history.
func (h *Handlers) GetTeamPlanAssignments(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	if _, ok = h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	history, err := teamPlanHistory(c.Request.Context(), h.Pool, team, 50)
	if err != nil {
		log.Error().Err(err).Str("team_id", team.String()).Msg("list plan assignments failed")
		respondError(c, ErrInternal)
		return
	}
	var current *teamPlan
	if len(history) > 0 && history[0].EffectiveTo == nil {
		current = &history[0]
	}
	pending, err := pendingCustomerPlanChange(c.Request.Context(), h.Pool, team, "staff")
	if err != nil {
		log.Error().Err(err).Str("team_id", team.String()).Msg("load pending plan change failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, gin.H{"current": current, "history": history, "pending_change": pending})
}

type customerPlan struct {
	PlanKey       string     `json:"plan_key"`
	Kind          string     `json:"kind"`
	DisplayName   string     `json:"display_name"`
	Limits        planLimits `json:"limits"`
	EffectiveFrom time.Time  `json:"effective_from"`
}

type customerPendingPlanChange struct {
	ID                uuid.UUID `json:"id"`
	TargetPlanKey     string    `json:"target_plan_key"`
	TargetDisplayName string    `json:"target_display_name"`
	EffectiveAt       time.Time `json:"effective_at"`
	Undoable          bool      `json:"undoable"`
	PausesRunning     bool      `json:"pauses_running"`
}

type customerBillingPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// GetBillingPlan tells a team which plan it is on, its limits, the current
// billing period and any change waiting to take effect.
func (h *Handlers) GetBillingPlan(c *gin.Context) {
	team, ok := h.requireBillingRead(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		log.Error().Err(err).Str("team_id", team.String()).Msg("begin billing plan read failed")
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	reader := &Handlers{DB: db.New(tx)}
	current, assigned, err := currentTeamPlan(ctx, tx, team)
	var limits teamLimits
	if err == nil && assigned {
		limits, err = reader.teamEffectiveLimits(ctx, team)
	}
	var anchor pgtype.Timestamptz
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT commercial_billing_anchor FROM team_billing_account WHERE team_id=$1`, team).Scan(&anchor)
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
		}
	}
	var start, end time.Time
	if err == nil {
		start, end, err = reader.currentBillingPeriod(ctx, team, anchor, h.nowUTC())
	}
	var pending *customerPendingPlanChange
	if err == nil {
		pending, err = pendingCustomerPlanChange(ctx, tx, team, "customer")
	}
	var proCheckout customerProCheckout
	if err == nil {
		proCheckout, err = customerProCheckoutTerms(ctx, tx, team, assigned && current.Kind == planKindFree, anchor.Valid)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		log.Error().Err(err).Str("team_id", team.String()).Msg("load billing plan failed")
		respondError(c, ErrInternal)
		return
	}
	var plan *customerPlan
	if assigned {
		plan = &customerPlan{PlanKey: current.PlanKey, Kind: current.Kind, DisplayName: current.Terms.DisplayName, EffectiveFrom: current.EffectiveFrom,
			Limits: planLimits{MaxConcurrent: &limits.MaxConcurrent, MaxVCPU: &limits.MaxVCPU, MaxMemoryMiB: &limits.MaxMemoryMiB, MaxDiskMiB: &limits.MaxDiskMiB, MaxTemplates: &limits.MaxTemplates}}
	}
	c.JSON(http.StatusOK, gin.H{
		"plan":           plan,
		"period":         customerBillingPeriod{Start: start, End: end},
		"pending_change": pending,
		"pro_checkout":   proCheckout,
	})
}

// Plan change timings a preview can report.
const (
	planChangeNow           = "immediate"
	planChangeEndOfPeriod   = "end_of_billing_period"
	planChangeAfterPurchase = "after_purchase"
)

// selfServePlans are the plans a team can choose for itself.
var selfServePlans = map[string]bool{"free": true, "starter": true, "pro_monthly": true}

// planChangeRule says when a customer's move from one kind of plan to another
// takes effect, or why it is not self-serve. Upgrades wait only for payment;
// leaving a paid subscription or custom plan waits for the billing period to
// end; leaving prepaid credit for Free is immediate.
func planChangeRule(from, to string) (string, string) {
	switch {
	case from == to:
		return "", "team is already on this kind of plan"
	case to == planKindSubscription && (from == planKindFree || from == planKindPrepaid):
		return planChangeAfterPurchase, ""
	case to == planKindPrepaid && from == planKindFree:
		return planChangeAfterPurchase, ""
	case to == planKindPrepaid && from == planKindSubscription:
		return planChangeEndOfPeriod, ""
	case to == planKindFree && (from == planKindSubscription || from == planKindCustom):
		return planChangeEndOfPeriod, ""
	case to == planKindFree && from == planKindPrepaid:
		return planChangeNow, ""
	}
	return "", "this plan change is not available for the team's current plan"
}

type customerPlanChangePreview struct {
	TargetPlanKey     string     `json:"target_plan_key"`
	TargetDisplayName string     `json:"target_display_name"`
	TargetKind        string     `json:"target_kind"`
	Timing            string     `json:"timing,omitempty"`
	EffectiveAt       *time.Time `json:"effective_at,omitempty"`
	PausesRunning     bool       `json:"pauses_running"`
	Limits            planLimits `json:"limits"`
	Blocked           string     `json:"blocked,omitempty"`
	PreviewToken      string     `json:"preview_token,omitempty"`
}

// GetBillingPlanChangePreview tells a team when a move to a plan would take
// effect and the limits it would then have, or why it cannot move.
func (h *Handlers) GetBillingPlanChangePreview(c *gin.Context) {
	team, ok := h.requireBillingRead(c)
	if !ok {
		return
	}
	target := c.Query("target_plan")
	if !selfServePlans[target] {
		respondErrorMsg(c, "invalid_plan", "target_plan must be free, starter or pro_monthly", http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	terms, err := h.planTermsForPricingVersion(ctx, target, "v2")
	if errors.Is(err, errUnknownPlan) {
		respondErrorMsg(c, "invalid_plan", "this plan is not available", http.StatusBadRequest)
		return
	}
	var current teamPlan
	var assigned bool
	var pricing pricingPublicState
	if err == nil {
		pricing, err = h.publicPricingState(ctx)
	}
	if err == nil {
		current, assigned, err = currentTeamPlan(ctx, h.Pool, team)
	}
	if err != nil {
		log.Error().Err(err).Str("team_id", team.String()).Msg("plan change preview failed")
		respondError(c, ErrInternal)
		return
	}
	kind := terms.Kind
	preview := customerPlanChangePreview{TargetPlanKey: target, TargetDisplayName: terms.DisplayName, TargetKind: kind, Limits: terms.Limits}
	switch {
	case !assigned:
		preview.Blocked = "plan changes are not available for this team yet"
	case terms.Retired:
		preview.Blocked = "this plan is no longer offered"
	default:
		preview.Timing, preview.Blocked = planChangeRule(current.Kind, kind)
		if !pricing.EntryOpen && preview.Timing == planChangeAfterPurchase {
			preview.Timing, preview.Blocked = "", "new plans are not available yet"
		}
	}
	if preview.Blocked == "" && kind == planKindFree {
		ready, err := planChangePausesReady(ctx, h.Pool)
		if err != nil {
			log.Error().Err(err).Str("team_id", team.String()).Msg("plan change preview failed")
			respondError(c, ErrInternal)
			return
		}
		if !ready {
			preview.Blocked = planChangePausesUnavailable
		}
	}
	if preview.Blocked == "" {
		preview.PausesRunning = kind == planKindFree
		at := h.nowUTC()
		if preview.Timing == planChangeEndOfPeriod {
			_, at, err = h.planChangeBoundary(ctx, team, current, at)
			if err != nil {
				var conflict teamPlanChangeConflictError
				if errors.As(err, &conflict) {
					preview.Timing, preview.Blocked = "", conflict.reason
					c.JSON(http.StatusOK, preview)
					return
				}
				log.Error().Err(err).Str("team_id", team.String()).Msg("plan change preview failed")
				respondError(c, ErrInternal)
				return
			}
		}
		if preview.Timing != planChangeAfterPurchase {
			preview.EffectiveAt = &at
			preview.PreviewToken, err = planChangeConsentToken(current, terms, preview.Timing, at)
			if err != nil {
				log.Error().Err(err).Str("team_id", team.String()).Msg("plan change preview failed")
				respondError(c, ErrInternal)
				return
			}
		}
	} else {
		preview.Timing = ""
	}
	c.JSON(http.StatusOK, preview)
}

type staffPlanAssignmentBody struct {
	Key       string    `json:"idempotency_key"`
	VersionID uuid.UUID `json:"version_id"`
	Reason    string    `json:"reason"`
}

// AssignTeamPlan lets staff put a team on a custom plan version, such as an
// Enterprise arrangement. The team needs no billing account or Stripe
// customer. Fresh assignments wait until any paid authority or billing
// transition has been resolved; accepted requests remain replayable.
func (h *Handlers) AssignTeamPlan(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	var body staffPlanAssignmentBody
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF || body.VersionID == uuid.Nil {
		respondErrorMsg(c, "bad_request", "idempotency_key, version_id and reason are required", http.StatusBadRequest)
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if strings.TrimSpace(body.Key) == "" || utf8.RuneCountInString(body.Key) > 200 || body.Reason == "" || utf8.RuneCountInString(body.Reason) > 2000 {
		respondErrorMsg(c, "bad_request", "idempotency_key, version_id and reason are required", http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	plan, err := h.assignStaffPlan(ctx, team, actor, body)
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, errStaffPlanAuthority):
		respondErrorMsg(c, "conflict", "resolve the existing paid plan or billing transition before assigning a custom plan", http.StatusConflict)
	case errors.Is(err, errPricingV2Off):
		respondErrorMsg(c, "conflict", "plan assignment is not available yet", http.StatusConflict)
	case errors.Is(err, errUnknownPlan):
		respondErrorMsg(c, "invalid_plan", "version_id must be a published custom plan version without fees", http.StatusBadRequest)
	case errors.Is(err, errPlanRetired):
		respondErrorMsg(c, "conflict", "this plan version is retired", http.StatusConflict)
	case errors.Is(err, errPlanAssignmentReused):
		respondErrorMsg(c, "conflict", "idempotency key was used for a different plan assignment", http.StatusConflict)
	case errors.Is(err, pgx.ErrNoRows), errors.As(err, &pgErr) && pgErr.Code == "23503":
		respondErrorMsg(c, "not_found", "team not found", http.StatusNotFound)
	case err != nil:
		log.Error().Err(err).Str("team_id", team.String()).Msg("staff plan assignment failed")
		respondErrorMsg(c, "unavailable", "the plan could not be assigned; retry with the same request", http.StatusServiceUnavailable)
	default:
		c.JSON(http.StatusOK, plan)
	}
}

var errPricingV2Off = errors.New("pricing v2 is off")
var errStaffPlanAuthority = errors.New("existing commercial authority or unresolved billing transition")

func (h *Handlers) assignStaffPlan(ctx context.Context, team, actor uuid.UUID, body staffPlanAssignmentBody) (teamPlan, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return teamPlan{}, err
	}
	defer tx.Rollback(ctx)
	version, entryOpen, err := lockPricingEntry(ctx, tx)
	if err != nil {
		return teamPlan{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
		return teamPlan{}, err
	}
	prior, err := scanTeamPlan(tx.QueryRow(ctx, `SELECT `+teamPlanColumns+` FROM team_plan_assignment WHERE team_id=$1 AND idempotency_key=$2`, team, body.Key))
	if err == nil {
		if prior.VersionID == nil || *prior.VersionID != body.VersionID || prior.Source != planSourceStaff {
			return teamPlan{}, errPlanAssignmentReused
		}
		return prior, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return teamPlan{}, err
	}
	if version != "v2" || !entryOpen {
		return teamPlan{}, errPricingV2Off
	}
	// The team lock also fences checkout activation and plan-change workers.
	// Replay above remains valid even after later commercial commitments.
	var blocked bool
	if err = tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND status<>'ended')
 OR EXISTS(SELECT 1 FROM team_plan_assignment WHERE team_id=$1 AND effective_to IS NULL AND kind='subscription')
 OR EXISTS(SELECT 1 FROM billing_pro_upgrade WHERE team_id=$1 AND state NOT IN ('expired','ended'))
 OR EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=$1 AND state='pending' AND offer_key<>'free')
 OR EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND (checkout_initializing_at IS NOT NULL OR checkout_may_exist))
 OR EXISTS(SELECT 1 FROM billing_yc_operation WHERE team_id=$1 AND state<>'ended')
 OR EXISTS(SELECT 1 FROM yc_claim_team_intent WHERE team_id=$1 AND released_at IS NULL)
 OR EXISTS(SELECT 1 FROM billing_sponsored_operation WHERE team_id=$1 AND state NOT IN ('revoked','expired'))
 OR EXISTS(SELECT 1 FROM billing_prepaid_purchase WHERE team_id=$1 AND (payment_state IN ('pending','uncertain','processing') OR credit_state IN ('pending','uncertain')))
 OR EXISTS(SELECT 1 FROM team_plan_change WHERE team_id=$1 AND (state IN ('scheduled','applied') OR (state='undone' AND subscription_id IS NOT NULL AND provider_renewed_at IS NULL)))`, team).Scan(&blocked); err != nil {
		return teamPlan{}, err
	}
	if blocked {
		return teamPlan{}, errStaffPlanAuthority
	}
	catalogVersion, err := scanPlanVersion(tx.QueryRow(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1 AND state<>'draft' FOR SHARE`, body.VersionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return teamPlan{}, errUnknownPlan
	}
	if err != nil {
		return teamPlan{}, err
	}
	catalog := &Handlers{DB: db.New(tx)}
	terms, err := catalog.termsOfVersion(ctx, catalogVersion, 0)
	if err != nil {
		return teamPlan{}, err
	}
	if terms.Kind != planKindCustom || terms.Limits.MaxConcurrent == nil {
		return teamPlan{}, errUnknownPlan
	}
	plan, err := assignTeamPlan(ctx, tx, planAssignment{Team: team, Terms: terms, Source: planSourceStaff, Actor: &actor, Reason: body.Reason, Key: body.Key})
	if err != nil {
		return plan, err
	}
	return plan, tx.Commit(ctx)
}
