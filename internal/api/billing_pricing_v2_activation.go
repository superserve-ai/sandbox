package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

const (
	activationTargetFree       = "free"
	activationTargetLegacyPAYG = "legacy_payg"
	activationTargetContract   = "contract"
	activationCreditReads      = 8
	activationCreditReadCap    = 200
	activationCreditBudget     = 20 * time.Second
	activationSource           = "migration"
)

var ErrPricingV2Off = errors.New("pricing v2 is off in this region")

type PricingV2Activation struct {
	h *Handlers
}

func NewPricingV2Activation(pool *pgxpool.Pool, stripe StripeBillingClient, region, systemTeamID string) *PricingV2Activation {
	return &PricingV2Activation{h: &Handlers{Pool: pool, DB: db.New(pool), Stripe: stripe,
		Config: &config.Config{TeamCreationRegion: region, SystemTeamID: systemTeamID}}}
}

type activationTeam struct {
	TeamID      uuid.UUID
	Bucket      string
	Target      string
	Reason      string
	CreditCents *int64
}

type ActivationTeam struct {
	TeamID      uuid.UUID `json:"team_id"`
	Reason      string    `json:"reason,omitempty"`
	CreditCents *int64    `json:"credit_cents,omitempty"`
}

type ActivationReport struct {
	Adoption            *PricingAdoptionState     `json:"adoption"`
	DeferredObligations []PricingAdoptionResidual `json:"deferred_obligations"`
	ResidualCount       int                       `json:"residual_unassigned_count"`
	ResidualUnassigned  []PricingAdoptionResidual `json:"residual_unassigned"`
	Region              string                    `json:"region"`
	PricingVersion      string                    `json:"pricing_version"`
	AsOf                time.Time                 `json:"as_of"`
	ToFree              int                       `json:"to_free"`
	ToContract          int                       `json:"to_contract"`
	ToLegacyPAYG        int                       `json:"to_legacy_payg"`
	BlockedToFree       []ActivationTeam          `json:"blocked_to_free"`
	LapsedWithCredit    []ActivationTeam          `json:"lapsed_with_credit"`
	LapsedNoCredit      []ActivationTeam          `json:"lapsed_no_credit"`
	LapsedUnchecked     []ActivationTeam          `json:"lapsed_unchecked"`
	AlreadyAssigned     int                       `json:"already_assigned"`
	Skipped             []ActivationTeam          `json:"skipped"`
	SkippedReasons      map[string]int            `json:"skipped_reasons"`
	Pending             int                       `json:"pending"`
	CreditReads         int                       `json:"credit_reads"`
	ElapsedMS           int64                     `json:"elapsed_ms"`
}

type ActivationCursor struct {
	Lapsed bool      `json:"lapsed"`
	TeamID uuid.UUID `json:"team_id"`
}

type ActivationBatch struct {
	Next               *ActivationCursor `json:"next,omitempty"`
	AssignedFree       int               `json:"assigned_free"`
	AssignedContract   int               `json:"assigned_contract"`
	AssignedLegacyPAYG int               `json:"assigned_legacy_payg"`
	Deferred           int               `json:"deferred"`
	Remaining          int               `json:"remaining"`
	Assigned           []uuid.UUID       `json:"assigned"`
}

func (h *Handlers) resolveActivationTeams(ctx context.Context, rows []db.ListPricingV2ActivationBucketsRow) ([]activationTeam, int) {
	teams := make([]activationTeam, len(rows))
	reader, _ := h.Stripe.(stripeCreditBalanceReader)
	ctx, cancel := context.WithTimeout(ctx, activationCreditBudget)
	defer cancel()
	sem := make(chan struct{}, activationCreditReads)
	var wg sync.WaitGroup
	reads := 0
	for i, row := range rows {
		teams[i] = activationTeam{TeamID: row.TeamID, Bucket: row.Bucket, Reason: row.Reason}
		switch row.Bucket {
		case activationTargetFree, activationTargetLegacyPAYG, activationTargetContract:
			teams[i].Target = row.Bucket
		case "blocked":
			teams[i].Target = activationTargetFree
		case "lapsed":
			if row.StripeCustomerID == "" {
				teams[i].Target, teams[i].Reason = activationTargetFree, "lapsed_no_credit"
				teams[i].CreditCents = new(int64)
				continue
			}
			if reader == nil {
				teams[i].Reason = "credit_unknown"
				continue
			}
			if reads >= activationCreditReadCap {
				teams[i].Reason = "lapsed_unchecked"
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				teams[i].Reason = "lapsed_unchecked"
				continue
			}
			reads++
			wg.Add(1)
			go func(t *activationTeam, customer string) {
				defer wg.Done()
				defer func() { <-sem }()
				balance, err := reader.GetCustomerCreditBalance(ctx, customer)
				if err != nil {
					log.Warn().Err(err).Str("team_id", t.TeamID.String()).Msg("billing: pricing v2 activation credit read failed")
					t.Reason = "credit_unknown"
					return
				}
				cents := int64(math.Round(balance.AvailableUSD * 100))
				t.CreditCents = &cents
				if cents > 0 {
					t.Target, t.Reason = activationTargetLegacyPAYG, "lapsed_with_credit"
				} else {
					t.Target, t.Reason = activationTargetFree, "lapsed_no_credit"
				}
			}(&teams[i], row.StripeCustomerID)
		}
	}
	wg.Wait()
	return teams, reads
}

func summarizeActivation(region string, asOf time.Time, teams []activationTeam) ActivationReport {
	r := ActivationReport{Region: region, AsOf: asOf, SkippedReasons: map[string]int{}, Skipped: []ActivationTeam{},
		BlockedToFree: []ActivationTeam{}, LapsedWithCredit: []ActivationTeam{}, LapsedNoCredit: []ActivationTeam{}, LapsedUnchecked: []ActivationTeam{}}
	for _, t := range teams {
		listed := ActivationTeam{TeamID: t.TeamID, Reason: t.Reason, CreditCents: t.CreditCents}
		switch {
		case t.Target == activationTargetFree:
			r.ToFree++
		case t.Target == activationTargetLegacyPAYG:
			r.ToLegacyPAYG++
		case t.Target == activationTargetContract:
			r.ToContract++
		case t.Bucket == "assigned":
			r.AlreadyAssigned++
		case t.Reason == "lapsed_unchecked":
			r.LapsedUnchecked = append(r.LapsedUnchecked, listed)
		default:
			r.Skipped = append(r.Skipped, listed)
			r.SkippedReasons[t.Reason]++
		}
		switch {
		case t.Bucket == "blocked":
			r.BlockedToFree = append(r.BlockedToFree, listed)
		case t.Reason == "lapsed_with_credit":
			r.LapsedWithCredit = append(r.LapsedWithCredit, listed)
		case t.Reason == "lapsed_no_credit":
			r.LapsedNoCredit = append(r.LapsedNoCredit, listed)
		}
	}
	r.Pending = r.ToFree + r.ToLegacyPAYG + r.ToContract + len(r.LapsedUnchecked) + r.SkippedReasons["credit_unknown"]
	return r
}

func (a *PricingV2Activation) Report(ctx context.Context) (ActivationReport, error) {
	h := a.h
	started := time.Now()
	version, err := h.DB.GetPricingVersion(ctx)
	if err != nil {
		return ActivationReport{}, err
	}
	rows, err := h.DB.ListPricingV2ActivationBuckets(ctx, db.ListPricingV2ActivationBucketsParams{
		Region: h.Config.TeamCreationRegion, SystemTeamID: h.systemTeamID(),
	})
	if err != nil {
		return ActivationReport{}, err
	}
	teams, reads := h.resolveActivationTeams(ctx, rows)
	r := summarizeActivation(h.Config.TeamCreationRegion, time.Now().UTC(), teams)
	r.PricingVersion, r.CreditReads, r.ElapsedMS = version, reads, time.Since(started).Milliseconds()
	if err := a.adoptionReport(ctx, &r); err != nil {
		return ActivationReport{}, err
	}
	return r, nil
}

func (a *PricingV2Activation) ApplyBatch(ctx context.Context, actor, reason string, size int32) (ActivationBatch, error) {
	return a.ApplyBatchAfter(ctx, actor, reason, size, nil)
}

func (a *PricingV2Activation) ApplyBatchAfter(ctx context.Context, actor, reason string, size int32, after *ActivationCursor) (ActivationBatch, error) {
	h := a.h
	if system, err := uuid.Parse(h.Config.SystemTeamID); err != nil || system == uuid.Nil {
		return ActivationBatch{}, errors.New("apply requires a valid nonzero SYSTEM_TEAM_ID")
	}
	if actor == "" || reason == "" {
		return ActivationBatch{}, errors.New("an actor and a reason are required")
	}
	version, err := h.DB.GetPricingVersion(ctx)
	if err != nil {
		return ActivationBatch{}, err
	}
	if version != "v2" {
		return ActivationBatch{}, ErrPricingV2Off
	}
	if _, err := a.PrepareAdoption(ctx, actor, reason); err != nil {
		return ActivationBatch{}, err
	}
	free, payg, err := a.activationTerms(ctx)
	if err != nil {
		return ActivationBatch{}, err
	}
	params := db.ListPricingV2ActivationPendingParams{Region: h.Config.TeamCreationRegion, SystemTeamID: h.systemTeamID(), BatchLimit: min(size, activationCreditReadCap)}
	if after != nil {
		params.AfterLapsed, params.AfterTeamID = after.Lapsed, after.TeamID
	}
	pending, err := h.DB.ListPricingV2ActivationPending(ctx, params)
	if err != nil {
		return ActivationBatch{}, err
	}
	rows := make([]db.ListPricingV2ActivationBucketsRow, len(pending))
	for i, p := range pending {
		rows[i] = db.ListPricingV2ActivationBucketsRow(p)
	}
	teams, _ := h.resolveActivationTeams(ctx, rows)

	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return ActivationBatch{}, err
	}
	defer tx.Rollback(ctx)
	if err := tx.QueryRow(ctx, `SELECT pricing_version FROM billing_pricing_switch FOR SHARE`).Scan(&version); err != nil {
		return ActivationBatch{}, err
	}
	if version != "v2" {
		return ActivationBatch{}, ErrPricingV2Off
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM billing_pricing_adoption WHERE singleton FOR UPDATE`); err != nil {
		return ActivationBatch{}, err
	}
	ids := make([]uuid.UUID, len(teams))
	for i, t := range teams {
		ids[i] = t.TeamID
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '2s'`); err != nil {
		return ActivationBatch{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=ANY($1) ORDER BY team_id FOR UPDATE`, ids); err != nil {
		return ActivationBatch{}, err
	}
	locked, err := tx.Query(ctx, `SELECT id FROM team WHERE id = ANY($1) ORDER BY id FOR UPDATE SKIP LOCKED`, ids)
	if err != nil {
		return ActivationBatch{}, err
	}
	ids, err = pgx.CollectRows(locked, pgx.RowTo[uuid.UUID])
	if err != nil {
		return ActivationBatch{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=ANY($1) ORDER BY team_id FOR UPDATE`, ids); err != nil {
		return ActivationBatch{}, err
	}
	current := map[uuid.UUID]db.ListPricingV2ActivationBucketsRow{}
	recheck, err := tx.Query(ctx, `SELECT x.id, b.bucket, COALESCE(b.stripe_customer_id, '') FROM unnest($1::uuid[]) x(id) CROSS JOIN LATERAL pricing_v2_activation_bucket(x.id) b`, ids)
	if err != nil {
		return ActivationBatch{}, err
	}
	for recheck.Next() {
		var id uuid.UUID
		var row db.ListPricingV2ActivationBucketsRow
		if err := recheck.Scan(&id, &row.Bucket, &row.StripeCustomerID); err != nil {
			recheck.Close()
			return ActivationBatch{}, err
		}
		current[id] = row
	}
	if err := recheck.Err(); err != nil {
		return ActivationBatch{}, err
	}
	var unknownIDs []uuid.UUID
	var unknownReasons []string
	for i, team := range teams {
		if current[team.TeamID].Bucket != team.Bucket || current[team.TeamID].StripeCustomerID != rows[i].StripeCustomerID {
			continue
		}
		if team.Reason == "credit_unknown" || team.Reason == "lapsed_unchecked" {
			unknownIDs = append(unknownIDs, team.TeamID)
			unknownReasons = append(unknownReasons, team.Reason)
		}
	}
	if len(unknownIDs) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO billing_pricing_adoption_credit_hold(team_id,reason)
 SELECT * FROM unnest($1::uuid[],$2::text[]) ON CONFLICT(team_id) DO UPDATE SET reason=EXCLUDED.reason,observed_at=clock_timestamp()`, unknownIDs, unknownReasons); err != nil {
			return ActivationBatch{}, err
		}
	}
	var batch ActivationBatch
	if len(pending) == int(params.BatchLimit) && len(pending) > 0 {
		last := pending[len(pending)-1]
		batch.Next = &ActivationCursor{Lapsed: last.Bucket == "lapsed", TeamID: last.TeamID}
	}
	var as []planAssignment
	target := map[uuid.UUID]string{}
	for i, t := range teams {
		if t.Target == "" || current[t.TeamID].Bucket != t.Bucket || current[t.TeamID].StripeCustomerID != rows[i].StripeCustomerID {
			batch.Deferred++
			continue
		}
		terms := free
		if t.Target == activationTargetLegacyPAYG {
			terms = payg
		}
		assignment := planAssignment{Team: t.TeamID, Terms: terms, Source: activationSource, Reason: reason}
		if t.Target == activationTargetContract {
			assignment, err = activationContractAssignment(ctx, tx, t.TeamID, reason)
			if errors.Is(err, pgx.ErrNoRows) {
				batch.Deferred++
				continue
			}
			if err != nil {
				return ActivationBatch{}, err
			}
		}
		target[t.TeamID] = t.Target
		as = append(as, assignment)
	}
	if len(as) > 0 {
		if batch.Assigned, err = assignInitialTeamPlans(ctx, tx, as); err != nil {
			return ActivationBatch{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO billing_pricing_adoption_credit_resolution(team_id,assignment_id,source)
 SELECT pa.team_id,pa.id,billing_pricing_adoption_credit_source(pa.team_id) FROM team_plan_assignment pa
 WHERE pa.team_id=ANY($1) AND pa.effective_to IS NULL ON CONFLICT(team_id) DO UPDATE
 SET assignment_id=EXCLUDED.assignment_id,source=EXCLUDED.source,verified_at=clock_timestamp()`, batch.Assigned); err != nil {
		return ActivationBatch{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM billing_pricing_adoption_credit_hold WHERE team_id=ANY($1)`, batch.Assigned); err != nil {
		return ActivationBatch{}, err
	}
	for _, id := range batch.Assigned {
		if target[id] == activationTargetContract {
			batch.AssignedContract++
		} else if target[id] == activationTargetLegacyPAYG {
			batch.AssignedLegacyPAYG++
		} else {
			batch.AssignedFree++
			if _, err := requestTeamPauseAll(ctx, db.New(tx), id, teamPauseReasonPlanSwitchFree); err != nil {
				return ActivationBatch{}, err
			}
		}
	}
	batch.Deferred += len(as) - len(batch.Assigned)
	if batch.Assigned == nil {
		batch.Assigned = []uuid.UUID{}
	}
	audit, err := json.Marshal(map[string]any{"actor": actor, "reason": reason, "region": h.Config.TeamCreationRegion,
		"assigned_contract": batch.AssignedContract, "assigned_free": batch.AssignedFree, "assigned_legacy_payg": batch.AssignedLegacyPAYG, "teams": batch.Assigned})
	if err != nil {
		return ActivationBatch{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(event_type,new_value) VALUES('billing.pricing_v2.activation_applied',$1)`, audit); err != nil {
		return ActivationBatch{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ActivationBatch{}, err
	}
	remaining, err := h.DB.CountPricingV2ActivationPending(ctx, db.CountPricingV2ActivationPendingParams{
		Region: params.Region, SystemTeamID: params.SystemTeamID})
	if err != nil {
		return batch, err
	}
	batch.Remaining = int(remaining)
	if _, err := a.CaptureAdoption(ctx, actor, reason); err != nil {
		return ActivationBatch{}, err
	}
	return batch, nil
}

func (a *PricingV2Activation) activationTerms(ctx context.Context) (free, payg planTerms, err error) {
	forgetPricingVersion()
	free, err = a.h.planTerms(ctx, "free")
	if err != nil {
		return free, payg, fmt.Errorf("Free plan terms: %w", err)
	}
	if free.PricingVersion != "v2" || free.Kind != planKindFree {
		return free, payg, ErrPricingV2Off
	}
	payg, err = a.h.planTerms(ctx, "payg")
	return free, payg, err
}

func activationContractAssignment(ctx context.Context, tx pgx.Tx, team uuid.UUID, reason string) (planAssignment, error) {
	var contractID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM billing_commercial_contract WHERE team_id=$1 AND status='active' FOR SHARE`, team).Scan(&contractID); err != nil {
		return planAssignment{}, err
	}
	q := db.New(tx)
	c, err := q.GetCurrentCommercialContract(ctx, team)
	if err != nil {
		return planAssignment{}, err
	}
	terms := planTerms{OfferKey: c.OfferKey, DisplayName: c.OfferKey, Kind: planKindCustom,
		FeeCents: c.ChargeAmountCents, IntervalMonths: c.ChargeIntervalMonths,
		MonthlyCreditCents: c.EntitlementAmountCents, Grants: []planGrant{}}
	if c.ChargeKind == "subscription" {
		terms.Kind = planKindSubscription
	}
	family, _, ok := planOfferInterval(c.OfferKey)
	if ok {
		terms.Family = family
	} else {
		terms.Family = c.OfferKey
	}
	var limits []byte
	if err := tx.QueryRow(ctx, `SELECT CASE WHEN l.contract_id IS NOT NULL THEN
        jsonb_build_object('max_concurrent',l.max_sandboxes,'max_vcpu',l.max_template_vcpu,
          'max_memory_mib',l.max_template_memory_mib,'max_disk_mib',l.max_template_disk_mib,'max_templates',l.max_templates)
        ELSE jsonb_build_object('max_concurrent',e.max_concurrent,'max_vcpu',e.max_vcpu,
          'max_memory_mib',e.max_memory_mib,'max_disk_mib',e.max_disk_mib,'max_templates',e.max_templates) END
        FROM team_effective_limits($1) e LEFT JOIN billing_contract_limits l ON l.contract_id=$2`, team, contractID).Scan(&limits); err != nil {
		return planAssignment{}, err
	}
	if err := json.Unmarshal(limits, &terms.Limits); err != nil {
		return planAssignment{}, err
	}
	if c.EntitlementCadence == "monthly" {
		terms.Grants = append(terms.Grants, planGrant{EveryMonths: 1, AmountCents: c.EntitlementAmountCents, ExpiresAfterMonths: 1})
	} else {
		terms.MonthlyCreditCents = 0
		schedule, err := q.ListCommercialEntitlementSchedule(ctx, db.ListCommercialEntitlementScheduleParams{TeamID: team, ContractID: contractID})
		if err != nil {
			return planAssignment{}, err
		}
		for _, period := range schedule {
			repeat := int32(1)
			terms.Grants = append(terms.Grants, planGrant{StartMonths: period.MonthOffset, Repeat: &repeat,
				EveryMonths: 1, AmountCents: period.AmountCents, ExpiresAfterMonths: 1})
		}
	}
	return planAssignment{Team: team, Terms: terms, Source: activationSource, Reason: reason, ContractID: &contractID}, nil
}
