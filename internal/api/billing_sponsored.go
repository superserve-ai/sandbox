package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type sponsoredPhase struct {
	Periods int   `json:"periods"`
	Amount  int64 `json:"amount_cents"`
}
type sponsoredRequest struct {
	Key       string           `json:"idempotency_key"`
	Schedule  []sponsoredPhase `json:"schedule"`
	Start     string           `json:"start"`
	Reason    string           `json:"reason"`
	Reference string           `json:"reference"`
}

func (r sponsoredRequest) amounts() ([]int64, error) {
	if strings.TrimSpace(r.Key) == "" || len(r.Key) > 200 || r.Start != "now" || strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 2000 || strings.TrimSpace(r.Reference) == "" || len(r.Reference) > 2000 || len(r.Schedule) == 0 || len(r.Schedule) > 24 {
		return nil, errors.New("idempotency_key, start=now, reason, reference and a bounded monthly schedule are required")
	}
	var amounts []int64
	for _, p := range r.Schedule {
		if p.Periods < 1 || p.Periods > 24 || len(amounts)+p.Periods > 24 || p.Amount < 1 || p.Amount > 100000000 {
			return nil, errors.New("schedule supports at most 24 months and 1 to 100000000 USD cents per month")
		}
		for i := 0; i < p.Periods; i++ {
			amounts = append(amounts, p.Amount)
		}
	}
	return amounts, nil
}

type sponsoredOperation struct {
	ID, Team, Contract                                                  uuid.UUID
	Request                                                             sponsoredRequest
	Params                                                              StripeCreateCheckoutSessionParams
	Customer, Subscription, State, CustomerName                         string
	Start                                                               time.Time
	Anchor, PeriodStart, End, CustomerAttempt, ProviderAttempt, Revoked pgtype.Timestamptz
}

func (h *Handlers) sponsoredOperation(ctx context.Context, id uuid.UUID) (sponsoredOperation, error) {
	var o sponsoredOperation
	var request, terms []byte
	err := h.Pool.QueryRow(ctx, `SELECT id,team_id,contract_id,request,resource_terms,COALESCE(customer_id,''),COALESCE(subscription_id,''),state,resolved_start,anchor,starts_at,ends_at,customer_attempt_at,provider_attempt_at,revoked_at,customer_name FROM billing_sponsored_operation WHERE id=$1`, id).Scan(&o.ID, &o.Team, &o.Contract, &request, &terms, &o.Customer, &o.Subscription, &o.State, &o.Start, &o.Anchor, &o.PeriodStart, &o.End, &o.CustomerAttempt, &o.ProviderAttempt, &o.Revoked, &o.CustomerName)
	if err != nil {
		return o, err
	}
	if err = json.Unmarshal(request, &o.Request); err != nil {
		return o, err
	}
	err = json.Unmarshal(terms, &o.Params)
	return o, err
}
func (h *Handlers) SponsoredPreflight(c *gin.Context) { h.sponsoredApply(c, false) }
func (h *Handlers) SponsoredApply(c *gin.Context)     { h.sponsoredApply(c, true) }
func (h *Handlers) sponsoredLocalPreflight(ctx context.Context, q db.DBTX, team uuid.UUID) error {
	var region string
	if err := q.QueryRow(ctx, `SELECT home_region FROM team WHERE id=$1`, team).Scan(&region); err != nil {
		return err
	}
	if h.Config == nil || region == "" || region != h.Config.TeamCreationRegion {
		return errors.New("sponsorship must be approved in the team's home billing region")
	}
	var conflict bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1 AND status<>'ended')
 OR EXISTS(SELECT 1 FROM billing_sponsored_operation o WHERE o.team_id=$1 AND (o.state NOT IN ('revoked','expired') OR EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.sponsorship_id=o.id AND e.period_end>clock_timestamp())))
 OR EXISTS(SELECT 1 FROM billing_yc_operation WHERE team_id=$1 AND NOT billing_yc_released($1))
 OR EXISTS(SELECT 1 FROM billing_signup_choice WHERE team_id=$1 AND state<>'selecting' AND offer_key IN ('pro_monthly','pro_annual'))
 OR EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND (checkout_initializing_at IS NOT NULL OR checkout_may_exist))`, team).Scan(&conflict)
	if err != nil {
		return err
	}
	if conflict {
		return errors.New("existing contract, sponsorship, or checkout conflicts")
	}
	return nil
}
func (h *Handlers) sponsoredApply(c *gin.Context, apply bool) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	var input sponsoredRequest
	if c.ShouldBindJSON(&input) != nil {
		respondErrorMsg(c, "bad_request", "invalid sponsorship", 400)
		return
	}
	amounts, err := input.amounts()
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), 400)
		return
	}
	actor, actorOK := c.Get("actor_id")
	if apply && !actorOK {
		respondErrorMsg(c, "bad_request", "X-Actor-User-Id is required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	request, _ := json.Marshal(input)
	var existing uuid.UUID
	var same bool
	err = h.Pool.QueryRow(ctx, `SELECT id,request=$3::jsonb FROM billing_sponsored_operation WHERE team_id=$1 AND idempotency_key=$2`, team, input.Key, request).Scan(&existing, &same)
	if err == nil {
		if !same {
			respondErrorMsg(c, "conflict", "idempotency key already has different terms", 409)
			return
		}
		h.sponsoredStatus(c, team, existing)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		respondError(c, ErrInternal)
		return
	}
	conflicts := []string{}
	if err = h.sponsoredLocalPreflight(ctx, h.Pool, team); err != nil {
		conflicts = append(conflicts, err.Error())
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		respondErrorMsg(c, "unavailable", "billing provider unavailable", 503)
		return
	}
	var identity []byte
	var customer, subscription string
	var anchor pgtype.Timestamptz
	err = h.Pool.QueryRow(ctx, `SELECT jsonb_build_object('team_id',t.id,'name',t.name,'home_region',t.home_region,'members',COALESCE((SELECT jsonb_agg(jsonb_build_object('user_id',m.profile_id,'email',p.email)) FROM team_member m LEFT JOIN profile p ON p.id=m.profile_id WHERE m.team_id=t.id),'[]'::jsonb)),COALESCE(a.stripe_customer_id,''),COALESCE(a.stripe_subscription_id,''),a.commercial_billing_anchor FROM team t LEFT JOIN team_billing_account a ON a.team_id=t.id WHERE t.id=$1`, team).Scan(&identity, &customer, &subscription, &anchor)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if anchor.Valid && subscription == "" {
		conflicts = append(conflicts, "existing anniversary has no aligned usage subscription; reconcile billing setup before sponsorship")
	}
	if customer != "" {
		debt, e := client.entitlementDebt(ctx, customer)
		if e != nil || debt != "" {
			conflicts = append(conflicts, "existing debt or incomplete debt observation blocks sponsorship")
		}
	}
	prices := []string{}
	for _, r := range h.billingResourceStates(true) {
		if r.SubscriptionIncluded() {
			prices = append(prices, r.StripePriceID)
		}
	}
	terms, err := h.freezeProResourceTerms(ctx, team, prices, client)
	if err == nil {
		err = validateEntitlementResourceTerms(terms, "", "", "", false)
	}
	if err != nil {
		conflicts = append(conflicts, err.Error())
	}
	params := StripeCreateCheckoutSessionParams{ResourceTerms: terms}
	frozen, _ := json.Marshal(params)
	var historicalConflict bool
	if err = h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_sponsored_operation o JOIN billing_commercial_contract c ON c.id=o.contract_id WHERE o.team_id=$1 AND o.subscription_id=$2 AND o.resource_terms<>$3::jsonb)`, team, subscription, frozen).Scan(&historicalConflict); err != nil {
		respondError(c, ErrInternal)
		return
	}
	if historicalConflict {
		conflicts = append(conflicts, "resource terms differ from historical sponsorship on this subscription; explicit billing migration required")
	}
	if subscription != "" {
		sub, e := client.invoiceSubscription(ctx, subscription)
		var rounding string
		if e == nil {
			e = h.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT adjustment_price_id FROM billing_invoice_account WHERE team_id=$1),'')`, team).Scan(&rounding)
		}
		if e == nil && (sub.Customer != customer || sub.Status != "active" || !anchor.Valid || sub.BillingCycleAnchor != anchor.Time.Unix()) {
			e = errors.New("existing billing association or anniversary differs")
		}
		if e == nil {
			e = validateFrozenProResources(sub, terms, rounding)
			if e == nil {
				e = invoiceCalendarCompatible(anchor.Time, sub, rounding)
			}
		}
		if e != nil {
			conflicts = append(conflicts, e.Error())
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	previewAnchor := now
	if anchor.Valid {
		previewAnchor = anchor.Time
	}
	start, end, ok := billing.AnniversaryPeriod(previewAnchor, now)
	if !ok {
		respondErrorMsg(c, "conflict", "billing anniversary unavailable", 409)
		return
	}
	periods := []gin.H{}
	cursor := start
	for i, amount := range amounts {
		s, e, _ := billing.AnniversaryPeriod(previewAnchor, cursor)
		periods = append(periods, gin.H{"month_offset": i, "amount_cents": amount, "start": s, "end": e})
		cursor = e
	}
	if !apply {
		var capacity struct {
			MaxObservedTeams      int64 `json:"max_observed_teams"`
			ObservedTeams         int64 `json:"observed_teams"`
			TargetAlreadyObserved bool  `json:"target_already_observed"`
			Available             bool  `json:"available"`
		}
		err = h.Pool.QueryRow(ctx, `SELECT max_observed_teams,
          (SELECT count(*) FROM billing_funding_account WHERE observe),
          COALESCE((SELECT observe FROM billing_funding_account WHERE team_id=$1),false)
          FROM billing_funding_policy WHERE singleton`, team).Scan(&capacity.MaxObservedTeams, &capacity.ObservedTeams, &capacity.TargetAlreadyObserved)
		if err != nil {
			respondError(c, ErrInternal)
			return
		}
		capacity.Available = capacity.TargetAlreadyObserved || capacity.ObservedTeams < capacity.MaxObservedTeams
		if !capacity.Available {
			conflicts = append(conflicts, "funding observation cohort is at capacity")
		}
		var snapshot []byte
		err = h.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
          'contracts',COALESCE((SELECT jsonb_agg(to_jsonb(c)) FROM billing_commercial_contract c WHERE team_id=$1),'[]'::jsonb),
          'paid_entitlements',COALESCE((SELECT jsonb_agg(to_jsonb(e)) FROM billing_usage_entitlement e WHERE team_id=$1 AND sponsorship_id IS NULL),'[]'::jsonb),
          'sponsored_entitlements',COALESCE((SELECT jsonb_agg(to_jsonb(e)) FROM billing_usage_entitlement e WHERE team_id=$1 AND sponsorship_id IS NOT NULL),'[]'::jsonb),
          'signup_choice',(SELECT to_jsonb(s) FROM billing_signup_choice s WHERE team_id=$1))`, team).Scan(&snapshot)
		if err != nil {
			respondError(c, ErrInternal)
			return
		}
		plan := "free"
		current, e := h.DB.GetCurrentCommercialPlan(ctx, team)
		if e == nil {
			plan = current.OfferKey
		} else if !errors.Is(e, pgx.ErrNoRows) {
			respondError(c, ErrInternal)
			return
		}
		c.JSON(200, gin.H{"identity": json.RawMessage(identity), "customer_id": customer, "subscription_id": subscription, "effective_plan": plan, "current_billing": json.RawMessage(snapshot), "funding_capacity": capacity, "first_period_start": start, "first_period_end": end, "schedule": periods, "resource_scope": terms, "conflicts": conflicts, "eligible": len(conflicts) == 0, "exhaustion": "add a usable payment method to continue; existing billing enforcement pauses resources with observation and suspension lag; retained storage may continue accruing charges", "new_account_anchor": "provider subscription anniversary is confirmed during onboarding"})
		return
	}
	if len(conflicts) > 0 {
		respondErrorMsg(c, "conflict", strings.Join(conflicts, "; "), 409)
		return
	}

	rawTerms, _ := json.Marshal(params)
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR UPDATE`, team)
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1) ON CONFLICT DO NOTHING`, team)
	}
	if err == nil {
		_, err = h.DB.WithTx(tx).LockTeamBillingAccount(ctx, team)
	}
	// Recheck retry identity after serialization, before treating another request as conflict.
	if err == nil {
		e := tx.QueryRow(ctx, `SELECT id,request=$3::jsonb FROM billing_sponsored_operation WHERE team_id=$1 AND idempotency_key=$2`, team, input.Key, request).Scan(&existing, &same)
		if e == nil {
			if !same {
				err = errors.New("idempotency key already has different terms")
			} else {
				err = tx.Commit(ctx)
				if err == nil {
					h.sponsoredStatus(c, team, existing)
					return
				}
			}
		} else if !errors.Is(e, pgx.ErrNoRows) {
			err = e
		}
	}
	if err == nil {
		err = h.sponsoredLocalPreflight(ctx, tx, team)
	}
	if err == nil {
		err = tx.QueryRow(ctx, `INSERT INTO billing_sponsored_operation(team_id,idempotency_key,request,resource_terms,approved_by,reason,reference,customer_id,subscription_id,customer_name) VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),NULLIF($9,''),(SELECT name FROM team WHERE id=$1)) RETURNING id`, team, input.Key, request, rawTerms, actor, input.Reason, input.Reference, customer, subscription).Scan(&existing)
	}
	if err == nil {
		// BEFORE INSERT runs before conflict resolution: inserting observe=true
		// would charge an existing cohort member for another slot at capacity.
		_, err = tx.Exec(ctx, `INSERT INTO billing_funding_account(team_id) VALUES($1) ON CONFLICT(team_id) DO NOTHING`, team)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE billing_funding_account SET observe=true,enforce=true WHERE team_id=$1`, team)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		respondErrorMsg(c, "conflict", err.Error(), 409)
		return
	}
	h.sponsoredStatus(c, team, existing)
}
func (h *Handlers) SponsoredStatus(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("operation_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid operation", 400)
		return
	}
	h.sponsoredStatus(c, team, id)
}
func (h *Handlers) sponsoredStatus(c *gin.Context, team, id uuid.UUID) {
	var raw []byte
	err := h.Pool.QueryRow(c.Request.Context(), `SELECT (to_jsonb(o)-ARRAY['lease_token','lease_until'])||jsonb_build_object('entitlements',COALESCE((SELECT jsonb_agg(jsonb_build_object('period_start',e.period_start,'period_end',e.period_end,'amount_cents',e.amount_cents,'state',e.state,'grant_id',e.stripe_credit_grant_id) ORDER BY e.period_start) FROM billing_usage_entitlement e WHERE e.sponsorship_id=o.id),'[]'::jsonb)) FROM billing_sponsored_operation o WHERE team_id=$1 AND id=$2`, team, id).Scan(&raw)
	if err != nil {
		respondErrorMsg(c, "not_found", "sponsorship not found", 404)
		return
	}
	c.Data(200, "application/json", raw)
}
func (h *Handlers) SponsoredRevoke(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("operation_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid operation", 400)
		return
	}
	actor, ok := c.Get("actor_id")
	if !ok {
		respondErrorMsg(c, "bad_request", "X-Actor-User-Id is required", 400)
		return
	}
	ctx := c.Request.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(ctx)
	// The contract lock serializes revocation against pending -> uncertain issuance.
	_, err = tx.Exec(ctx, `SELECT c.id FROM billing_commercial_contract c JOIN billing_sponsored_operation o ON o.contract_id=c.id WHERE o.team_id=$1 AND o.id=$2 FOR UPDATE OF c`, team, id)
	var count int64
	if err == nil {
		tag, e := tx.Exec(ctx, `UPDATE billing_sponsored_operation SET revoked_at=COALESCE(revoked_at,clock_timestamp()),revoked_by=COALESCE(revoked_by,$3),state=CASE WHEN state IN ('revoked','expired') THEN state ELSE 'revoking' END,next_check_at=clock_timestamp() WHERE team_id=$1 AND id=$2`, team, id, actor)
		err = e
		count = tag.RowsAffected()
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE billing_entitlement_work SET next_check_at=clock_timestamp() WHERE contract_id=(SELECT contract_id FROM billing_sponsored_operation WHERE id=$1)`, id)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	if count == 0 {
		respondErrorMsg(c, "not_found", "sponsorship not found", 404)
		return
	}
	h.sponsoredStatus(c, team, id)
}
