package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

// CommercialOfferRequest pins acceptance authority and version before provider setup.
// Materialization is separate: acceptance must not start the benefit clock.
type CommercialOfferRequest struct {
	Key        string    `json:"idempotency_key"`
	OfferKey   string    `json:"offer_key"`
	Version    int       `json:"offer_version"`
	ApprovalID uuid.UUID `json:"approval_id"`
	Company    string    `json:"company_identity"`
	Region     string    `json:"home_region"`
	Reason     string    `json:"reason"`
	Reference  string    `json:"reference"`
}

var errCommercialOfferConflict = errors.New("commercial offer authority, pricing or existing assignment conflicts")

func (r CommercialOfferRequest) validate() error {
	if r.OfferKey != "yc_2026" || r.Version < 1 || r.ApprovalID == uuid.Nil || strings.TrimSpace(r.Key) == "" || len(r.Key) > 200 || strings.TrimSpace(r.Company) == "" || len(r.Company) > 500 || strings.TrimSpace(r.Region) == "" || strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 2000 || strings.TrimSpace(r.Reference) == "" || len(r.Reference) > 2000 {
		return errors.New("exact offer version, approval, company, region and audited idempotency key/reason/reference are required")
	}
	return nil
}

func (h *Handlers) registerCommercialOfferRoutes(r *gin.RouterGroup) {
	r.POST("/teams/:team_id/billing/commercial-offer-assignment/preflight", h.CommercialOfferPreflight)
	r.POST("/teams/:team_id/billing/commercial-offer-assignment", h.CommercialOfferApply)
	r.GET("/teams/:team_id/billing/commercial-offer-assignment", h.CommercialOfferStatus)
}
func (h *Handlers) CommercialOfferPreflight(c *gin.Context) { h.commercialOfferApply(c, false) }
func (h *Handlers) CommercialOfferApply(c *gin.Context)     { h.commercialOfferApply(c, true) }
func (h *Handlers) commercialOfferApply(c *gin.Context, apply bool) {
	permission := platformBillingReadPermission
	if apply {
		permission = platformBillingWritePermission
	}
	actor, ok := h.requirePlatformBilling(c, permission)
	if !ok {
		return
	}
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	var r CommercialOfferRequest
	if c.ShouldBindJSON(&r) != nil || r.validate() != nil {
		respondErrorMsg(c, "bad_request", "invalid commercial offer assignment", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	raw, err := h.assignCommercialOffer(ctx, team, actor, r, apply)
	if err != nil {
		commercialOfferError(c, err)
		return
	}
	c.Header("Cache-Control", "private, no-store")
	c.Data(200, "application/json", raw)
}
func commercialOfferError(c *gin.Context, err error) {
	if errors.Is(err, errCommercialOfferDisabled) {
		respondErrorMsg(c, "service_unavailable", err.Error(), 503)
		return
	}
	if errors.Is(err, errCommercialOfferConflict) {
		respondErrorMsg(c, "conflict", err.Error(), 409)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		respondErrorMsg(c, "not_found", "commercial offer or assignment unavailable", 404)
		return
	}
	respondError(c, ErrInternal)
}

// Callers are authenticated platform handlers or a durable activation consumer.
// Shared approval is checked here as well, so an internal caller cannot invent
// company eligibility. This function creates no grants or provider operations.
func (h *Handlers) assignCommercialOffer(ctx context.Context, team, actor uuid.UUID, r CommercialOfferRequest, apply bool) (json.RawMessage, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	if team == uuid.Nil || actor == uuid.Nil || h.PromotionAuthPool == nil || h.Config == nil || r.Region != h.Config.TeamCreationRegion {
		return nil, errCommercialOfferConflict
	}
	var authorized bool
	err := h.PromotionAuthPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.read_yc_activation_authority($1,$2) WHERE company_identity=$1 AND team_id=$2 AND approval_id=$3 AND home_region=$4 AND offer_key=$5 AND offer_version=$6 AND revoked_at IS NULL)`, r.Company, team, r.ApprovalID, r.Region, r.OfferKey, r.Version).Scan(&authorized)
	if err != nil {
		return nil, err
	}
	if !authorized {
		return nil, errCommercialOfferConflict
	}
	release, err := h.lockYCAuthority(ctx, ycOperation{ID: r.ApprovalID, Team: team, Request: ycApproval{Region: r.Region}})
	if err != nil {
		return nil, err
	}
	defer release()
	return h.assignCommercialOfferRegional(ctx, team, actor, r, apply, nil)
}

func (h *Handlers) assignCommercialOfferRegional(ctx context.Context, team, actor uuid.UUID, r CommercialOfferRequest, apply bool, accepted *YCAcceptanceRecord) (json.RawMessage, error) {
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if accepted != nil {
		if _, err = tx.Exec(ctx, "SET LOCAL lock_timeout='1s'"); err != nil {
			return nil, err
		}
	}
	var region string
	if err = tx.QueryRow(ctx, `SELECT home_region FROM team WHERE id=$1 FOR NO KEY UPDATE`, team).Scan(&region); err != nil {
		return nil, err
	}
	if region != r.Region {
		return nil, errCommercialOfferConflict
	}
	request, _ := json.Marshal(r)
	var id uuid.UUID
	var same bool
	err = tx.QueryRow(ctx, `SELECT id,request=$2::jsonb FROM billing_commercial_offer_assignment WHERE team_id=$1`, team, request).Scan(&id, &same)
	if err == nil {
		if !same {
			return nil, errCommercialOfferConflict
		}
		if accepted != nil {
			if err = verifyAcceptedAssignment(ctx, tx, *accepted, id); err != nil {
				return nil, err
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	} else {
		if err = commercialOfferEnabled(ctx, tx, team); err != nil {
			return nil, err
		}
		// Match the existing sponsorship/checkout account serialization boundary.
		// Apply creates the empty row when needed; preflight remains audit-only.
		if apply {
			if _, err = tx.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1) ON CONFLICT DO NOTHING`, team); err != nil {
				return nil, err
			}
		}
		if err = lockCommercialOfferAccount(ctx, tx, team); err != nil && (apply || !errors.Is(err, pgx.ErrNoRows)) {
			return nil, err
		}
		var reserved bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_checkout_attempt WHERE team_id=$1 AND (state IN ('dispatched','customer_observed') OR (state='prepared' AND prepared_until>clock_timestamp())))`, team).Scan(&reserved); err != nil {
			return nil, err
		}
		if reserved {
			return nil, errCommercialOfferConflict
		}
		if err = h.sponsoredLocalPreflight(ctx, tx, team); err != nil {
			return nil, errCommercialOfferConflict
		}
		// This slice admits new signups only. Existing provider accounts require the
		// existing administrative workflow and its debt/history reconciliation.
		var existing bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_account WHERE team_id=$1 AND (stripe_customer_id IS NOT NULL OR stripe_subscription_id IS NOT NULL OR commercial_billing_anchor IS NOT NULL)) OR EXISTS(SELECT 1 FROM billing_commercial_contract WHERE team_id=$1)`, team).Scan(&existing); err != nil {
			return nil, err
		}
		if existing {
			return nil, errCommercialOfferConflict
		}
		var card string
		var rates []uuid.UUID
		var pricingAt time.Time
		var resourceRates json.RawMessage
		if accepted == nil {
			if err = tx.QueryRow(ctx, commercialOfferPricingSQL, team, r.OfferKey, r.Version).Scan(&card, &rates, &pricingAt, &resourceRates); err != nil {
				return nil, err
			}
		} else {
			card, rates, pricingAt, resourceRates, err = acceptedOfferPricing(ctx, tx, *accepted)
			if err != nil {
				return nil, err
			}
		}
		if len(rates) < 3 {
			return nil, errCommercialOfferConflict
		}
		if apply {
			err = tx.QueryRow(ctx, `INSERT INTO billing_commercial_offer_assignment(team_id,approval_id,company_identity,home_region,offer_key,offer_version,idempotency_key,rate_card_key,rate_ids,pricing_at,request,assigned_by,reason,reference,resource_rates)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`, team, r.ApprovalID, r.Company, r.Region, r.OfferKey, r.Version, r.Key, card, rates, pricingAt, request, actor, r.Reason, r.Reference, resourceRates).Scan(&id)
			if err != nil {
				return nil, err
			}
		}
	}
	action := "preflight"
	if apply {
		action = "assign"
	}
	var assignment any
	if id != uuid.Nil {
		assignment = id
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_commercial_offer_audit(team_id,actor_id,action,assignment_id) VALUES($1,$2,$3,$4)`, team, actor, action, assignment); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if id == uuid.Nil {
		err = tx.QueryRow(ctx, `SELECT jsonb_build_object('eligible',true,'state','unassigned','terms',to_jsonb(v),'periods','[]'::jsonb) FROM billing_commercial_offer_version v WHERE offer_key=$1 AND version=$2`, r.OfferKey, r.Version).Scan(&raw)
	} else {
		raw, err = commercialOfferStatus(ctx, tx, team)
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return raw, nil
}

// Resolve the same active team card/default and rate ordering as billing pricing.
// Persist row identities once; retries never re-resolve a newly published rate.
const commercialOfferPricingSQL = `WITH selected AS (
 SELECT COALESCE((SELECT t.plan_key FROM team_pricing_plan t JOIN pricing_plan p ON p.key=t.plan_key
 WHERE t.team_id=$1 AND p.active AND t.effective_from<=now() AND (t.effective_to IS NULL OR t.effective_to>now()) ORDER BY t.effective_from DESC LIMIT 1),'payg') AS card
), rates AS (
 SELECT DISTINCT ON (r.resource,r.unit) r.id,r.plan_key,r.resource,r.unit,r.price_usd,p.currency FROM selected s JOIN pricing_rate r ON r.plan_key=s.card
 JOIN pricing_plan p ON p.key=r.plan_key AND p.active AND p.currency='USD'
 JOIN billing_commercial_offer_version v ON v.offer_key=$2 AND v.version=$3 AND v.rate_card_key=s.card
 WHERE r.effective_from<=now() AND (r.effective_to IS NULL OR r.effective_to>now())
 ORDER BY r.resource,r.unit,r.effective_from DESC,r.created_at DESC,r.id DESC
) SELECT plan_key,array_agg(id ORDER BY resource,unit),now(),jsonb_agg(to_jsonb(rates) ORDER BY resource,unit) FROM rates GROUP BY plan_key`

func commercialOfferStatus(ctx context.Context, q db.DBTX, team uuid.UUID) (json.RawMessage, error) {
	var raw json.RawMessage
	err := q.QueryRow(ctx, `SELECT jsonb_build_object('assignment',to_jsonb(a),'terms',to_jsonb(v),
 'state',CASE WHEN x.assignment_id IS NULL THEN 'pending_activation' ELSE 'materialized' END,
 'activation',to_jsonb(x),'periods',COALESCE((SELECT jsonb_agg(to_jsonb(p) ORDER BY month_offset) FROM billing_commercial_offer_period p WHERE p.assignment_id=a.id),'[]'::jsonb))
 FROM billing_commercial_offer_assignment a JOIN billing_commercial_offer_version v ON v.offer_key=a.offer_key AND v.version=a.offer_version
 LEFT JOIN billing_commercial_offer_activation x ON x.assignment_id=a.id WHERE a.team_id=$1`, team).Scan(&raw)
	return raw, err
}
func (h *Handlers) CommercialOfferStatus(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingReadPermission)
	if !ok {
		return
	}
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	tx, err := h.Pool.Begin(c.Request.Context())
	if err != nil {
		respondError(c, ErrInternal)
		return
	}
	defer tx.Rollback(c.Request.Context())
	raw, err := commercialOfferStatus(c.Request.Context(), tx, team)
	if err == nil {
		_, err = tx.Exec(c.Request.Context(), `INSERT INTO billing_commercial_offer_audit(team_id,actor_id,action,assignment_id) SELECT team_id,$2,'status',id FROM billing_commercial_offer_assignment WHERE team_id=$1`, team, actor)
	}
	if err == nil {
		err = tx.Commit(c.Request.Context())
	}
	if err != nil {
		commercialOfferError(c, err)
		return
	}
	c.Header("Cache-Control", "private, no-store")
	c.Data(200, "application/json", raw)
}

// materializeCommercialOffer uses persisted activation evidence, never a supplied
// timestamp. It is deliberately not routed: downstream activation owns the call.
func (h *Handlers) materializeCommercialOffer(ctx context.Context, team, assignment, contract uuid.UUID, merchant string, live bool) error {
	q := db.DBTX(h.Pool)
	var existing uuid.UUID
	var existingMerchant string
	var existingLive bool
	err := q.QueryRow(ctx, `SELECT contract_id,merchant_account,live_mode FROM billing_commercial_offer_activation WHERE assignment_id=$1 AND team_id=$2`, assignment, team).Scan(&existing, &existingMerchant, &existingLive)
	if err == nil {
		if existing != contract || existingMerchant != merchant || existingLive != live {
			return errCommercialOfferConflict
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err = commercialOfferEnabled(ctx, q, team); err != nil {
		return err
	}
	var approval uuid.UUID
	var region, company string
	if err = q.QueryRow(ctx, `SELECT approval_id,home_region,company_identity FROM billing_commercial_offer_assignment WHERE id=$1 AND team_id=$2`, assignment, team).Scan(&approval, &region, &company); err != nil {
		return err
	}
	if h.Config == nil || h.Config.TeamCreationRegion != region {
		return errCommercialOfferConflict
	}
	if err = h.verifyYCAuthority(ctx, ycOperation{ID: approval, Team: team, Request: ycApproval{Region: region, CompanyIdentity: company}}); err != nil {
		return err
	}
	release, err := h.lockYCAuthority(ctx, ycOperation{ID: approval, Team: team, Request: ycApproval{Region: region}})
	if err != nil {
		return err
	}
	defer release()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q = tx
	if err = lockCommercialOfferAccount(ctx, q, team); err != nil {
		return err
	}
	// A concurrent materializer may have committed while this call acquired locks.
	err = q.QueryRow(ctx, `SELECT contract_id,merchant_account,live_mode FROM billing_commercial_offer_activation WHERE assignment_id=$1 AND team_id=$2`, assignment, team).Scan(&existing, &existingMerchant, &existingLive)
	if err == nil {
		if existing != contract || existingMerchant != merchant || existingLive != live {
			return errCommercialOfferConflict
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var id uuid.UUID
	err = q.QueryRow(ctx, `INSERT INTO billing_commercial_offer_activation(assignment_id,team_id,contract_id,anchor,ends_at,merchant_account,live_mode)
 SELECT a.id,a.team_id,c.id,c.entitlement_anchor,c.ends_at,$4,$5 FROM billing_commercial_offer_assignment a
 JOIN billing_commercial_contract c ON c.team_id=a.team_id WHERE a.id=$1 AND a.team_id=$2 AND c.id=$3
 ON CONFLICT (assignment_id) DO NOTHING RETURNING assignment_id`, assignment, team, contract, merchant, live).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		var same bool
		err = q.QueryRow(ctx, `SELECT contract_id=$3 AND merchant_account=$4 AND live_mode=$5 FROM billing_commercial_offer_activation WHERE assignment_id=$1 AND team_id=$2`, assignment, team, contract, merchant, live).Scan(&same)
		if err == nil && !same {
			return errCommercialOfferConflict
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Use the existing mutable billing account as the serialization point. Row locks
// require UPDATE privilege, which immutable assignment tables deliberately lack.
func lockCommercialOfferAccount(ctx context.Context, q db.DBTX, team uuid.UUID) error {
	var locked uuid.UUID
	return q.QueryRow(ctx, `SELECT team_id FROM team_billing_account WHERE team_id=$1 FOR UPDATE`, team).Scan(&locked)
}

var errCommercialOfferDisabled = errors.New("commercial offer assignment rollout is disabled")

func commercialOfferEnabled(ctx context.Context, q db.DBTX, team uuid.UUID) error {
	var enabled bool
	if err := q.QueryRow(ctx, `SELECT feature_enabled('billing_commercial_offer_assignments_enabled',$1)`, team).Scan(&enabled); err != nil {
		return err
	}
	if !enabled {
		return errCommercialOfferDisabled
	}
	return nil
}

// Every attempt transition uses the same order as assignment, including the team
// lock needed by first-account insertion. No transaction spans a provider call.
// Non-key locks allow account-first recovery to insert team-referencing audit rows.
func (h *Handlers) withCommercialCheckoutAccount(ctx context.Context, team uuid.UUID, f func(context.Context, pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team).Scan(&id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO team_billing_account(team_id) VALUES($1) ON CONFLICT DO NOTHING`, team); err != nil {
		return err
	}
	if err = lockCommercialOfferAccount(ctx, tx, team); err != nil {
		return err
	}
	if err = f(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handlers) prepareCommercialCheckout(ctx context.Context, team uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := h.withCommercialCheckoutAccount(ctx, team, func(ctx context.Context, tx pgx.Tx) error {
		var assigned bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_offer_assignment WHERE team_id=$1)`, team).Scan(&assigned); err != nil {
			return err
		}
		if assigned {
			return errCommercialOfferConflict
		}
		return tx.QueryRow(ctx, `INSERT INTO billing_commercial_checkout_attempt(team_id) VALUES($1) RETURNING id`, team).Scan(&id)
	})
	return id, err
}

func (h *Handlers) dispatchCommercialCheckout(ctx context.Context, team, attempt uuid.UUID) error {
	return h.withCommercialCheckoutAccount(ctx, team, func(ctx context.Context, tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `UPDATE billing_commercial_checkout_attempt SET state='dispatched'
 WHERE id=$1 AND team_id=$2 AND state='prepared' AND prepared_until>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM billing_commercial_offer_assignment WHERE team_id=$2)`, attempt, team)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return errCommercialOfferConflict
		}
		return nil
	})
}

func (h *Handlers) finishCommercialCheckout(ctx context.Context, team, attempt uuid.UUID, customer string) error {
	return h.withCommercialCheckoutAccount(ctx, team, func(ctx context.Context, tx pgx.Tx) error {
		if customer == "" {
			// Only a token that never authorized dispatch can be released. A failed
			// or canceled retry cannot clear an earlier uncertain provider outcome.
			_, err := tx.Exec(ctx, `UPDATE billing_commercial_checkout_attempt SET state='no_effect' WHERE id=$1 AND team_id=$2 AND state='prepared'`, attempt, team)
			return err
		}
		var assigned bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_commercial_offer_assignment WHERE team_id=$1)`, team).Scan(&assigned); err != nil {
			return err
		}
		if assigned {
			return errCommercialOfferConflict
		}
		result, err := tx.Exec(ctx, `UPDATE billing_commercial_checkout_attempt SET state='customer_observed',customer_id=$3 WHERE id=$1 AND team_id=$2 AND state IN ('prepared','dispatched')`, attempt, team, customer)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return errCommercialOfferConflict
		}
		return nil
	})
}

// Ordinary checkout reserves eligibility before authorizing any customer POST.
// Provisioning an assigned offer must use its separate verified activation path.

func (h *Handlers) ensureCheckoutStripeCustomer(ctx context.Context, team uuid.UUID) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if h.Stripe == nil || h.Pool == nil || h.DB == nil {
		return "", errors.New("Stripe billing is not configured")
	}
	if client, ok := h.Stripe.(*stripeHTTPClient); ok {
		if client.apiVersion == "" || client.httpClient == nil {
			return "", errors.New("Stripe client is not configured")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+"/v1/customers", nil)
		if err != nil {
			return "", err
		}
		if req.URL.Host == "" || (req.URL.Scheme != "https" && req.URL.Scheme != "http") {
			return "", errors.New("Stripe provider URL is not configured")
		}
	}
	attempt, err := h.prepareCommercialCheckout(ctx, team)
	if err != nil {
		return "", err
	}
	customer, err := h.ensureStripeCustomerBeforeCreate(ctx, team, func() error { return h.dispatchCommercialCheckout(ctx, team, attempt) })
	if err != nil {
		cleanupErr := h.finishCommercialCheckout(context.WithoutCancel(ctx), team, attempt, "")
		return "", errors.Join(err, cleanupErr)
	}
	if err = h.finishCommercialCheckout(context.WithoutCancel(ctx), team, attempt, customer); err != nil {
		return "", err
	}
	return customer, nil
}
