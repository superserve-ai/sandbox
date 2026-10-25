package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"
)

// planPreviewMonths is how far previews expand indefinitely repeating grants.
const planPreviewMonths = 24

type planSchedulePreview struct {
	Issues  []planGrantIssue `json:"issues"`
	Summary string           `json:"summary"`
	Months  int32            `json:"months"`
}

func previewPlanSchedule(grants []planGrant) planSchedulePreview {
	return planSchedulePreview{Issues: expandPlanSchedule(grants, planPreviewMonths), Summary: planCreditSummary(grants), Months: planPreviewMonths}
}

func formatUSDCents(cents int64) string {
	whole := fmt.Sprint(cents / 100)
	for i := len(whole) - 3; i > 0; i -= 3 {
		whole = whole[:i] + "," + whole[i:]
	}
	if cents%100 != 0 {
		return fmt.Sprintf("$%s.%02d", whole, cents%100)
	}
	return "$" + whole
}

func monthsPhrase(n int32) string {
	if n == 1 {
		return "1 month"
	}
	return fmt.Sprintf("%d months", n)
}

// planCreditSummary renders a schedule in words, e.g. "$1,000 every month".
func planCreditSummary(grants []planGrant) string {
	if len(grants) == 0 {
		return "No included credit"
	}
	parts := make([]string, 0, len(grants))
	for _, g := range grants {
		cadence := "every month"
		if g.EveryMonths > 1 {
			cadence = "every " + monthsPhrase(g.EveryMonths)
		}
		var p string
		switch {
		case g.Repeat == nil:
			p = formatUSDCents(g.AmountCents) + " " + cadence
		case *g.Repeat == 1:
			p = formatUSDCents(g.AmountCents) + " once"
		default:
			p = fmt.Sprintf("%d × %s %s", *g.Repeat, formatUSDCents(g.AmountCents), cadence)
		}
		if g.StartMonths > 0 {
			p += " from month " + fmt.Sprint(g.StartMonths+1)
		}
		if g.ExpiresAfterMonths != g.EveryMonths || (g.Repeat != nil && *g.Repeat == 1 && g.ExpiresAfterMonths != 1) {
			p += ", each expiring after " + monthsPhrase(g.ExpiresAfterMonths)
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", then ")
}

func (h *Handlers) listPlanVersions(ctx context.Context) ([]planVersion, error) {
	rows, err := h.Pool.Query(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version ORDER BY sort_order,family,version DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (planVersion, error) { return scanPlanVersion(row) })
}

type planVersionResponse struct {
	planVersion
	Preview planSchedulePreview `json:"preview"`
}

// GetPlatformBillingCatalog lists every plan and signup promotion version.
func (h *Handlers) GetPlatformBillingCatalog(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	plans, err := h.listPlanVersions(c.Request.Context())
	if err != nil {
		log.Error().Err(err).Msg("list plan versions failed")
		respondError(c, ErrInternal)
		return
	}
	model, err := h.pricingVersion(c.Request.Context())
	if err != nil {
		log.Error().Err(err).Msg("read pricing version failed")
		respondError(c, ErrInternal)
		return
	}
	out := make([]planVersionResponse, 0, len(plans))
	for _, p := range plans {
		out = append(out, planVersionResponse{planVersion: p, Preview: previewPlanSchedule(p.CreditSchedule)})
	}
	c.JSON(http.StatusOK, gin.H{"plans": out, "pricing_version": model})
}

// PreviewPlanSchedule expands a draft schedule, passed as the JSON
// credit_schedule query parameter, with the same rules that materialise
// contracts, so the console never reimplements them.
func (h *Handlers) PreviewPlanSchedule(c *gin.Context) {
	if _, ok := h.requirePlatformBilling(c, platformBillingReadPermission); !ok {
		return
	}
	var grants []planGrant
	if raw := c.Query("credit_schedule"); len(raw) > 8192 || json.Unmarshal([]byte(raw), &grants) != nil {
		respondErrorMsg(c, "bad_request", "invalid credit schedule", http.StatusBadRequest)
		return
	}
	if err := validatePlanSchedule(grants); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, previewPlanSchedule(grants))
}

// IDs and version numbers may be minted by the caller so the console can
// write the same version to every region and retry until all agree.
type planDraftRequest struct {
	ID              *uuid.UUID     `json:"id"`
	Version         *int32         `json:"version"`
	PricingVersion  string         `json:"pricing_version"`
	Family          string         `json:"family"`
	Kind            string         `json:"kind"`
	Public          bool           `json:"public"`
	DisplayName     string         `json:"display_name"`
	PriceLabel      string         `json:"price_label"`
	Tagline         string         `json:"tagline"`
	Features        []string       `json:"features"`
	SortOrder       int32          `json:"sort_order"`
	DisplayOnly     bool           `json:"display_only"`
	SelfServe       bool           `json:"self_serve"`
	MonthlyFeeCents *int64         `json:"monthly_fee_cents"`
	AnnualFeeCents  *int64         `json:"annual_fee_cents"`
	CreditSchedule  []planGrant    `json:"credit_schedule"`
	Matching        *planMatching  `json:"matching"`
	Allowance       *planAllowance `json:"allowance"`
	Limits          planLimits     `json:"limits"`
	Reason          string         `json:"reason"`
}

func (r planDraftRequest) version() planVersion {
	v := planVersion{PricingVersion: r.PricingVersion, Family: strings.TrimSpace(r.Family), Kind: r.Kind, Public: r.Public, DisplayName: strings.TrimSpace(r.DisplayName),
		PriceLabel: strings.TrimSpace(r.PriceLabel), Tagline: strings.TrimSpace(r.Tagline), Features: r.Features, SortOrder: r.SortOrder, DisplayOnly: r.DisplayOnly,
		SelfServe: r.SelfServe, MonthlyFeeCents: r.MonthlyFeeCents, AnnualFeeCents: r.AnnualFeeCents, CreditSchedule: r.CreditSchedule, Matching: r.Matching,
		Allowance: r.Allowance, Limits: r.Limits}
	if v.PricingVersion == "" {
		v.PricingVersion = "legacy"
	}
	if v.Features == nil {
		v.Features = []string{}
	}
	if v.CreditSchedule == nil {
		v.CreditSchedule = []planGrant{}
	}
	return v
}

func bindPlanDraft(c *gin.Context) (planDraftRequest, planVersion, string, bool) {
	var req planDraftRequest
	if err := c.ShouldBindJSON(&req); err != nil || (req.Version != nil && *req.Version < 1) || (req.ID != nil && *req.ID == uuid.Nil) {
		respondErrorMsg(c, "bad_request", "invalid plan draft", http.StatusBadRequest)
		return req, planVersion{}, "", false
	}
	reason, ok := checkCatalogReason(c, req.Reason)
	if !ok {
		return req, planVersion{}, "", false
	}
	v := req.version()
	if err := v.validate(); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return req, planVersion{}, "", false
	}
	return req, v, reason, true
}

// contentKey identifies a version's terms, ignoring identity, state and
// history, so an idempotent retry can recognise the version it created.
func (v planVersion) contentKey() string {
	v.ID, v.Version, v.State = uuid.Nil, 0, ""
	v.CreatedBy, v.PublishedBy, v.RetiredBy = nil, nil, nil
	v.CreatedAt, v.UpdatedAt, v.PublishedAt, v.RetiredAt = time.Time{}, time.Time{}, nil, nil
	if v.Features == nil {
		v.Features = []string{}
	}
	if v.CreditSchedule == nil {
		v.CreditSchedule = []planGrant{}
	}
	key, _ := json.Marshal(v)
	return string(key)
}

func checkCatalogReason(c *gin.Context, raw string) (string, bool) {
	reason := strings.TrimSpace(raw)
	if reason == "" || utf8.RuneCountInString(reason) > 500 || strings.ContainsRune(reason, 0) {
		respondErrorMsg(c, "bad_request", "a reason of at most 500 characters is required", http.StatusBadRequest)
		return "", false
	}
	return reason, true
}

func bindCatalogReason(c *gin.Context) (string, bool) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondErrorMsg(c, "bad_request", "a JSON body with a reason is required", http.StatusBadRequest)
		return "", false
	}
	return checkCatalogReason(c, req.Reason)
}

// planWriteColumns are the columns a draft sets, in planVersionArgs order.
const planWriteColumns = `public,display_name,price_label,tagline,features,sort_order,display_only,self_serve,monthly_fee_cents,annual_fee_cents,
credit_schedule,matching_bps,cap_cents,allowance_period,allowance_on_exhausted,allowance_cents,allowance_compute_seconds,allowance_compute_vcpu,
allowance_compute_memory_gib,max_sandboxes,max_template_vcpu,max_template_memory_mib,max_template_disk_mib,max_templates`

func planVersionArgs(v planVersion) []any {
	schedule, _ := json.Marshal(v.CreditSchedule)
	var bps *int32
	var capCents, allowanceCents *int64
	var period, onExhausted *string
	var seconds, vcpu, memory *int32
	if v.Matching != nil {
		bps, capCents = &v.Matching.MatchingBps, &v.Matching.CapCents
	}
	if a := v.Allowance; a != nil {
		period, onExhausted = &a.Period, &a.OnExhausted
		if a.Compute != nil {
			seconds, vcpu, memory = &a.Compute.Seconds, &a.Compute.VCPU, &a.Compute.MemoryGiB
		} else {
			allowanceCents = &a.AmountCents
		}
	}
	return []any{v.Public, v.DisplayName, v.PriceLabel, v.Tagline, v.Features, v.SortOrder, v.DisplayOnly, v.SelfServe, v.MonthlyFeeCents, v.AnnualFeeCents,
		schedule, bps, capCents, period, onExhausted, allowanceCents, seconds, vcpu, memory,
		v.Limits.MaxConcurrent, v.Limits.MaxVCPU, v.Limits.MaxMemoryMiB, v.Limits.MaxDiskMiB, v.Limits.MaxTemplates}
}

// placeholders returns "$from,...,$to".
func placeholders(from, to int) string {
	parts := make([]string, 0, to-from+1)
	for i := from; i <= to; i++ {
		parts = append(parts, fmt.Sprintf("$%d", i))
	}
	return strings.Join(parts, ",")
}

// assignments returns "column=$n,..." for planWriteColumns starting at $from.
func planWriteAssignments(from int) string {
	cols := strings.Split(strings.ReplaceAll(planWriteColumns, "\n", ""), ",")
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = fmt.Sprintf("%s=$%d", strings.TrimSpace(c), from+i)
	}
	return strings.Join(parts, ",")
}

func respondCatalogWriteError(c *gin.Context, err error) {
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, errCatalogNoop):
		c.Status(http.StatusNoContent)
	case errors.Is(err, errOnlyDrafts):
		respondErrorMsg(c, "conflict", err.Error(), http.StatusConflict)
	case errors.Is(err, pgx.ErrNoRows), errors.As(err, &pgErr) && pgErr.Code == "P0002":
		respondErrorMsg(c, "not_found", "catalog version not found", http.StatusNotFound)
	case errors.As(err, &pgErr) && (pgErr.Code == "23505" || pgErr.Code == "40001" || pgErr.Code == "40P01"):
		respondErrorMsg(c, "conflict", "another version was created concurrently; retry", http.StatusConflict)
	case errors.As(err, &pgErr) && (pgErr.Code == "P0001" || pgErr.Code == "55000"):
		respondErrorMsg(c, "conflict", pgErr.Message, http.StatusConflict)
	case errors.As(err, &pgErr) && (pgErr.Code == "23514" || pgErr.Code == "22P02" || pgErr.Code == "22021"):
		respondErrorMsg(c, "bad_request", "the catalog rejected these terms ("+pgErr.ConstraintName+")", http.StatusBadRequest)
	default:
		log.Error().Err(err).Msg("billing catalog write failed")
		respondError(c, ErrInternal)
	}
}

func (h *Handlers) planVersionResponse(c *gin.Context, id uuid.UUID, status int) {
	v, err := scanPlanVersion(h.Pool.QueryRow(c.Request.Context(), `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1`, id))
	if err != nil {
		respondCatalogWriteError(c, err)
		return
	}
	c.JSON(status, planVersionResponse{planVersion: v, Preview: previewPlanSchedule(v.CreditSchedule)})
}

// catalogWrite runs one staff change and its audit row in a transaction.
// write returns the affected version and its terms as the change left them.
func (h *Handlers) catalogWrite(c *gin.Context, actor uuid.UUID, action, reason string, write func(context.Context, pgx.Tx) (uuid.UUID, []byte, error)) (uuid.UUID, bool) {
	ctx := c.Request.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		log.Error().Err(err).Str("action", action).Msg("billing catalog write could not begin")
		respondError(c, ErrInternal)
		return uuid.Nil, false
	}
	defer tx.Rollback(ctx)
	id, terms, err := write(ctx, tx)
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO billing_catalog_audit(actor_id,action,version_id,reason,terms) VALUES($1,$2,$3,$4,$5)`, actor, action, id, reason, terms)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		respondCatalogWriteError(c, err)
		return uuid.Nil, false
	}
	return id, true
}

func planVersionTerms(ctx context.Context, tx pgx.Tx, id uuid.UUID) ([]byte, error) {
	var terms []byte
	err := tx.QueryRow(ctx, `SELECT to_jsonb(v) FROM billing_plan_version v WHERE id=$1`, id).Scan(&terms)
	return terms, err
}

var (
	errOnlyDrafts  = errors.New("only drafts of this family can be changed")
	errCatalogNoop = errors.New("the change is already in place")
)

// CreatePlanVersionDraft adds the family's next version as a draft. Editing a
// published plan is creating a draft from its terms and publishing that.
func (h *Handlers) CreatePlanVersionDraft(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	req, v, reason, ok := bindPlanDraft(c)
	if !ok {
		return
	}
	if req.ID != nil {
		existing, err := scanPlanVersion(h.Pool.QueryRow(c.Request.Context(), `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1`, *req.ID))
		if err == nil {
			if existing.contentKey() != v.contentKey() || (req.Version != nil && *req.Version != existing.Version) {
				respondErrorMsg(c, "conflict", "a different version already uses this id", http.StatusConflict)
				return
			}
			h.planVersionResponse(c, existing.ID, http.StatusOK)
			return
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			respondCatalogWriteError(c, err)
			return
		}
	}
	id, ok := h.catalogWrite(c, actor, "create_draft", reason, func(ctx context.Context, tx pgx.Tx) (uuid.UUID, []byte, error) {
		var id uuid.UUID
		var terms []byte
		args := append([]any{v.Family, actor, req.ID, req.Version, v.PricingVersion, v.Kind}, planVersionArgs(v)...)
		err := tx.QueryRow(ctx, `INSERT INTO billing_plan_version(family,created_by,id,version,pricing_version,kind,`+planWriteColumns+`)
 SELECT $1,$2,COALESCE($3::uuid,gen_random_uuid()),COALESCE($4::integer,COALESCE(MAX(version),0)+1),$5,$6,`+placeholders(7, len(args))+`
 FROM billing_plan_version WHERE family=$1
 RETURNING id,to_jsonb(billing_plan_version.*)`, args...).Scan(&id, &terms)
		return id, terms, err
	})
	if ok {
		h.planVersionResponse(c, id, http.StatusCreated)
	}
}

func catalogVersionID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("version_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid version id", http.StatusBadRequest)
		return uuid.Nil, false
	}
	return id, true
}

// UpdatePlanVersionDraft replaces a draft's terms; published versions reject it.
func (h *Handlers) UpdatePlanVersionDraft(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	id, ok := catalogVersionID(c)
	if !ok {
		return
	}
	_, v, reason, ok := bindPlanDraft(c)
	if !ok {
		return
	}
	if existing, err := scanPlanVersion(h.Pool.QueryRow(c.Request.Context(), `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1`, id)); err == nil &&
		existing.State == "draft" && existing.Family == v.Family && existing.PricingVersion == v.PricingVersion && existing.contentKey() == v.contentKey() {
		h.planVersionResponse(c, id, http.StatusOK)
		return
	}
	if _, ok = h.catalogWrite(c, actor, "update_draft", reason, func(ctx context.Context, tx pgx.Tx) (uuid.UUID, []byte, error) {
		var terms []byte
		args := append([]any{id, v.Family, v.PricingVersion, v.Kind}, planVersionArgs(v)...)
		err := tx.QueryRow(ctx, `UPDATE billing_plan_version SET kind=$4,`+planWriteAssignments(5)+`
 WHERE id=$1 AND family=$2 AND pricing_version=$3 AND state='draft' RETURNING to_jsonb(billing_plan_version.*)`, args...).Scan(&terms)
		if errors.Is(err, pgx.ErrNoRows) {
			err = errOnlyDrafts
		}
		return id, terms, err
	}); ok {
		h.planVersionResponse(c, id, http.StatusOK)
	}
}

// DeletePlanVersionDraft discards a draft that was never published.
func (h *Handlers) DeletePlanVersionDraft(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	id, ok := catalogVersionID(c)
	if !ok {
		return
	}
	reason, ok := bindCatalogReason(c)
	if !ok {
		return
	}
	if _, ok = h.catalogWrite(c, actor, "delete_draft", reason, func(ctx context.Context, tx pgx.Tx) (uuid.UUID, []byte, error) {
		var terms []byte
		err := tx.QueryRow(ctx, `DELETE FROM billing_plan_version WHERE id=$1 AND state='draft' RETURNING to_jsonb(billing_plan_version.*)`, id).Scan(&terms)
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_plan_version WHERE id=$1)`, id).Scan(&exists); err == nil {
				err = errOnlyDrafts
				if !exists {
					err = errCatalogNoop
				}
			}
		}
		return id, terms, err
	}); ok {
		c.Status(http.StatusNoContent)
	}
}

// PublishPlanVersion makes a draft the family's current version and retires
// the version it replaces. Existing contracts keep their frozen terms.
func (h *Handlers) PublishPlanVersion(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	id, ok := catalogVersionID(c)
	if !ok {
		return
	}
	var req struct {
		Reason   string       `json:"reason"`
		Expected *planVersion `json:"expected"`
	}
	if c.ShouldBindJSON(&req) != nil {
		respondErrorMsg(c, "bad_request", "a JSON body with a reason is required", http.StatusBadRequest)
		return
	}
	reason, ok := checkCatalogReason(c, req.Reason)
	if !ok {
		return
	}
	v, err := scanPlanVersion(h.Pool.QueryRow(c.Request.Context(), `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1`, id))
	if err != nil {
		respondCatalogWriteError(c, err)
		return
	}
	expected := v
	if req.Expected != nil {
		expected = *req.Expected
	}
	if v.contentKey() != expected.contentKey() {
		respondErrorMsg(c, "conflict", "catalog terms changed; refresh and retry", http.StatusConflict)
		return
	}
	if v.State == "published" {
		h.planVersionResponse(c, id, http.StatusOK)
		return
	}
	if err = v.validate(); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if _, ok = h.catalogWrite(c, actor, "publish", reason, func(ctx context.Context, tx pgx.Tx) (uuid.UUID, []byte, error) {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM billing_lock_pricing_public_state()`); err != nil {
			return id, nil, err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('billing-catalog:' || $1 || ':' || $2)::bigint)`, v.Family, v.PricingVersion); err != nil {
			return id, nil, err
		}
		current, err := scanPlanVersion(tx.QueryRow(ctx, `SELECT `+planVersionColumns+` FROM billing_plan_version WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return id, nil, err
		}
		if current.contentKey() != expected.contentKey() {
			return id, nil, &pgconn.PgError{Code: "55000", Message: "catalog terms changed; refresh and retry"}
		}
		if _, err := tx.Exec(ctx, `SELECT publish_billing_plan_version($1,$2)`, id, actor); err != nil {
			return id, nil, err
		}
		terms, err := planVersionTerms(ctx, tx, id)
		return id, terms, err
	}); ok {
		h.planVersionResponse(c, id, http.StatusOK)
	}
}

// RetirePlanVersion withdraws a family from new sales without a replacement.
func (h *Handlers) RetirePlanVersion(c *gin.Context) {
	actor, ok := h.requirePlatformBilling(c, platformBillingWritePermission)
	if !ok {
		return
	}
	id, ok := catalogVersionID(c)
	if !ok {
		return
	}
	reason, ok := bindCatalogReason(c)
	if !ok {
		return
	}
	var state string
	if err := h.Pool.QueryRow(c.Request.Context(), `SELECT state FROM billing_plan_version WHERE id=$1`, id).Scan(&state); err != nil {
		respondCatalogWriteError(c, err)
		return
	}
	if state == "retired" {
		h.planVersionResponse(c, id, http.StatusOK)
		return
	}
	if _, ok = h.catalogWrite(c, actor, "retire", reason, func(ctx context.Context, tx pgx.Tx) (uuid.UUID, []byte, error) {
		if _, err := tx.Exec(ctx, `SELECT retire_billing_plan_version($1,$2)`, id, actor); err != nil {
			return id, nil, err
		}
		terms, err := planVersionTerms(ctx, tx, id)
		return id, terms, err
	}); ok {
		h.planVersionResponse(c, id, http.StatusOK)
	}
}
