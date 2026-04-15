package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// ---------------------------------------------------------------------------
// Request / response shapes (handler-local; persisted shapes live in db.Models)
// ---------------------------------------------------------------------------

type buildStep struct {
	Run     *string         `json:"run,omitempty"`
	Copy    *buildCopyOp    `json:"copy,omitempty"`
	Env     *buildEnvOp     `json:"env,omitempty"`
	Workdir *string         `json:"workdir,omitempty"`
}

type buildCopyOp struct {
	Src string `json:"src"` // base64-encoded tar; capped at 1 MiB in V1
	Dst string `json:"dst"`
}

type buildEnvOp struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// buildSpec is the canonical declaration that gets persisted as jsonb in
// template.build_spec. Server-owned shape; SDKs are thin clients.
type buildSpec struct {
	From     string      `json:"from"`
	Steps    []buildStep `json:"steps,omitempty"`
	StartCmd string      `json:"start_cmd,omitempty"`
	ReadyCmd string      `json:"ready_cmd,omitempty"`
}

type createTemplateRequest struct {
	Alias      string     `json:"alias"`
	Visibility *string    `json:"visibility,omitempty"`
	Vcpu       *int32     `json:"vcpu,omitempty"`
	MemoryMib  *int32     `json:"memory_mib,omitempty"`
	DiskMib    *int32     `json:"disk_mib,omitempty"`
	BuildSpec  *buildSpec `json:"build_spec,omitempty"`
}

type templateResponse struct {
	ID           uuid.UUID  `json:"id"`
	TeamID       uuid.UUID  `json:"team_id"`
	Alias        string     `json:"alias"`
	Visibility   string     `json:"visibility"`
	Status       string     `json:"status"`
	Vcpu         int32      `json:"vcpu"`
	MemoryMib    int32      `json:"memory_mib"`
	DiskMib      int32      `json:"disk_mib"`
	SizeBytes    *int64     `json:"size_bytes,omitempty"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	CreatedAt    string     `json:"created_at"`
	BuiltAt      *string    `json:"built_at,omitempty"`
	BuildSpec    *buildSpec `json:"build_spec,omitempty"`
}

type templateBuildResponse struct {
	ID            uuid.UUID `json:"id"`
	TemplateID    uuid.UUID `json:"template_id"`
	Status        string    `json:"status"`
	BuildSpecHash string    `json:"build_spec_hash"`
	ErrorMessage  *string   `json:"error_message,omitempty"`
	StartedAt     *string   `json:"started_at,omitempty"`
	FinalizedAt   *string   `json:"finalized_at,omitempty"`
	CreatedAt     string    `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const (
	maxAlias        = 128
	maxVcpu         = 4
	maxMemoryMib    = 4096
	maxDiskMib      = 8192
	defaultVcpu     = 1
	defaultMemoryMi = 1024
	defaultDiskMib  = 4096
	maxCopySrcBytes = 1024 * 1024 // 1 MiB cap on inline base64-tar payloads
)

// validateBuildSpec enforces base-image policy and step-shape invariants.
// Catches obvious problems (alpine, distroless, bad step shape, oversized
// copy payload) before we persist a row or hand off to the builder.
func validateBuildSpec(spec *buildSpec) error {
	if spec == nil {
		return fmt.Errorf("build_spec is required")
	}
	if strings.TrimSpace(spec.From) == "" {
		return fmt.Errorf("build_spec.from is required")
	}
	// Permissive policy: allow any OCI ref, but reject known-incompatible
	// bases up front so the user gets a fast clear error rather than a
	// build-time mystery failure. Heuristic on the image name; the converter
	// will do a stricter check post-pull.
	low := strings.ToLower(spec.From)
	if strings.Contains(low, "alpine") {
		return fmt.Errorf("alpine bases are not supported in V1 (musl + non-systemd init); use a debian/ubuntu-based image")
	}
	if strings.Contains(low, "distroless") {
		return fmt.Errorf("distroless bases are not supported (no shell for RUN steps)")
	}
	for i, step := range spec.Steps {
		set := 0
		if step.Run != nil {
			set++
		}
		if step.Copy != nil {
			set++
			if len(step.Copy.Src) > maxCopySrcBytes {
				return fmt.Errorf("build_spec.steps[%d].copy.src exceeds %d bytes (V1 cap)", i, maxCopySrcBytes)
			}
			if step.Copy.Dst == "" {
				return fmt.Errorf("build_spec.steps[%d].copy.dst is required", i)
			}
		}
		if step.Env != nil {
			set++
			if step.Env.Key == "" {
				return fmt.Errorf("build_spec.steps[%d].env.key is required", i)
			}
		}
		if step.Workdir != nil {
			set++
		}
		if set != 1 {
			return fmt.Errorf("build_spec.steps[%d] must set exactly one of run/copy/env/workdir", i)
		}
	}
	return nil
}

// canonicalSpecHash produces a stable hash of the spec for idempotent build
// submits. Marshals via encoding/json — Go's json package emits map keys in
// sorted order, so the same spec always hashes to the same value.
func canonicalSpecHash(spec *buildSpec) (string, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseTemplateID(c *gin.Context) (uuid.UUID, error) {
	raw := c.Param("template_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("Invalid template_id: %q is not a valid UUID", raw),
			http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

func parseBuildID(c *gin.Context) (uuid.UUID, error) {
	raw := c.Param("build_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("Invalid build_id: %q is not a valid UUID", raw),
			http.StatusBadRequest)
		return uuid.Nil, err
	}
	return id, nil
}

func toTemplateResponse(t db.Template) templateResponse {
	resp := templateResponse{
		ID:         t.ID,
		TeamID:     t.TeamID,
		Alias:      t.Alias,
		Visibility: string(t.Visibility),
		Status:     string(t.Status),
		Vcpu:       t.Vcpu,
		MemoryMib:  t.MemoryMib,
		DiskMib:    t.DiskMib,
		CreatedAt:  t.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if t.SizeBytes != nil {
		resp.SizeBytes = t.SizeBytes
	}
	if t.ErrorMessage != nil {
		resp.ErrorMessage = t.ErrorMessage
	}
	if t.BuiltAt != nil {
		s := t.BuiltAt.UTC().Format("2006-01-02T15:04:05Z")
		resp.BuiltAt = &s
	}
	if len(t.BuildSpec) > 0 {
		var spec buildSpec
		if err := json.Unmarshal(t.BuildSpec, &spec); err == nil {
			resp.BuildSpec = &spec
		}
	}
	return resp
}

func toBuildResponse(b db.TemplateBuild) templateBuildResponse {
	resp := templateBuildResponse{
		ID:            b.ID,
		TemplateID:    b.TemplateID,
		Status:        string(b.Status),
		BuildSpecHash: b.BuildSpecHash,
		CreatedAt:     b.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if b.ErrorMessage != nil {
		resp.ErrorMessage = b.ErrorMessage
	}
	if b.StartedAt != nil {
		s := b.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
		resp.StartedAt = &s
	}
	if b.FinalizedAt != nil {
		s := b.FinalizedAt.UTC().Format("2006-01-02T15:04:05Z")
		resp.FinalizedAt = &s
	}
	return resp
}

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation. Used by CreateTemplateBuild to detect the idempotency race:
// two concurrent submits collide on uniq_template_build_inflight; the
// second one returns the existing row instead of erroring.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// ---------------------------------------------------------------------------
// Template CRUD
// ---------------------------------------------------------------------------

func (h *Handlers) CreateTemplate(c *gin.Context) {
	var req createTemplateRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Field validation (manual; bindJSONStrict doesn't honor `binding` tags).
	req.Alias = strings.TrimSpace(req.Alias)
	if req.Alias == "" || len(req.Alias) > maxAlias {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("alias is required and must be 1-%d characters", maxAlias),
			http.StatusBadRequest)
		return
	}
	visibility := db.TemplateVisibilityPrivate
	if req.Visibility != nil {
		switch *req.Visibility {
		case "private":
			visibility = db.TemplateVisibilityPrivate
		case "public":
			// V1: only the system team can publish public templates. Until
			// system_team_id wiring lands, reject all public submits with
			// a 403. Internal seeding bypasses the API.
			respondErrorMsg(c, "forbidden",
				"public visibility is reserved for system-curated templates",
				http.StatusForbidden)
			return
		default:
			respondErrorMsg(c, "bad_request",
				"visibility must be 'private' or 'public'",
				http.StatusBadRequest)
			return
		}
	}

	vcpu := int32(defaultVcpu)
	if req.Vcpu != nil {
		vcpu = *req.Vcpu
	}
	memMib := int32(defaultMemoryMi)
	if req.MemoryMib != nil {
		memMib = *req.MemoryMib
	}
	diskMib := int32(defaultDiskMib)
	if req.DiskMib != nil {
		diskMib = *req.DiskMib
	}
	if vcpu < 1 || vcpu > maxVcpu {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("vcpu must be 1-%d", maxVcpu), http.StatusBadRequest)
		return
	}
	if memMib < 256 || memMib > maxMemoryMib {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("memory_mib must be 256-%d", maxMemoryMib), http.StatusBadRequest)
		return
	}
	if diskMib < 1024 || diskMib > maxDiskMib {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("disk_mib must be 1024-%d", maxDiskMib), http.StatusBadRequest)
		return
	}
	if err := validateBuildSpec(req.BuildSpec); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	specJSON, err := json.Marshal(req.BuildSpec)
	if err != nil {
		log.Error().Err(err).Msg("marshal build_spec")
		respondError(c, ErrInternal)
		return
	}

	tpl, err := h.DB.CreateTemplate(c.Request.Context(), db.CreateTemplateParams{
		TeamID:     teamID,
		Alias:      req.Alias,
		Visibility: visibility,
		BuildSpec:  specJSON,
		Vcpu:       vcpu,
		MemoryMib:  memMib,
		DiskMib:    diskMib,
	})
	if err != nil {
		if isUniqueViolation(err) {
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("a template with alias %q already exists for this team", req.Alias),
				http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("CreateTemplate INSERT failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusCreated, toTemplateResponse(tpl))
}

func (h *Handlers) GetTemplate(c *gin.Context) {
	tplID, err := parseTemplateID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	tpl, err := h.DB.GetTemplate(c.Request.Context(), db.GetTemplateParams{
		ID:     tplID,
		TeamID: teamID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("template_id", tplID.String()).Msg("DB GetTemplate failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, toTemplateResponse(tpl))
}

func (h *Handlers) ListTemplates(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	visibility := c.Query("visibility")
	aliasPrefix := c.Query("alias_prefix")

	var rows []db.Template
	if visibility == "" && aliasPrefix == "" {
		rows, err = h.DB.ListTemplatesForTeam(c.Request.Context(), teamID)
	} else {
		params := db.ListTemplatesForTeamFilteredParams{TeamID: teamID}
		if visibility != "" {
			switch visibility {
			case "private":
				v := db.TemplateVisibilityPrivate
				params.Visibility = &v
			case "public":
				v := db.TemplateVisibilityPublic
				params.Visibility = &v
			default:
				respondErrorMsg(c, "bad_request",
					"visibility must be 'private' or 'public'",
					http.StatusBadRequest)
				return
			}
		}
		if aliasPrefix != "" {
			params.AliasPrefix = &aliasPrefix
		}
		rows, err = h.DB.ListTemplatesForTeamFiltered(c.Request.Context(), params)
	}
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB ListTemplates failed")
		respondError(c, ErrInternal)
		return
	}

	out := make([]templateResponse, 0, len(rows))
	for _, t := range rows {
		out = append(out, toTemplateResponse(t))
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) DeleteTemplate(c *gin.Context) {
	tplID, err := parseTemplateID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Refuse to delete a template that still has any non-destroyed sandbox
	// referencing it — active, paused, or failed. Paused sandboxes hold a
	// snapshot dependent on the template's files; failed rows hold lineage.
	// User must destroy dependents first.
	count, err := h.DB.CountLiveSandboxesForTemplate(c.Request.Context(), uuid.NullUUID{UUID: tplID, Valid: true})
	if err != nil {
		log.Error().Err(err).Str("template_id", tplID.String()).Msg("DB CountLiveSandboxesForTemplate failed")
		respondError(c, ErrInternal)
		return
	}
	if count > 0 {
		respondErrorMsg(c, "conflict",
			fmt.Sprintf("template has %d sandbox(es) (active, paused, or failed) still referencing it; destroy them first", count),
			http.StatusConflict)
		return
	}

	rows, err := h.DB.SoftDeleteTemplate(c.Request.Context(), db.SoftDeleteTemplateParams{
		ID:     tplID,
		TeamID: teamID,
	})
	if err != nil {
		log.Error().Err(err).Str("template_id", tplID.String()).Msg("DB SoftDeleteTemplate failed")
		respondError(c, ErrInternal)
		return
	}
	if rows == 0 {
		respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
		return
	}

	c.Status(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Template builds
// ---------------------------------------------------------------------------

func (h *Handlers) CreateTemplateBuild(c *gin.Context) {
	tplID, err := parseTemplateID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	tpl, err := h.DB.GetTemplateForOwner(c.Request.Context(), db.GetTemplateForOwnerParams{
		ID:     tplID,
		TeamID: teamID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("template_id", tplID.String()).Msg("DB GetTemplateForOwner failed")
		respondError(c, ErrInternal)
		return
	}

	// Per-team build concurrency check. Cheap: one COUNT plus one team
	// lookup. Race window between this check and the INSERT is small but
	// harmless — the worst case is one extra concurrent build.
	limit, err := h.DB.GetTeamBuildConcurrency(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB GetTeamBuildConcurrency failed")
		respondError(c, ErrInternal)
		return
	}
	inflight, err := h.DB.CountInFlightBuildsForTeam(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB CountInFlightBuildsForTeam failed")
		respondError(c, ErrInternal)
		return
	}
	if int64(limit) > 0 && inflight >= int64(limit) {
		respondErrorMsg(c, "rate_limited",
			fmt.Sprintf("per-team build concurrency limit reached (%d in flight)", inflight),
			http.StatusTooManyRequests)
		return
	}

	// Hash the template's persisted spec — we build whatever's currently
	// stored, not a fresh client-supplied spec. Editing a template's spec
	// is a separate (V2) concern; for V1 the spec is fixed at create time.
	var spec buildSpec
	if err := json.Unmarshal(tpl.BuildSpec, &spec); err != nil {
		log.Error().Err(err).Str("template_id", tplID.String()).Msg("unmarshal stored build_spec")
		respondError(c, ErrInternal)
		return
	}
	specHash, err := canonicalSpecHash(&spec)
	if err != nil {
		log.Error().Err(err).Msg("hash build_spec")
		respondError(c, ErrInternal)
		return
	}

	build, err := h.DB.CreateTemplateBuild(c.Request.Context(), db.CreateTemplateBuildParams{
		TemplateID:    tplID,
		TeamID:        teamID,
		BuildSpecHash: specHash,
	})
	if err != nil {
		if isUniqueViolation(err) {
			// Idempotent submit: another in-flight build for this template
			// with the same spec_hash already exists. Return it instead.
			existing, getErr := h.DB.GetExistingInflightBuild(c.Request.Context(), db.GetExistingInflightBuildParams{
				TemplateID:    tplID,
				BuildSpecHash: specHash,
			})
			if getErr == nil {
				c.JSON(http.StatusOK, toBuildResponse(existing))
				return
			}
			log.Error().Err(getErr).Msg("idempotent build lookup failed after unique violation")
		}
		log.Error().Err(err).Str("template_id", tplID.String()).Msg("DB CreateTemplateBuild failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusCreated, toBuildResponse(build))
}

func (h *Handlers) GetTemplateBuild(c *gin.Context) {
	buildID, err := parseBuildID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	build, err := h.DB.GetTemplateBuild(c.Request.Context(), db.GetTemplateBuildParams{
		ID:     buildID,
		TeamID: teamID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Build not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("build_id", buildID.String()).Msg("DB GetTemplateBuild failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusOK, toBuildResponse(build))
}

func (h *Handlers) ListTemplateBuilds(c *gin.Context) {
	tplID, err := parseTemplateID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	rows, err := h.DB.ListBuildsForTemplate(c.Request.Context(), db.ListBuildsForTemplateParams{
		TemplateID: tplID,
		TeamID:     teamID,
		Limit:      20,
	})
	if err != nil {
		log.Error().Err(err).Str("template_id", tplID.String()).Msg("DB ListBuildsForTemplate failed")
		respondError(c, ErrInternal)
		return
	}

	out := make([]templateBuildResponse, 0, len(rows))
	for _, b := range rows {
		out = append(out, toBuildResponse(b))
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) CancelTemplateBuild(c *gin.Context) {
	buildID, err := parseBuildID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// V1: cancel just records the terminal status. The supervisor (Day 6)
	// will pick this up on its next tick and call vmd.CancelBuild to tear
	// down the build VM. Until the supervisor exists, builds in 'pending'
	// are immediately effectively cancelled (nothing is running on them).
	rows, err := h.DB.CancelBuild(c.Request.Context(), db.CancelBuildParams{
		ID:     buildID,
		TeamID: teamID,
	})
	if err != nil {
		log.Error().Err(err).Str("build_id", buildID.String()).Msg("DB CancelBuild failed")
		respondError(c, ErrInternal)
		return
	}
	if rows == 0 {
		// Either not found, not yours, or already terminal. We don't
		// distinguish — terminal-already is functionally a no-op success.
		c.Status(http.StatusNoContent)
		return
	}
	c.Status(http.StatusNoContent)
}

// lookupTemplateForCreate resolves a from_template ref (UUID or alias) to a
// Template row that is visible to teamID. Writes a 4xx response and returns
// a non-nil error on failure so callers can early-return.
func (h *Handlers) lookupTemplateForCreate(c *gin.Context, teamID uuid.UUID, ref string) (db.Template, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		respondErrorMsg(c, "bad_request", "from_template is empty", http.StatusBadRequest)
		return db.Template{}, fmt.Errorf("empty ref")
	}
	if id, err := uuid.Parse(ref); err == nil {
		tpl, err := h.DB.GetTemplate(c.Request.Context(), db.GetTemplateParams{
			ID:     id,
			TeamID: teamID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
				return db.Template{}, err
			}
			log.Error().Err(err).Str("template_id", id.String()).Msg("DB GetTemplate failed")
			respondError(c, ErrInternal)
			return db.Template{}, err
		}
		return tpl, nil
	}
	tpl, err := h.DB.GetTemplateByAlias(c.Request.Context(), db.GetTemplateByAliasParams{
		Alias:  ref,
		TeamID: teamID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
			return db.Template{}, err
		}
		log.Error().Err(err).Str("alias", ref).Msg("DB GetTemplateByAlias failed")
		respondError(c, ErrInternal)
		return db.Template{}, err
	}
	return tpl, nil
}

// StreamTemplateBuildLogs is the SSE log stream endpoint. The real
// implementation streams ProcessEvent chunks from boxd via the build
// supervisor's in-memory log buffer (Day 11 in the implementation
// order). Until then, return 501 so SDKs can probe for support but not
// hang waiting for events that will never arrive.
func (h *Handlers) StreamTemplateBuildLogs(c *gin.Context) {
	respondErrorMsg(c, "not_implemented",
		"build log streaming is not yet wired (planned: Day 11)",
		http.StatusNotImplemented)
}
