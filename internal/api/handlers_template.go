package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
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
	Alias     string     `json:"alias"`
	Vcpu      *int32     `json:"vcpu,omitempty"`
	MemoryMib *int32     `json:"memory_mib,omitempty"`
	DiskMib   *int32     `json:"disk_mib,omitempty"`
	BuildSpec *buildSpec `json:"build_spec,omitempty"`
}

type templateResponse struct {
	ID           uuid.UUID `json:"id"`
	TeamID       uuid.UUID `json:"team_id"`
	Alias        string    `json:"alias"`
	Status       string    `json:"status"`
	Vcpu         int32     `json:"vcpu"`
	MemoryMib    int32     `json:"memory_mib"`
	DiskMib      int32     `json:"disk_mib"`
	SizeBytes    *int64    `json:"size_bytes,omitempty"`
	ErrorMessage *string   `json:"error_message,omitempty"`
	CreatedAt    string    `json:"created_at"`
	BuiltAt      *string   `json:"built_at,omitempty"`
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

// toTemplateResponse serializes a template for the API. build_spec is never
// included in responses — it can be large (base64-tar copy payloads) and can
// contain secrets (env steps). Callers that need the spec should read it
// server-side from the jsonb column directly.
func toTemplateResponse(t db.Template) templateResponse {
	resp := templateResponse{
		ID:        t.ID,
		TeamID:    t.TeamID,
		Alias:     t.Alias,
		Status:    string(t.Status),
		Vcpu:      t.Vcpu,
		MemoryMib: t.MemoryMib,
		DiskMib:   t.DiskMib,
		CreatedAt: t.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if t.SizeBytes != nil {
		resp.SizeBytes = t.SizeBytes
	}
	if t.ErrorMessage != nil {
		resp.ErrorMessage = t.ErrorMessage
	}
	if t.BuiltAt.Valid {
		s := t.BuiltAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		resp.BuiltAt = &s
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
	if b.StartedAt.Valid {
		s := b.StartedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		resp.StartedAt = &s
	}
	if b.FinalizedAt.Valid {
		s := b.FinalizedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
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

	// Compute the canonical hash before the DB call so template_build's
	// idempotency index can do its job on insert. The hash covers the
	// canonical JSON of the spec — same hash → same build.
	specHash, err := canonicalSpecHash(req.BuildSpec)
	if err != nil {
		log.Error().Err(err).Msg("hash build_spec")
		respondError(c, ErrInternal)
		return
	}

	row, err := h.DB.CreateTemplateWithBuild(c.Request.Context(), db.CreateTemplateWithBuildParams{
		TeamID:        teamID,
		Alias:         req.Alias,
		BuildSpec:     specJSON,
		Vcpu:          vcpu,
		MemoryMib:     memMib,
		DiskMib:       diskMib,
		BuildSpecHash: specHash,
	})
	if err != nil {
		if isUniqueViolation(err) {
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("a template with alias %q already exists for this team", req.Alias),
				http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("CreateTemplateWithBuild failed")
		respondError(c, ErrInternal)
		return
	}

	// Return 202 Accepted — the template row exists and a build is queued;
	// the caller polls GetTemplate / GetBuild for progress. Includes the
	// build_id so clients can also subscribe to log streams immediately.
	resp := toTemplateResponse(templateFromWithBuild(row))
	respBody := gin.H{
		"id":            resp.ID,
		"team_id":       resp.TeamID,
		"alias":         resp.Alias,
		"status":        resp.Status,
		"vcpu":          resp.Vcpu,
		"memory_mib":    resp.MemoryMib,
		"disk_mib":      resp.DiskMib,
		"created_at":    resp.CreatedAt,
		"build_id":      row.BuildID,
	}
	c.JSON(http.StatusAccepted, respBody)
}

// templateFromWithBuild adapts the flattened CreateTemplateWithBuild row
// into a plain db.Template so existing serialization helpers work.
func templateFromWithBuild(r db.CreateTemplateWithBuildRow) db.Template {
	return db.Template{
		ID:           r.ID,
		TeamID:       r.TeamID,
		Alias:        r.Alias,
		Status:       r.Status,
		BuildSpec:    r.BuildSpec,
		Vcpu:         r.Vcpu,
		MemoryMib:    r.MemoryMib,
		DiskMib:      r.DiskMib,
		RootfsPath:   r.RootfsPath,
		SnapshotPath: r.SnapshotPath,
		MemPath:      r.MemPath,
		SizeBytes:    r.SizeBytes,
		ErrorMessage: r.ErrorMessage,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
		BuiltAt:      r.BuiltAt,
		DeletedAt:    r.DeletedAt,
	}
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
		ID:       tplID,
		TeamID:   teamID,
		TeamID_2: h.systemTeamID(),
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

	aliasPrefix := c.Query("alias_prefix")

	var rows []db.Template
	if aliasPrefix == "" {
		rows, err = h.DB.ListTemplatesForTeam(c.Request.Context(), db.ListTemplatesForTeamParams{
			TeamID:   teamID,
			TeamID_2: h.systemTeamID(),
		})
	} else {
		rows, err = h.DB.ListTemplatesForTeamFiltered(c.Request.Context(), db.ListTemplatesForTeamFilteredParams{
			TeamID:      teamID,
			TeamID_2:    h.systemTeamID(),
			AliasPrefix: &aliasPrefix,
		})
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

// systemTeamID returns the configured system-team UUID, or uuid.Nil when
// unset. Passing uuid.Nil into the OR team_id = $N clause matches nothing
// extra — effectively disabling the system-templates shelf.
func (h *Handlers) systemTeamID() uuid.UUID {
	if h.Config == nil || h.Config.SystemTeamID == "" {
		return uuid.Nil
	}
	id, err := uuid.Parse(h.Config.SystemTeamID)
	if err != nil {
		log.Warn().Str("value", h.Config.SystemTeamID).Msg("SYSTEM_TEAM_ID is not a valid UUID; ignoring")
		return uuid.Nil
	}
	return id
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
	count, err := h.DB.CountLiveSandboxesForTemplate(c.Request.Context(), pgtype.UUID{Bytes: tplID, Valid: true})
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
			ID:       id,
			TeamID:   teamID,
			TeamID_2: h.systemTeamID(),
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
		Alias:    ref,
		TeamID:   teamID,
		TeamID_2: h.systemTeamID(),
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

// StreamTemplateBuildLogs is the SSE log stream endpoint. Bridges vmd's
// server-streaming StreamBuildLogs RPC into Server-Sent Events for the SDK.
//
// Flow:
//  1. Look up the template_build row (team scope check).
//  2. If no vmd_build_vm_id yet, build is still pending — emit a "pending"
//     system event and close. Client polls again.
//  3. Otherwise open vmd.StreamBuildLogs and re-emit each event as SSE.
//  4. Close when the stream sends Finished or the client disconnects.
func (h *Handlers) StreamTemplateBuildLogs(c *gin.Context) {
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

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return
	}

	writeEvent := func(ev gin.H) {
		data, marshalErr := json.Marshal(ev)
		if marshalErr != nil {
			return
		}
		fmt.Fprintf(c.Writer, "data: %s\n\n", data)
		flusher.Flush()
	}

	// Pending build: no vmd_build_vm_id yet, nothing to stream. Tell the
	// client explicitly and close — they can re-poll in a few seconds.
	if build.VmdBuildVmID == nil || *build.VmdBuildVmID == "" {
		writeEvent(gin.H{
			"timestamp": time.Now().Format(time.RFC3339Nano),
			"stream":    "system",
			"text":      "build is still pending (not yet dispatched to a host)",
			"finished":  true,
			"status":    string(build.Status),
		})
		return
	}

	// Resolve the vmd client for the host that's running this build. For
	// single-host V1 it's the default client; multi-host uses the host
	// registry. Missing host ID (shouldn't happen post-dispatch) falls
	// back to the default client.
	hostID := ""
	if build.VmdHostID != nil {
		hostID = *build.VmdHostID
	}
	vmdc, vmdErr := h.vmdForHost(c.Request.Context(), hostID)
	if vmdErr != nil {
		writeEvent(gin.H{
			"stream":   "system",
			"text":     "failed to reach build host",
			"finished": true,
			"status":   "failed",
		})
		log.Error().Err(vmdErr).Str("build_id", buildID.String()).Msg("resolve VMD for log stream")
		return
	}

	streamErr := vmdc.StreamBuildLogs(c.Request.Context(), *build.VmdBuildVmID, func(ev vmdclient.BuildLogEvent) error {
		writeEvent(gin.H{
			"timestamp": time.Unix(0, ev.TimestampUnixNanos).Format(time.RFC3339Nano),
			"stream":    ev.Stream,
			"text":      ev.Text,
			"finished":  ev.Finished,
			"status":    ev.Status,
		})
		return nil
	})
	if streamErr != nil {
		// The HTTP response committed 200 at header-send time, so we can't
		// downgrade the status. Emit a terminal error event so the client
		// knows what happened.
		writeEvent(gin.H{
			"stream":   "system",
			"text":     fmt.Sprintf("log stream ended with error: %v", streamErr),
			"finished": true,
			"status":   "failed",
		})
	}
}
