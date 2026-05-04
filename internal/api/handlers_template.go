package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// ---------------------------------------------------------------------------
// Request / response shapes (handler-local; persisted shapes live in db.Models)
// ---------------------------------------------------------------------------

type buildStep struct {
	Run     *string      `json:"run,omitempty"`
	Env     *buildEnvOp  `json:"env,omitempty"`
	Workdir *string      `json:"workdir,omitempty"`
	User    *buildUserOp `json:"user,omitempty"`
}

type buildEnvOp struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type buildUserOp struct {
	Name string `json:"name"`
	Sudo bool   `json:"sudo,omitempty"`
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
	Name      string     `json:"name"`
	Vcpu      *int32     `json:"vcpu,omitempty"`
	MemoryMib *int32     `json:"memory_mib,omitempty"`
	DiskMib   *int32     `json:"disk_mib,omitempty"`
	BuildSpec *buildSpec `json:"build_spec,omitempty"`
}

type templateResponse struct {
	ID           uuid.UUID `json:"id"`
	TeamID       uuid.UUID `json:"team_id"`
	Name         string    `json:"name"`
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
	maxName = 128

	// Platform ceiling — applies to every team including system.
	absoluteMaxVcpu      = 4
	absoluteMaxMemoryMib = 4096
	absoluteMaxDiskMib   = 8192

	// Customer-team defaults (overridable via team.max_template_*).
	defaultMaxVcpu      = 2
	defaultMaxMemoryMib = 2048
	defaultMaxDiskMib   = 8192
	defaultMaxTemplates = 10
	defaultMaxSandboxes = 50

	defaultVcpu     = 1
	defaultMemoryMi = 1024
	defaultDiskMib  = 4096
)

// templateNameRE restricts template names to lowercase alphanumeric with
// `.`, `_`, `/`, `-` in the middle. URL-safe, shell-safe, no Unicode.
var templateNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/-]*[a-z0-9])?$`)

// validateTemplateShape returns a user-facing error message on failure, "" on pass.
func validateTemplateShape(team db.Team, systemTeamID uuid.UUID, vcpu, memMib, diskMib int32) string {
	if vcpu < 1 || vcpu > absoluteMaxVcpu {
		return fmt.Sprintf("vcpu must be 1-%d", absoluteMaxVcpu)
	}
	if memMib < 256 || memMib > absoluteMaxMemoryMib {
		return fmt.Sprintf("memory_mib must be 256-%d", absoluteMaxMemoryMib)
	}
	if diskMib < 1024 || diskMib > absoluteMaxDiskMib {
		return fmt.Sprintf("disk_mib must be 1024-%d", absoluteMaxDiskMib)
	}
	if team.ID == systemTeamID {
		return ""
	}
	effMaxVcpu := int32(defaultMaxVcpu)
	if team.MaxTemplateVcpu != nil {
		effMaxVcpu = *team.MaxTemplateVcpu
	}
	if vcpu > effMaxVcpu {
		return fmt.Sprintf("vcpu must be 1-%d (your team's limit); contact support@superserve.ai for higher", effMaxVcpu)
	}
	effMaxMem := int32(defaultMaxMemoryMib)
	if team.MaxTemplateMemoryMib != nil {
		effMaxMem = *team.MaxTemplateMemoryMib
	}
	if memMib > effMaxMem {
		return fmt.Sprintf("memory_mib must be 256-%d (your team's limit); contact support@superserve.ai for higher", effMaxMem)
	}
	effMaxDisk := int32(defaultMaxDiskMib)
	if team.MaxTemplateDiskMib != nil {
		effMaxDisk = *team.MaxTemplateDiskMib
	}
	if diskMib > effMaxDisk {
		return fmt.Sprintf("disk_mib must be 1024-%d (your team's limit); contact support@superserve.ai for higher", effMaxDisk)
	}
	return ""
}

// validateBuildSpec enforces base-image policy and step-shape invariants.
// Catches obvious problems (alpine, distroless, bad step shape) before we
// persist a row or hand off to the builder.
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
		return fmt.Errorf("alpine bases are not supported (musl + non-systemd init); use a debian/ubuntu-based image")
	}
	if strings.Contains(low, "distroless") {
		return fmt.Errorf("distroless bases are not supported (no shell for RUN steps)")
	}
	for i, step := range spec.Steps {
		set := 0
		if step.Run != nil {
			set++
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
		if step.User != nil {
			set++
			if err := validateUserName(step.User.Name); err != nil {
				return fmt.Errorf("build_spec.steps[%d].user: %w", i, err)
			}
		}
		if set != 1 {
			return fmt.Errorf("build_spec.steps[%d] must set exactly one of run/env/workdir/user", i)
		}
	}
	return nil
}

// validateUserName enforces a conservative Linux-username policy so we
// don't shell-inject or collide with system accounts. Follows useradd's
// NAME_REGEX: lowercase letter/underscore, then letters/digits/_/- up to
// 31 chars total.
func validateUserName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > 31 {
		return fmt.Errorf("name exceeds 31 characters")
	}
	first := name[0]
	if !(first == '_' || (first >= 'a' && first <= 'z')) {
		return fmt.Errorf("name must start with a lowercase letter or underscore")
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return fmt.Errorf("name contains invalid character %q", c)
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

// acquireBuildSlot begins a tx, takes a per-team advisory lock, verifies
// capacity, and returns a tx-bound *db.Queries for the caller to insert
// into. Caller commits to finalize; defer Rollback as a safety net.
// On limit exceeded or DB error the response is already written and
// (nil, nil) is returned — caller just returns.
func (h *Handlers) acquireBuildSlot(c *gin.Context, teamID uuid.UUID) (*db.Queries, pgx.Tx) {
	ctx := c.Request.Context()
	tx, err := h.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("BeginTx for build admission failed")
		respondError(c, ErrInternal)
		return nil, nil
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", teamID.String()); err != nil {
		_ = tx.Rollback(ctx)
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("pg_advisory_xact_lock failed")
		respondError(c, ErrInternal)
		return nil, nil
	}
	q := h.DB.WithTx(tx)
	limit, err := q.GetTeamBuildConcurrency(ctx, teamID)
	if err != nil {
		_ = tx.Rollback(ctx)
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB GetTeamBuildConcurrency failed")
		respondError(c, ErrInternal)
		return nil, nil
	}
	active, err := q.CountInFlightBuildsForTeam(ctx, teamID)
	if err != nil {
		_ = tx.Rollback(ctx)
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB CountInFlightBuildsForTeam failed")
		respondError(c, ErrInternal)
		return nil, nil
	}
	if int64(limit) > 0 && active >= int64(limit) {
		_ = tx.Rollback(ctx)
		respondErrorMsg(c, "too_many_builds",
			fmt.Sprintf("team has reached the maximum of %d concurrent builds; contact support to raise the limit", limit),
			http.StatusTooManyRequests)
		return nil, nil
	}
	return q, tx
}

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
// included in responses — it can contain secrets (env steps). Callers that
// need the spec should read it server-side from the jsonb column directly.
func toTemplateResponse(t db.Template) templateResponse {
	resp := templateResponse{
		ID:        t.ID,
		TeamID:    t.TeamID,
		Name:      t.Name,
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
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Field validation (manual; bindJSONStrict doesn't honor `binding` tags).
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > maxName {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("name is required and must be 1-%d characters", maxName),
			http.StatusBadRequest)
		return
	}
	if !templateNameRE.MatchString(req.Name) {
		respondErrorMsg(c, "bad_request",
			"name must be lowercase, start and end with a letter or digit, and contain only letters, digits, '.', '_', '/', '-'",
			http.StatusBadRequest)
		return
	}
	// `superserve/` is reserved for curated templates owned by the system team.
	if strings.HasPrefix(req.Name, "superserve/") && teamID != h.systemTeamID() {
		respondErrorMsg(c, "bad_request",
			"names starting with 'superserve/' are reserved",
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
	team, err := h.DB.GetTeam(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB GetTeam failed")
		respondError(c, ErrInternal)
		return
	}
	if msg := validateTemplateShape(team, h.systemTeamID(), vcpu, memMib, diskMib); msg != "" {
		respondErrorMsg(c, "bad_request", msg, http.StatusBadRequest)
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

	// Gate on per-team concurrency and do the insert under the same tx,
	// so concurrent submits serialize cleanly.
	ctx := c.Request.Context()
	q, tx := h.acquireBuildSlot(c, teamID)
	if q == nil {
		return
	}
	defer tx.Rollback(ctx)

	// Per-team template count cap. Inside the advisory lock so concurrent
	// submits at limit-1 don't both pass. System team is exempt.
	if teamID != h.systemTeamID() {
		count, err := q.CountActiveTemplatesForTeam(ctx, teamID)
		if err != nil {
			log.Error().Err(err).Str("team_id", teamID.String()).Msg("DB CountActiveTemplatesForTeam failed")
			respondError(c, ErrInternal)
			return
		}
		effMaxTemplates := int64(defaultMaxTemplates)
		if team.MaxTemplates != nil {
			effMaxTemplates = int64(*team.MaxTemplates)
		}
		if count >= effMaxTemplates {
			respondErrorMsg(c, "too_many_templates",
				fmt.Sprintf("team has reached the limit of %d templates; delete some or contact support@superserve.ai for higher", effMaxTemplates),
				http.StatusTooManyRequests)
			return
		}
	}

	row, err := q.CreateTemplateWithBuild(ctx, db.CreateTemplateWithBuildParams{
		TeamID:        teamID,
		Name:          req.Name,
		BuildSpec:     specJSON,
		Vcpu:          vcpu,
		MemoryMib:     memMib,
		DiskMib:       diskMib,
		BuildSpecHash: specHash,
	})
	if err != nil {
		if isUniqueViolation(err) {
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("a template with name %q already exists for this team", req.Name),
				http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("CreateTemplateWithBuild failed")
		respondError(c, ErrInternal)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit CreateTemplateWithBuild failed")
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
		"name":          resp.Name,
		"status":        resp.Status,
		"vcpu":          resp.Vcpu,
		"memory_mib":    resp.MemoryMib,
		"disk_mib":      resp.DiskMib,
		"created_at":    resp.CreatedAt,
		"build_id":      row.BuildID,
	}
	c.JSON(http.StatusAccepted, respBody)

	h.logTemplateActivity(c.Request.Context(), row.ID, teamID, "template", "created", "success", nil)
	h.logTemplateActivity(c.Request.Context(), row.ID, teamID, "template", "build_started", "success",
		buildMetadata(row.BuildID))
}

func buildMetadata(buildID uuid.UUID) []byte {
	b, _ := json.Marshal(map[string]string{"build_id": buildID.String()})
	return b
}

// templateFromWithBuild adapts the flattened CreateTemplateWithBuild row
// into a plain db.Template so existing serialization helpers work.
func templateFromWithBuild(r db.CreateTemplateWithBuildRow) db.Template {
	return db.Template{
		ID:           r.ID,
		TeamID:       r.TeamID,
		Name:         r.Name,
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

	namePrefix := c.Query("name_prefix")

	var rows []db.Template
	if namePrefix == "" {
		rows, err = h.DB.ListTemplatesForTeam(c.Request.Context(), db.ListTemplatesForTeamParams{
			TeamID:   teamID,
			TeamID_2: h.systemTeamID(),
		})
	} else {
		rows, err = h.DB.ListTemplatesForTeamFiltered(c.Request.Context(), db.ListTemplatesForTeamFilteredParams{
			TeamID:     teamID,
			TeamID_2:   h.systemTeamID(),
			NamePrefix: &namePrefix,
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

	res, err := h.DB.SoftDeleteTemplateIfUnused(c.Request.Context(), db.SoftDeleteTemplateIfUnusedParams{
		ID:     tplID,
		TeamID: teamID,
	})
	if err != nil {
		log.Error().Err(err).Str("template_id", tplID.String()).Msg("DB SoftDeleteTemplateIfUnused failed")
		respondError(c, ErrInternal)
		return
	}
	if !res.Found {
		respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
		return
	}
	if !res.Deleted {
		switch {
		case res.LiveCount > 0:
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("template has %d sandbox(es) (active, paused, or failed) still referencing it; destroy them first", res.LiveCount),
				http.StatusConflict)
		case res.InflightBuildCount > 0:
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("template has %d in-flight build(s); cancel them first", res.InflightBuildCount),
				http.StatusConflict)
		default:
			respondError(c, ErrInternal)
		}
		return
	}

	c.Status(http.StatusNoContent)
	h.logTemplateActivity(c.Request.Context(), tplID, teamID, "template", "deleted", "success", nil)

	// Drop the on-disk snapshot + rootfs. Safe because SoftDeleteTemplateIfUnused
	// blocks while any build is in flight, so no template-builder is
	// currently writing into these dirs.
	if h.VMD != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), vmdTimeout)
		defer cancel()
		if err := h.VMD.DeleteTemplateArtifacts(ctx, tplID.String()); err != nil {
			log.Warn().Err(err).Str("template_id", tplID.String()).Msg("vmd DeleteTemplateArtifacts failed; manual cleanup may be required")
		}
	}
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

	// Hash the template's persisted spec — we build whatever's currently
	// stored, not a fresh client-supplied spec. The spec is fixed at
	// template create time.
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

	ctx := c.Request.Context()
	q, tx := h.acquireBuildSlot(c, teamID)
	if q == nil {
		return
	}
	defer tx.Rollback(ctx)

	build, err := q.CreateTemplateBuild(ctx, db.CreateTemplateBuildParams{
		TemplateID:    tplID,
		TeamID:        teamID,
		BuildSpecHash: specHash,
	})
	if err != nil {
		if isUniqueViolation(err) {
			// Idempotent submit: another in-flight build for this template
			// with the same spec_hash already exists. Return it instead.
			// The existing row doesn't consume a new slot, so roll back the
			// admission txn before responding — GetExistingInflightBuild
			// runs outside the lock since it's read-only.
			_ = tx.Rollback(ctx)
			existing, getErr := h.DB.GetExistingInflightBuild(ctx, db.GetExistingInflightBuildParams{
				TemplateID:    tplID,
				TeamID:        teamID,
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
	if err := tx.Commit(ctx); err != nil {
		log.Error().Err(err).Str("team_id", teamID.String()).Msg("commit CreateTemplateBuild failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusCreated, toBuildResponse(build))
	h.logTemplateActivity(c.Request.Context(), tplID, teamID, "template", "build_started", "success",
		buildMetadata(build.ID))
}

func (h *Handlers) GetTemplateBuild(c *gin.Context) {
	tplID, err := parseTemplateID(c)
	if err != nil {
		return
	}
	buildID, err := parseBuildID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	build, err := h.DB.GetTemplateBuild(c.Request.Context(), db.GetTemplateBuildParams{
		ID:         buildID,
		TemplateID: tplID,
		TeamID:     teamID,
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
	tplID, err := parseTemplateID(c)
	if err != nil {
		return
	}
	buildID, err := parseBuildID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	// Pre-check scope so we can return 404 for wrong team/template instead
	// of silently 204'ing.
	if _, err := h.DB.GetTemplateBuild(c.Request.Context(), db.GetTemplateBuildParams{
		ID:         buildID,
		TemplateID: tplID,
		TeamID:     teamID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Build not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("build_id", buildID.String()).Msg("DB GetTemplateBuild failed")
		respondError(c, ErrInternal)
		return
	}

	// Cancel is idempotent on terminal builds (0 rows when status is already
	// ready/failed/cancelled). Supervisor picks it up on its next tick.
	if _, err := h.DB.CancelBuild(c.Request.Context(), db.CancelBuildParams{
		ID:         buildID,
		TemplateID: tplID,
		TeamID:     teamID,
	}); err != nil {
		log.Error().Err(err).Str("build_id", buildID.String()).Msg("DB CancelBuild failed")
		respondError(c, ErrInternal)
		return
	}
	c.Status(http.StatusNoContent)
	h.logTemplateActivity(c.Request.Context(), tplID, teamID, "template", "build_cancelled", "success",
		buildMetadata(buildID))
}

// lookupTemplateForCreate resolves a from_template ref (UUID or name) to a
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
	tpl, err := h.DB.GetTemplateByName(c.Request.Context(), db.GetTemplateByNameParams{
		Name:     ref,
		TeamID:   teamID,
		TeamID_2: h.systemTeamID(),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Template not found", http.StatusNotFound)
			return db.Template{}, err
		}
		log.Error().Err(err).Str("name", ref).Msg("DB GetTemplateByName failed")
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
	tplID, err := parseTemplateID(c)
	if err != nil {
		return
	}
	buildID, err := parseBuildID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	build, err := h.DB.GetTemplateBuild(c.Request.Context(), db.GetTemplateBuildParams{
		ID:         buildID,
		TemplateID: tplID,
		TeamID:     teamID,
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

	// Wait for the build to be dispatched to vmd (or transition terminal
	// without ever being dispatched, e.g. supervisor couldn't find the
	// template). Heartbeat each tick so SDKs don't treat the silence as
	// a finished stream and disconnect prematurely.
	for build.VmdBuildVmID == nil || *build.VmdBuildVmID == "" {
		if build.Status == db.TemplateBuildStatusFailed ||
			build.Status == db.TemplateBuildStatusCancelled ||
			build.Status == db.TemplateBuildStatusReady {
			msg := "build " + string(build.Status)
			if build.ErrorMessage != nil && *build.ErrorMessage != "" {
				msg = *build.ErrorMessage
			}
			writeEvent(gin.H{
				"timestamp": time.Now().Format(time.RFC3339Nano),
				"stream":    "system",
				"text":      msg,
				"finished":  true,
				"status":    string(build.Status),
			})
			return
		}

		writeEvent(gin.H{
			"timestamp": time.Now().Format(time.RFC3339Nano),
			"stream":    "system",
			"text":      "build queued, waiting for dispatch",
			"finished":  false,
		})

		select {
		case <-c.Request.Context().Done():
			return
		case <-time.After(2 * time.Second):
		}

		build, err = h.DB.GetTemplateBuild(c.Request.Context(), db.GetTemplateBuildParams{
			ID:         buildID,
			TemplateID: tplID,
			TeamID:     teamID,
		})
		if err != nil {
			writeEvent(gin.H{
				"stream":   "system",
				"text":     "failed to look up build",
				"finished": true,
				"status":   "failed",
			})
			log.Error().Err(err).Str("build_id", buildID.String()).Msg("re-fetch build during pending wait")
			return
		}
	}

	// Resolve the vmd client for the host running this build; falls back
	// to the default client when the host ID is absent.
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
