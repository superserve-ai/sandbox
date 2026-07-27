package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func validatePreviewAccess(value *string) error {
	if value == nil || *value == preview.AccessPublic || *value == preview.AccessPrivate {
		return nil
	}
	return fmt.Errorf("preview_access must be %q or %q", preview.AccessPublic, preview.AccessPrivate)
}

func validatePreviewPortAccess(value *string) error {
	if value == nil || *value == preview.AccessPublic || *value == preview.AccessPrivate {
		return nil
	}
	return fmt.Errorf("access must be %q or %q", preview.AccessPublic, preview.AccessPrivate)
}

func (h *Handlers) loadPreviewPorts(ctx context.Context, sandboxID uuid.UUID) (map[int32]vmdclient.PortPolicy, error) {
	rows, err := h.DB.ListPublishedPorts(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	return publishedPortPolicies(rows), nil
}

type previewPolicySnapshot struct {
	Access     string
	WireAccess string
	Revision   int64
	Ports      map[int32]vmdclient.PortPolicy
}

// vmdAccess is deliberately more restrictive than the DB default for a mixed
// policy. Phase 1 readers ignore per-port access, so persisting public beside a
// private bool-map entry would reopen that port after rollback.
func (p previewPolicySnapshot) vmdAccess() string {
	accesses := make([]string, 0, len(p.Ports))
	for _, policy := range p.Ports {
		accesses = append(accesses, policy.Access)
	}
	base := p.WireAccess
	if base == "" {
		base = p.Access
	}
	return preview.RestrictiveFallback(base, accesses...)
}

func (h *Handlers) loadPreviewPolicy(ctx context.Context, sandboxID, teamID uuid.UUID) (previewPolicySnapshot, error) {
	row, err := h.DB.GetSandboxPreviewPolicy(ctx, db.GetSandboxPreviewPolicyParams{ID: sandboxID, TeamID: teamID})
	if err != nil {
		return previewPolicySnapshot{}, err
	}
	return previewPolicySnapshot{Access: row.Access, WireAccess: row.WireAccess, Revision: row.Revision}, nil
}

func (h *Handlers) loadPreviewPolicySnapshot(ctx context.Context, sandboxID, teamID uuid.UUID) (previewPolicySnapshot, error) {
	policy, err := h.loadPreviewPolicy(ctx, sandboxID, teamID)
	if err != nil {
		return previewPolicySnapshot{}, err
	}
	policy.Ports, err = h.loadPreviewPorts(ctx, sandboxID)
	return policy, err
}

func publishedPortPolicies(ports []db.ListPublishedPortsRow) map[int32]vmdclient.PortPolicy {
	if len(ports) == 0 {
		return nil
	}
	out := make(map[int32]vmdclient.PortPolicy, len(ports))
	for _, port := range ports {
		out[port.Port] = vmdclient.PortPolicy{Access: port.Access}
	}
	return out
}

// applyPreviewMutation serializes publication changes on the sandbox row,
// performs the mutation, and reads the resulting full allowlist in the same
// transaction. The returned revision orders the later vmd pushes.
func (h *Handlers) applyPreviewMutation(ctx context.Context, sandboxID, teamID uuid.UUID, mutate func(*db.Queries) error) (previewPolicySnapshot, error) {
	run := func(q *db.Queries) (previewPolicySnapshot, error) {
		if _, err := q.LockSandboxForPreviewMutation(ctx, db.LockSandboxForPreviewMutationParams{ID: sandboxID, TeamID: teamID}); err != nil {
			if err == pgx.ErrNoRows {
				return previewPolicySnapshot{}, ErrSandboxNotFound
			}
			return previewPolicySnapshot{}, err
		}
		if err := q.EnsureSandboxPreviewPolicy(ctx, db.EnsureSandboxPreviewPolicyParams{
			SandboxID: sandboxID,
			Access:    preview.AccessLegacyPublic,
		}); err != nil {
			return previewPolicySnapshot{}, err
		}
		if err := mutate(q); err != nil {
			return previewPolicySnapshot{}, err
		}
		policy, err := q.AdvanceSandboxPreviewPolicy(ctx, sandboxID)
		if err != nil {
			return previewPolicySnapshot{}, err
		}
		ports, err := q.ListPublishedPorts(ctx, sandboxID)
		if err != nil {
			return previewPolicySnapshot{}, err
		}
		return previewPolicySnapshot{
			Access: policy.Access, WireAccess: policy.WireAccess,
			Revision: policy.Revision, Ports: publishedPortPolicies(ports),
		}, nil
	}

	if h.Pool == nil {
		return run(h.DB)
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return previewPolicySnapshot{}, err
	}
	defer tx.Rollback(ctx)
	policy, err := run(h.DB.WithTx(tx))
	if err != nil {
		return previewPolicySnapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return previewPolicySnapshot{}, err
	}
	return policy, nil
}

func (h *Handlers) pushPreviewPolicy(ctx context.Context, sandbox db.Sandbox, policy previewPolicySnapshot) error {
	vmd, err := h.vmdForHost(ctx, sandbox.HostID)
	if err != nil {
		return fmt.Errorf("resolve vmd: %w", err)
	}
	vmdCtx, cancel := context.WithTimeout(ctx, vmdTimeout)
	defer cancel()
	err = vmd.UpdateSandboxPreviewPolicy(vmdCtx, sandbox.ID.String(), policy.vmdAccess(), policy.Ports, policy.Revision)
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

func (h *Handlers) requireHostPreviewCapabilities(c *gin.Context, hostID string, capabilities ...string) bool {
	for _, capability := range capabilities {
		hasCapability, err := h.DB.HostHasCapability(c.Request.Context(), db.HostHasCapabilityParams{
			HostID: hostID, Capability: capability,
		})
		if err != nil {
			log.Error().Err(err).Str("host_id", hostID).Str("capability", capability).Msg("DB HostHasCapability failed")
			respondError(c, ErrInternal)
			return false
		}
		if !hasCapability {
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("The sandbox's host does not enforce %q; retry after the fleet is upgraded", capability),
				http.StatusConflict)
			return false
		}
	}
	return true
}

func (h *Handlers) requireHostPreviewPorts(c *gin.Context, hostID string) bool {
	return h.requireHostPreviewCapabilities(c, hostID, preview.HostCapabilityPorts)
}

func (h *Handlers) requireHostPreviewPortAccess(c *gin.Context, hostID string) bool {
	return h.requireHostPreviewCapabilities(c, hostID, preview.HostCapabilityPorts, preview.HostCapabilityPortAccess)
}

func parsePreviewPort(c *gin.Context) (int32, bool) {
	port, err := strconv.Atoi(c.Param("port"))
	if err != nil || port < int(preview.MinPublishedPort) || port > int(preview.MaxPublishedPort) {
		respondErrorMsg(c, "bad_request", fmt.Sprintf("port must be an integer in [%d, %d]", preview.MinPublishedPort, preview.MaxPublishedPort), http.StatusBadRequest)
		return 0, false
	}
	parsed := int32(port)
	if err := preview.ValidatePublishedPort(parsed); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return 0, false
	}
	return parsed, true
}

type publishedPortResponse struct {
	Port   int32  `json:"port"`
	Access string `json:"access"`
}

type listPreviewPortsResponse struct {
	PreviewAccess string                  `json:"preview_access"`
	Ports         []publishedPortResponse `json:"ports"`
}

func (h *Handlers) ListSandboxPreviewPorts(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxRead(c, teamID) {
		return
	}
	_, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}
	policy, err := h.loadPreviewPolicy(c.Request.Context(), sandboxID, teamID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandboxPreviewPolicy failed")
		respondError(c, ErrInternal)
		return
	}
	rows, err := h.DB.ListPublishedPorts(c.Request.Context(), sandboxID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB ListPublishedPorts failed")
		respondError(c, ErrInternal)
		return
	}
	ports := make([]publishedPortResponse, 0, len(rows))
	for _, port := range rows {
		ports = append(ports, publishedPortResponse{Port: port.Port, Access: port.Access})
	}
	c.JSON(http.StatusOK, listPreviewPortsResponse{PreviewAccess: policy.Access, Ports: ports})
}

type publishPortRequest struct {
	Port   int32   `json:"port"`
	Access *string `json:"access,omitempty"`
}

func (h *Handlers) PublishSandboxPreviewPort(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	var body publishPortRequest
	if err := bindJSONStrict(c, &body); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := preview.ValidatePublishedPort(body.Port); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePreviewPortAccess(body.Access); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}
	if body.Access != nil && *body.Access == preview.AccessPrivate {
		current, err := h.loadPreviewPolicy(c.Request.Context(), sandboxID, teamID)
		if err != nil {
			log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("load preview policy before private publication failed")
			respondError(c, ErrInternal)
			return
		}
		if current.Access == preview.AccessLegacyPublic {
			respondErrorMsg(c, "conflict", "legacy_public routes every port; PATCH preview_access to public or private before publishing a private port", http.StatusConflict)
			return
		}
	}
	if !h.requireHostPreviewPortAccess(c, sandbox.HostID) {
		return
	}

	var published db.PublishPortRow
	policy, err := h.applyPreviewMutation(c.Request.Context(), sandboxID, teamID, func(q *db.Queries) error {
		var mutationErr error
		published, mutationErr = q.PublishPort(c.Request.Context(), db.PublishPortParams{
			SandboxID: sandboxID,
			Port:      body.Port,
			Access:    body.Access,
		})
		return mutationErr
	})
	if !h.handlePreviewMutationResult(c, sandboxID, "PublishPort", err) || !h.pushAfterPreviewMutation(c, sandbox, policy) {
		return
	}

	detail, _ := json.Marshal(map[string]any{"port": body.Port, "access": published.Access})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_port_published", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_port_published", map[string]any{"sandbox_id": sandboxID.String(), "port": body.Port})
	c.JSON(http.StatusOK, publishedPortResponse{Port: published.Port, Access: published.Access})
}

// Unpublish is idempotent and retry-safe. Even when the row is already absent,
// it advances the revision and re-pushes the authoritative allowlist so a
// failed earlier attempt can always be repaired by repeating DELETE.
func (h *Handlers) UnpublishSandboxPreviewPort(c *gin.Context) {
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}
	port, ok := parsePreviewPort(c)
	if !ok {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSandboxWrite(c, teamID) {
		return
	}
	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}

	var deleted int64
	policy, err := h.applyPreviewMutation(c.Request.Context(), sandboxID, teamID, func(q *db.Queries) error {
		var mutationErr error
		deleted, mutationErr = q.UnpublishPort(c.Request.Context(), db.UnpublishPortParams{SandboxID: sandboxID, Port: port})
		return mutationErr
	})
	if !h.handlePreviewMutationResult(c, sandboxID, "UnpublishPort", err) || !h.pushAfterPreviewMutation(c, sandbox, policy) {
		return
	}
	if deleted > 0 {
		detail, _ := json.Marshal(map[string]any{"port": port})
		h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_port_unpublished", "success", &sandbox.Name, nil, detail)
		h.capture(c, "sandbox_preview_port_unpublished", map[string]any{"sandbox_id": sandboxID.String(), "port": port})
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) handlePreviewMutationResult(c *gin.Context, sandboxID uuid.UUID, operation string, err error) bool {
	if err == nil {
		return true
	}
	if err == ErrSandboxNotFound {
		respondError(c, ErrSandboxNotFound)
		return false
	}
	log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Str("operation", operation).Msg("preview mutation failed")
	respondError(c, ErrInternal)
	return false
}

func (h *Handlers) pushAfterPreviewMutation(c *gin.Context, sandbox db.Sandbox, policy previewPolicySnapshot) bool {
	if err := h.pushPreviewPolicy(c.Request.Context(), sandbox, policy); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("push preview policy failed; retry to converge")
		respondError(c, ErrInternal)
		return false
	}
	return true
}

func (h *Handlers) getTeamSandbox(c *gin.Context, sandboxID, teamID uuid.UUID) (db.Sandbox, bool) {
	sandbox, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{ID: sandboxID, TeamID: teamID})
	if err == pgx.ErrNoRows {
		respondError(c, ErrSandboxNotFound)
		return db.Sandbox{}, false
	}
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return db.Sandbox{}, false
	}
	return sandbox, true
}
