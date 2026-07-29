package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

const maxPreviewTokenExpirySeconds = 7 * 24 * 60 * 60

var (
	errPreviewPortNotPublished = errors.New("preview port is not published")
	errPreviewPortIsPublic     = errors.New("preview port is public")
	errPreviewTokenSeedInvalid = errors.New("preview token signing seed is unavailable")
	errPreviewTokenSnapshot    = errors.New("preview token snapshot does not match the durable generation")
)

type missingHostPreviewCapabilityError struct {
	capability string
}

func (e *missingHostPreviewCapabilityError) Error() string {
	return fmt.Sprintf("host does not advertise %q", e.capability)
}

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
		wireAccess := port.Access
		if wireAccess == preview.AccessPrivate {
			wireAccess = preview.AccessPrivateBrowserV1
		}
		out[port.Port] = vmdclient.PortPolicy{Access: wireAccess, TokenVersion: port.TokenVersion}
	}
	return out
}

// vmdPorts strips credential generations from non-tokenized modes. The
// control-plane snapshot retains them so API publication responses can report
// the durable generation for public ports too, but public wire records have no
// reason to carry credential state.
func (p previewPolicySnapshot) vmdPorts() map[int32]vmdclient.PortPolicy {
	if len(p.Ports) == 0 {
		return nil
	}
	out := make(map[int32]vmdclient.PortPolicy, len(p.Ports))
	for port, policy := range p.Ports {
		if !preview.IsTokenizedAccess(policy.Access) {
			policy.TokenVersion = 0
		}
		out[port] = policy
	}
	return out
}

func (p previewPolicySnapshot) requiresBrowserCapability() bool {
	if p.Access == preview.AccessPrivate {
		return true
	}
	return p.hasPrivatePorts()
}

func (p previewPolicySnapshot) hasPrivatePorts() bool {
	for _, port := range p.Ports {
		if preview.IsPrivateAccess(port.Access) {
			return true
		}
	}
	return false
}

func publicationRequiresBrowserAuth(current previewPolicySnapshot, target int32, requestedAccess *string) bool {
	targetExists := false
	for port, policy := range current.Ports {
		access := policy.Access
		if port == target {
			targetExists = true
			if requestedAccess != nil {
				access = *requestedAccess
			}
		}
		if preview.IsPrivateAccess(access) {
			return true
		}
	}
	if targetExists {
		return false
	}
	if requestedAccess != nil {
		return *requestedAccess == preview.AccessPrivate
	}
	return current.Access == preview.AccessPrivate
}

// applyPreviewMutation serializes publication changes on the sandbox row,
// performs the mutation, and reads the resulting full allowlist in the same
// transaction. The returned revision orders the later vmd pushes.
func (h *Handlers) applyPreviewMutation(ctx context.Context, sandboxID, teamID uuid.UUID, mutate func(*db.Queries) error) (previewPolicySnapshot, error) {
	return h.applyPreviewMutationValidated(ctx, sandboxID, teamID, mutate, nil)
}

// previewMutationFinalize runs after the exact post-mutation snapshot has been
// read while the sandbox row lock is still held. rollbackErr aborts the
// mutation. outcomeErr is returned only after a successful commit, for
// operations such as token rotation where revocation must remain durable even
// if replacement delivery fails.
type previewMutationFinalize func(*db.Queries, previewPolicySnapshot) (outcomeErr, rollbackErr error)

func (h *Handlers) applyPreviewMutationFinalized(ctx context.Context, sandboxID, teamID uuid.UUID, mutate func(*db.Queries) error, finalize previewMutationFinalize) (previewPolicySnapshot, error, error) {
	run := func(q *db.Queries) (previewPolicySnapshot, error, error) {
		if _, err := q.LockSandboxForPreviewMutation(ctx, db.LockSandboxForPreviewMutationParams{ID: sandboxID, TeamID: teamID}); err != nil {
			if err == pgx.ErrNoRows {
				return previewPolicySnapshot{}, nil, ErrSandboxNotFound
			}
			return previewPolicySnapshot{}, nil, err
		}
		if err := q.EnsureSandboxPreviewPolicy(ctx, db.EnsureSandboxPreviewPolicyParams{
			SandboxID: sandboxID,
			Access:    preview.AccessLegacyPublic,
		}); err != nil {
			return previewPolicySnapshot{}, nil, err
		}
		if err := mutate(q); err != nil {
			return previewPolicySnapshot{}, nil, err
		}
		policy, err := q.AdvanceSandboxPreviewPolicy(ctx, sandboxID)
		if err != nil {
			return previewPolicySnapshot{}, nil, err
		}
		ports, err := q.ListPublishedPorts(ctx, sandboxID)
		if err != nil {
			return previewPolicySnapshot{}, nil, err
		}
		result := previewPolicySnapshot{
			Access: policy.Access, WireAccess: policy.WireAccess,
			Revision: policy.Revision, Ports: publishedPortPolicies(ports),
		}
		if finalize == nil {
			return result, nil, nil
		}
		outcomeErr, rollbackErr := finalize(q, result)
		if rollbackErr != nil {
			return previewPolicySnapshot{}, nil, rollbackErr
		}
		return result, outcomeErr, nil
	}

	if h.Pool == nil {
		return run(h.DB)
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return previewPolicySnapshot{}, nil, err
	}
	defer tx.Rollback(ctx)
	policy, outcomeErr, mutationErr := run(h.DB.WithTx(tx))
	if mutationErr != nil {
		return previewPolicySnapshot{}, nil, mutationErr
	}
	if err := tx.Commit(ctx); err != nil {
		return previewPolicySnapshot{}, nil, err
	}
	return policy, outcomeErr, nil
}

// applyPreviewMutationValidated is applyPreviewMutation with a final
// transaction-local invariant check over the exact snapshot that would be
// committed. It closes the TOCTOU window between an inferred/private mutation
// and host-capability gating: a failed validation rolls back both the mutation
// and revision advance.
func (h *Handlers) applyPreviewMutationValidated(ctx context.Context, sandboxID, teamID uuid.UUID, mutate func(*db.Queries) error, validate func(*db.Queries, previewPolicySnapshot) error) (previewPolicySnapshot, error) {
	policy, _, err := h.applyPreviewMutationFinalized(ctx, sandboxID, teamID, mutate, func(q *db.Queries, result previewPolicySnapshot) (error, error) {
		if validate == nil {
			return nil, nil
		}
		return nil, validate(q, result)
	})
	return policy, err
}

func validateHostPreviewCapabilities(ctx context.Context, q *db.Queries, hostID string, capabilities ...string) error {
	ok, err := q.HostHasCapabilities(ctx, db.HostHasCapabilitiesParams{
		HostID: hostID, RequiredCapabilities: capabilities,
	})
	if err != nil {
		return err
	}
	if !ok {
		return &missingHostPreviewCapabilityError{capability: strings.Join(capabilities, `", "`)}
	}
	return nil
}

func previewBrowserCapabilities() []string {
	return []string{
		preview.HostCapabilityPorts,
		preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortTokens,
		preview.HostCapabilityPortBrowserAuth,
	}
}

func validateHostPreviewBrowserCapabilities(ctx context.Context, q *db.Queries, hostID string) error {
	return validateHostPreviewCapabilities(ctx, q, hostID, previewBrowserCapabilities()...)
}

func validateHostForPreviewSnapshot(ctx context.Context, q *db.Queries, hostID string, policy previewPolicySnapshot) error {
	if policy.requiresBrowserCapability() {
		return validateHostPreviewBrowserCapabilities(ctx, q, hostID)
	}
	return validateHostPreviewCapabilities(ctx, q, hostID,
		preview.HostCapabilityPorts,
		preview.HostCapabilityPortAccess,
	)
}

func (h *Handlers) pushPreviewPolicy(ctx context.Context, sandbox db.Sandbox, policy previewPolicySnapshot) error {
	vmd, err := h.vmdForHost(ctx, sandbox.HostID)
	if err != nil {
		return fmt.Errorf("resolve vmd: %w", err)
	}
	vmdCtx, cancel := context.WithTimeout(ctx, vmdTimeout)
	defer cancel()
	err = vmd.UpdateSandboxPreviewPolicy(vmdCtx, sandbox.ID.String(), policy.vmdAccess(), policy.vmdPorts(), policy.Revision)
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

// Credential issuance has stricter delivery semantics than an ordinary
// policy mutation. A paused sandbox legitimately has no live VMD record and
// will receive the authoritative snapshot on resume. For every other state,
// NotFound means token enforcement has not been activated, so no credential
// may be returned.
func (h *Handlers) pushPreviewCredentialPolicy(ctx context.Context, sandbox db.Sandbox, policy previewPolicySnapshot) (string, error) {
	vmd, err := h.vmdForHost(ctx, sandbox.HostID)
	if err != nil {
		return "delivery_failed", fmt.Errorf("resolve vmd: %w", err)
	}
	vmdCtx, cancel := context.WithTimeout(ctx, vmdTimeout)
	defer cancel()
	err = vmd.UpdateSandboxPreviewPolicy(vmdCtx, sandbox.ID.String(), policy.vmdAccess(), policy.vmdPorts(), policy.Revision)
	if status.Code(err) == codes.NotFound && sandbox.Status == db.SandboxStatusPaused {
		return "deferred_paused", nil
	}
	if err != nil {
		return "delivery_failed", err
	}
	return "delivered", nil
}

func (h *Handlers) requireHostPreviewCapabilities(c *gin.Context, hostID string, capabilities ...string) bool {
	hasCapabilities, err := h.DB.HostHasCapabilities(c.Request.Context(), db.HostHasCapabilitiesParams{
		HostID: hostID, RequiredCapabilities: capabilities,
	})
	if err != nil {
		log.Error().Err(err).Str("host_id", hostID).Strs("capabilities", capabilities).Msg("DB HostHasCapabilities failed")
		respondError(c, ErrInternal)
		return false
	}
	if !hasCapabilities {
		respondErrorMsg(c, "conflict",
			fmt.Sprintf("The sandbox's host does not enforce all required capabilities (%s); retry after the fleet is upgraded", strings.Join(capabilities, ", ")),
			http.StatusConflict)
		return false
	}
	return true
}

func (h *Handlers) requireHostPreviewPorts(c *gin.Context, hostID string) bool {
	return h.requireHostPreviewCapabilities(c, hostID, preview.HostCapabilityPorts)
}

func (h *Handlers) requireHostPreviewPortAccess(c *gin.Context, hostID string) bool {
	return h.requireHostPreviewCapabilities(c, hostID, preview.HostCapabilityPorts, preview.HostCapabilityPortAccess)
}

func (h *Handlers) requireHostPreviewPortBrowserAuth(c *gin.Context, hostID string) bool {
	return h.requireHostPreviewCapabilities(c, hostID, previewBrowserCapabilities()...)
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
	Port         int32  `json:"port"`
	Access       string `json:"access"`
	TokenVersion int64  `json:"token_version"`
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
		ports = append(ports, publishedPortResponse{Port: port.Port, Access: port.Access, TokenVersion: port.TokenVersion})
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
	current, err := h.loadPreviewPolicySnapshot(c.Request.Context(), sandboxID, teamID)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("load preview policy before publication failed")
		respondError(c, ErrInternal)
		return
	}
	if body.Access != nil && *body.Access == preview.AccessPrivate && current.Access == preview.AccessLegacyPublic {
		respondErrorMsg(c, "conflict", "legacy_public routes every port; PATCH preview_access to public or private before publishing a private port", http.StatusConflict)
		return
	}
	preflightNeedsBrowserAuth := publicationRequiresBrowserAuth(current, body.Port, body.Access)
	if preflightNeedsBrowserAuth && !h.requireHostPreviewPortBrowserAuth(c, sandbox.HostID) {
		return
	}
	if !preflightNeedsBrowserAuth && !h.requireHostPreviewPortAccess(c, sandbox.HostID) {
		return
	}

	var published db.PublishPortRow
	policy, err := h.applyPreviewMutationValidated(c.Request.Context(), sandboxID, teamID, func(q *db.Queries) error {
		var mutationErr error
		published, mutationErr = q.PublishPort(c.Request.Context(), db.PublishPortParams{
			SandboxID: sandboxID,
			Port:      body.Port,
			Access:    body.Access,
		})
		return mutationErr
	}, func(q *db.Queries, result previewPolicySnapshot) error {
		if result.hasPrivatePorts() {
			return validateHostPreviewBrowserCapabilities(c.Request.Context(), q, sandbox.HostID)
		}
		return validateHostPreviewCapabilities(c.Request.Context(), q, sandbox.HostID,
			preview.HostCapabilityPorts,
			preview.HostCapabilityPortAccess,
		)
	})
	if !h.handlePreviewMutationResult(c, sandboxID, "PublishPort", err) {
		return
	}
	publishedPolicy, exists := policy.Ports[published.Port]
	wantWireAccess := published.Access
	if wantWireAccess == preview.AccessPrivate {
		wantWireAccess = preview.AccessPrivateBrowserV1
	}
	if !exists || publishedPolicy.TokenVersion <= 0 || publishedPolicy.Access != wantWireAccess {
		log.Error().Str("sandbox_id", sandboxID.String()).Int32("port", published.Port).Msg("published port missing a positive authoritative token generation")
		respondError(c, ErrInternal)
		return
	}
	if !h.pushAfterPreviewMutation(c, sandbox, policy) {
		return
	}

	detail, _ := json.Marshal(map[string]any{"port": body.Port, "access": published.Access})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_port_published", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_port_published", map[string]any{"sandbox_id": sandboxID.String(), "port": body.Port})
	c.JSON(http.StatusOK, publishedPortResponse{
		Port: published.Port, Access: published.Access,
		TokenVersion: publishedPolicy.TokenVersion,
	})
}

type previewTokenRequest struct {
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

type previewTokenResponse struct {
	Token         string     `json:"token"`
	Port          int32      `json:"port"`
	Header        string     `json:"header"`
	QueryParam    string     `json:"query_param"`
	Access        string     `json:"access"`
	PreviewAccess string     `json:"preview_access"`
	TokenVersion  int64      `json:"token_version"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

func bindPreviewTokenRequest(c *gin.Context) (previewTokenRequest, bool) {
	var body previewTokenRequest
	if c.Request.ContentLength == 0 {
		return body, true
	}
	if err := bindJSONStrict(c, &body); err != nil {
		respondErrorMsg(c, "bad_request", "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return previewTokenRequest{}, false
	}
	if body.ExpiresInSeconds != nil && (*body.ExpiresInSeconds < 1 || *body.ExpiresInSeconds > maxPreviewTokenExpirySeconds) {
		respondErrorMsg(c, "bad_request",
			fmt.Sprintf("expires_in_seconds must be omitted or in [1, %d]", maxPreviewTokenExpirySeconds),
			http.StatusBadRequest)
		return previewTokenRequest{}, false
	}
	return body, true
}

func (h *Handlers) previewTokenSeed() ([]byte, bool) {
	if h.Config == nil || auth.ValidateSeed(h.Config.SandboxAccessTokenSeed) != nil {
		return nil, false
	}
	return h.Config.SandboxAccessTokenSeed, true
}

func buildPreviewTokenResponse(seed []byte, sandboxID uuid.UUID, policy previewPolicySnapshot, port int32, access string, tokenVersion int64, expiresInSeconds *int64) (previewTokenResponse, error) {
	claims := auth.PreviewClaims{SandboxID: sandboxID.String(), Port: int(port), Version: tokenVersion}
	var expiresAt *time.Time
	if expiresInSeconds != nil {
		// Derive both the signed claim and response from the same whole Unix
		// second; no sub-second rounding can make the response disagree with
		// what the proxy verifies.
		expiresUnix := time.Now().UTC().Unix() + *expiresInSeconds
		claims.ExpiresAt = expiresUnix
		t := time.Unix(expiresUnix, 0).UTC()
		expiresAt = &t
	}
	token, err := auth.ComputePreviewToken(seed, claims)
	if err != nil {
		return previewTokenResponse{}, err
	}
	return previewTokenResponse{
		Token: token, Port: port, Header: auth.PreviewTokenHeader, QueryParam: auth.PreviewTokenQueryParam,
		Access: access, PreviewAccess: policy.Access,
		TokenVersion: tokenVersion, ExpiresAt: expiresAt,
	}, nil
}

// logPreviewTokenRotationActivity synchronously records the result of a
// committed revocation before the HTTP response is written. It is deliberately
// outside the mutation transaction: audit storage failure must never resurrect
// the credential generation that rotation already revoked.
func (h *Handlers) logPreviewTokenRotationActivity(reqCtx context.Context, sandbox db.Sandbox, teamID uuid.UUID, actorID *uuid.UUID, port int32, tokenVersion int64, deliveryOutcome string, deliveryErr error) {
	auditStatus := "success"
	var auditError *string
	if deliveryErr != nil {
		auditStatus = "error"
		auditError = &deliveryOutcome
	}
	metadata, err := json.Marshal(map[string]any{
		"port":             port,
		"token_version":    tokenVersion,
		"delivery_outcome": deliveryOutcome,
	})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("marshal preview token rotation activity failed")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), asyncTimeout)
	defer cancel()
	if _, err := h.DB.CreateActivity(ctx, db.CreateActivityParams{
		SandboxID:    pgtype.UUID{Bytes: sandbox.ID, Valid: true},
		ResourceType: "sandbox",
		TeamID:       teamID,
		ActorID:      actorUUID(actorID),
		Category:     "sandbox",
		Action:       "preview_token_rotated",
		Status:       &auditStatus,
		SandboxName:  &sandbox.Name,
		Error:        auditError,
		Metadata:     metadata,
	}); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Int64("token_version", tokenVersion).Str("delivery_outcome", deliveryOutcome).Msg("preview token rotation activity failed")
	}
}

func respondPreviewPortCredentialError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, errPreviewPortNotPublished), errors.Is(err, pgx.ErrNoRows):
		respondErrorMsg(c, "not_found", "Preview port not published; publish it before minting a token", http.StatusNotFound)
	case errors.Is(err, errPreviewPortIsPublic):
		respondErrorMsg(c, "conflict", "Preview tokens can only be minted for private ports", http.StatusConflict)
	default:
		return false
	}
	return true
}

// MintSandboxPreviewToken activates header and browser authentication for an
// existing private publication. The no-op mutation advances the authoritative
// revision under the sandbox lock; the credential is returned only after the
// browser-aware snapshot has reached the live host.
func (h *Handlers) MintSandboxPreviewToken(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
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
	body, ok := bindPreviewTokenRequest(c)
	if !ok {
		return
	}
	seed, ok := h.previewTokenSeed()
	if !ok {
		log.Error().Msg("preview token requested without a valid signing seed")
		respondError(c, ErrInternal)
		return
	}
	sandbox, ok := h.getTeamSandbox(c, sandboxID, teamID)
	if !ok {
		return
	}

	// Check the current state before capability gating for precise 404/409
	// responses. It is re-read under the mutation lock below before issuance.
	current, err := h.DB.GetPublishedPreviewPort(c.Request.Context(), db.GetPublishedPreviewPortParams{
		SandboxID: sandboxID, TeamID: teamID, Port: port,
	})
	if err != nil {
		if respondPreviewPortCredentialError(c, err) {
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Int32("port", port).Msg("load preview port for mint failed")
		respondError(c, ErrInternal)
		return
	}
	if current.Access != preview.AccessPrivate {
		respondPreviewPortCredentialError(c, errPreviewPortIsPublic)
		return
	}
	if !h.requireHostPreviewPortBrowserAuth(c, sandbox.HostID) {
		return
	}

	serializedStatus := sandbox.Status
	policy, _, err := h.applyPreviewMutationFinalized(c.Request.Context(), sandboxID, teamID, func(q *db.Queries) error {
		current, err = q.GetPublishedPreviewPort(c.Request.Context(), db.GetPublishedPreviewPortParams{
			SandboxID: sandboxID, TeamID: teamID, Port: port,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errPreviewPortNotPublished
			}
			return err
		}
		if current.Access != preview.AccessPrivate {
			return errPreviewPortIsPublic
		}
		serializedStatus, err = q.GetSandboxStatusForPreviewMutation(c.Request.Context(), db.GetSandboxStatusForPreviewMutationParams{
			ID: sandboxID, TeamID: teamID,
		})
		return err
	}, func(q *db.Queries, result previewPolicySnapshot) (error, error) {
		if err := validateHostPreviewBrowserCapabilities(c.Request.Context(), q, sandbox.HostID); err != nil {
			return nil, err
		}
		pushed, exists := result.Ports[port]
		if !exists || pushed.TokenVersion != current.TokenVersion || pushed.Access != preview.AccessPrivateBrowserV1 {
			return nil, errPreviewTokenSnapshot
		}
		credentialSandbox := sandbox
		credentialSandbox.Status = serializedStatus
		_, err := h.pushPreviewCredentialPolicy(c.Request.Context(), credentialSandbox, result)
		return nil, err
	})
	if err != nil {
		if respondPreviewPortCredentialError(c, err) {
			return
		}
		h.handlePreviewMutationResult(c, sandboxID, "MintPreviewPortToken", err)
		return
	}
	resp, err := buildPreviewTokenResponse(seed, sandboxID, policy, port, current.Access, current.TokenVersion, body.ExpiresInSeconds)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Int32("port", port).Msg("mint preview token failed")
		respondError(c, ErrInternal)
		return
	}
	detail, _ := json.Marshal(map[string]any{"port": port, "expires_in_seconds": body.ExpiresInSeconds})
	h.logSandboxActivity(c.Request.Context(), sandbox.ID, teamID, actorIDFromContext(c), "sandbox", "preview_token_minted", "success", &sandbox.Name, nil, detail)
	h.capture(c, "sandbox_preview_token_minted", map[string]any{"sandbox_id": sandboxID.String(), "port": port})
	c.JSON(http.StatusOK, resp)
}

// RotateSandboxPreviewToken revokes one port's generation atomically with an
// authoritative revision advance. Replacement delivery runs while the
// sandbox mutation lock is held. After commit, the delivery outcome is audited
// synchronously before the response; failure is never a reason to roll the
// revocation back.
func (h *Handlers) RotateSandboxPreviewToken(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
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

	var rotated db.RotatePublishedPreviewPortTokenRow
	serializedStatus := sandbox.Status
	var seed []byte
	deliveryOutcome := "not_attempted"
	actorID := actorIDFromContext(c)
	policy, outcomeErr, err := h.applyPreviewMutationFinalized(c.Request.Context(), sandboxID, teamID, func(q *db.Queries) error {
		rotated, err = q.RotatePublishedPreviewPortToken(c.Request.Context(), db.RotatePublishedPreviewPortTokenParams{
			SandboxID: sandboxID, Port: port,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errPreviewPortNotPublished
			}
			return err
		}
		if rotated.Access != preview.AccessPrivate {
			return errPreviewPortIsPublic
		}
		serializedStatus, err = q.GetSandboxStatusForPreviewMutation(c.Request.Context(), db.GetSandboxStatusForPreviewMutationParams{
			ID: sandboxID, TeamID: teamID,
		})
		return err
	}, func(q *db.Queries, result previewPolicySnapshot) (error, error) {
		var deliveryErr error
		pushed, exists := result.Ports[port]
		switch {
		case !exists || pushed.TokenVersion != rotated.TokenVersion || pushed.Access != preview.AccessPrivateBrowserV1:
			deliveryOutcome = "snapshot_invalid"
			deliveryErr = errPreviewTokenSnapshot
		default:
			var validSeed bool
			seed, validSeed = h.previewTokenSeed()
			if !validSeed {
				deliveryOutcome = "seed_unavailable"
				deliveryErr = errPreviewTokenSeedInvalid
				break
			}
			if capabilityErr := validateHostPreviewBrowserCapabilities(c.Request.Context(), q, sandbox.HostID); capabilityErr != nil {
				deliveryOutcome = "capability_unavailable"
				deliveryErr = capabilityErr
				break
			}
			credentialSandbox := sandbox
			credentialSandbox.Status = serializedStatus
			deliveryOutcome, deliveryErr = h.pushPreviewCredentialPolicy(c.Request.Context(), credentialSandbox, result)
		}

		return deliveryErr, nil
	})
	if err != nil {
		if respondPreviewPortCredentialError(c, err) {
			return
		}
		h.handlePreviewMutationResult(c, sandboxID, "RotatePublishedPreviewPortToken", err)
		return
	}
	h.logPreviewTokenRotationActivity(c.Request.Context(), sandbox, teamID, actorID, port, rotated.TokenVersion, deliveryOutcome, outcomeErr)

	if outcomeErr != nil {
		if !h.handlePreviewMutationResult(c, sandboxID, "DeliverRotatedPreviewPortToken", outcomeErr) {
			return
		}
		return
	}
	resp, err := buildPreviewTokenResponse(seed, sandboxID, policy, port, rotated.Access, rotated.TokenVersion, nil)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Int32("port", port).Msg("mint rotated preview token failed")
		respondError(c, ErrInternal)
		return
	}
	h.capture(c, "sandbox_preview_token_rotated", map[string]any{"sandbox_id": sandboxID.String(), "port": port})
	c.JSON(http.StatusOK, resp)
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
	var missingCapability *missingHostPreviewCapabilityError
	if errors.As(err, &missingCapability) {
		respondErrorMsg(c, "conflict",
			fmt.Sprintf("The sandbox's host does not enforce %q; retry after the fleet is upgraded", missingCapability.capability),
			http.StatusConflict)
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
