package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/secrets"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// providerUpstreamHost is the host each provider's traffic forwards to.
// Used to reject sandbox creates that reference a secret blocked by the
// caller's egress rules.
var providerUpstreamHost = map[string]string{
	"anthropic": "api.anthropic.com",
}

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateSecretsRefs(refs map[string]string) error {
	if len(refs) == 0 {
		return nil
	}
	if len(refs) > envVarsMaxKeys {
		return fmt.Errorf("secrets has %d entries, max is %d", len(refs), envVarsMaxKeys)
	}
	for envKey, secretName := range refs {
		if !envKeyRE.MatchString(envKey) {
			return fmt.Errorf("secrets key %q is not a valid env-var name", envKey)
		}
		if err := validateSecretName(secretName); err != nil {
			return fmt.Errorf("secrets[%s]: %w", envKey, err)
		}
	}
	return nil
}

// resolveSecretBindings decrypts each referenced secret and mints a
// sandbox-bound token. Returns *AppError so the caller can map
// user-input failures to 400 and server-side failures to 500.
func (h *Handlers) resolveSecretBindings(
	ctx context.Context,
	teamID, sandboxID uuid.UUID,
	refs map[string]string,
	netCfg *networkConfigRequest,
) ([]vmdclient.SecretBinding, []db.AddSandboxSecretParams, *AppError) {
	if len(refs) == 0 {
		return nil, nil, nil
	}
	if h.Encryptor == nil || h.Signer == nil {
		log.Error().Msg("sandbox references secrets but Encryptor/Signer not configured")
		return nil, nil, NewAppError("not_configured",
			"This deployment does not support stored secrets. Contact support.",
			http.StatusServiceUnavailable)
	}

	bindings := make([]vmdclient.SecretBinding, 0, len(refs))
	rows := make([]db.AddSandboxSecretParams, 0, len(refs))

	for envKey, secretName := range refs {
		row, err := h.DB.GetSecretByName(ctx, db.GetSecretByNameParams{
			TeamID: teamID, Name: secretName,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil, NewAppError("secret_not_found",
					fmt.Sprintf("secrets[%s] references %q, which does not exist for this team", envKey, secretName),
					http.StatusBadRequest)
			}
			log.Error().Err(err).Str("name", secretName).Msg("DB GetSecretByName during sandbox create")
			return nil, nil, ErrInternal
		}
		if err := upstreamAllowedByEgress(row.Provider, netCfg); err != nil {
			return nil, nil, NewAppError("secret_blocked_by_egress",
				fmt.Sprintf("secrets[%s]: %s", envKey, err.Error()),
				http.StatusBadRequest)
		}

		plaintext, err := h.Encryptor.Decrypt(ctx, secrets.Encrypted{
			Ciphertext:   row.Ciphertext,
			EncryptedDEK: row.EncryptedDek,
			KEKID:        row.KekID,
		})
		if err != nil {
			log.Error().Err(err).Str("name", secretName).Msg("KMS decrypt during sandbox create")
			return nil, nil, ErrInternal
		}

		token, err := h.Signer.Mint(time.Now(), sandboxID, row.ID, teamID)
		if err != nil {
			log.Error().Err(err).Msg("mint proxy token")
			return nil, nil, ErrInternal
		}

		bindings = append(bindings, vmdclient.SecretBinding{
			SecretID:  row.ID.String(),
			Provider:  row.Provider,
			EnvKey:    envKey,
			RealValue: string(plaintext),
			Token:     wrapTokenForProvider(row.Provider, token),
		})
		rows = append(rows, db.AddSandboxSecretParams{
			SecretID: row.ID,
			EnvKey:   envKey,
		})
	}
	return bindings, rows, nil
}

// upstreamAllowedByEgress returns an error if the provider's upstream
// would be blocked by the sandbox's egress rules.
func upstreamAllowedByEgress(provider string, netCfg *networkConfigRequest) error {
	host, ok := providerUpstreamHost[provider]
	if !ok {
		return nil
	}
	if netCfg == nil {
		return nil
	}
	for _, denied := range netCfg.DenyOut {
		if strings.EqualFold(denied, host) {
			return fmt.Errorf("provider %q upstream %s is blocked by deny_out", provider, host)
		}
	}
	if len(netCfg.AllowOut) == 0 {
		return nil
	}
	for _, allowed := range netCfg.AllowOut {
		if strings.EqualFold(allowed, host) {
			return nil
		}
		if strings.HasPrefix(allowed, "*.") &&
			strings.HasSuffix(strings.ToLower(host), strings.ToLower(allowed[1:])) {
			return nil
		}
	}
	return fmt.Errorf("provider %q upstream %s is not in allow_out", provider, host)
}

// wrapTokenForProvider matches the SDK's expected key prefix so the
// client accepts our token from env. Anthropic checks for `sk-ant-`.
func wrapTokenForProvider(provider, jwt string) string {
	switch provider {
	case "anthropic":
		return "sk-ant-proxy-" + jwt
	default:
		return jwt
	}
}

// ---------------------------------------------------------------------------
// Request / response shapes
// ---------------------------------------------------------------------------

type createSecretRequest struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Value    string `json:"value"`
}

type updateSecretRequest struct {
	Value string `json:"value"`
}

// secretResponse is the customer-facing view. Excludes ciphertext / DEK.
type secretResponse struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Provider   string    `json:"provider"`
	CreatedAt  string    `json:"created_at"`
	UpdatedAt  string    `json:"updated_at"`
	LastUsedAt *string   `json:"last_used_at,omitempty"`
}

func toSecretResponse(s db.Secret) secretResponse {
	resp := secretResponse{
		ID:        s.ID,
		Name:      s.Name,
		Provider:  s.Provider,
		CreatedAt: s.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: s.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if s.LastUsedAt.Valid {
		t := s.LastUsedAt.Time.UTC().Format(time.RFC3339)
		resp.LastUsedAt = &t
	}
	return resp
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const (
	maxSecretNameLen  = 128
	maxSecretValueLen = 8 * 1024 // 8 KB; matches env_vars value cap
)

// secretNameRE — leading letter or underscore, then letters / digits /
// `_` / `-`. Shell- and URL-safe.
var secretNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

var supportedProviders = map[string]bool{
	"anthropic": true,
}

func validateSecretName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("name is required")
	}
	if len(name) > maxSecretNameLen {
		return fmt.Errorf("name exceeds %d characters", maxSecretNameLen)
	}
	if !secretNameRE.MatchString(name) {
		return errors.New("name must start with a letter or underscore and contain only letters, digits, '_', '-'")
	}
	return nil
}

func validateSecretValue(value string) error {
	if value == "" {
		return errors.New("value is required")
	}
	if len(value) > maxSecretValueLen {
		return fmt.Errorf("value exceeds %d bytes", maxSecretValueLen)
	}
	return nil
}

func validateProvider(provider string) error {
	if provider == "" {
		return errors.New("provider is required")
	}
	if !supportedProviders[provider] {
		supported := make([]string, 0, len(supportedProviders))
		for p := range supportedProviders {
			supported = append(supported, p)
		}
		sort.Strings(supported)
		return fmt.Errorf("unsupported provider %q (supported: %s)", provider, strings.Join(supported, ", "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (h *Handlers) requireEncryptor(c *gin.Context) bool {
	if h.Encryptor == nil {
		log.Error().Msg("/secrets called but no Encryptor configured")
		respondError(c, ErrInternal)
		return false
	}
	return true
}

func (h *Handlers) CreateSecret(c *gin.Context) {
	if !h.requireEncryptor(c) {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}

	var req createSecretRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Provider = strings.TrimSpace(req.Provider)

	if err := validateSecretName(req.Name); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateProvider(req.Provider); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateSecretValue(req.Value); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	enc, err := h.Encryptor.Encrypt(c.Request.Context(), []byte(req.Value))
	if err != nil {
		log.Error().Err(err).Str("name", req.Name).Msg("KMS encrypt failed")
		respondError(c, ErrInternal)
		return
	}

	row, err := h.DB.CreateSecret(c.Request.Context(), db.CreateSecretParams{
		TeamID:       teamID,
		Name:         req.Name,
		Provider:     req.Provider,
		Ciphertext:   enc.Ciphertext,
		EncryptedDek: enc.EncryptedDEK,
		KekID:        enc.KEKID,
	})
	if err != nil {
		if isUniqueViolation(err) {
			respondErrorMsg(c, "conflict",
				fmt.Sprintf("a secret named %q already exists", req.Name),
				http.StatusConflict)
			return
		}
		log.Error().Err(err).Str("name", req.Name).Msg("DB CreateSecret failed")
		respondError(c, ErrInternal)
		return
	}

	c.JSON(http.StatusCreated, toSecretResponse(row))
}

func (h *Handlers) ListSecrets(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	rows, err := h.DB.ListSecretsForTeam(c.Request.Context(), teamID)
	if err != nil {
		log.Error().Err(err).Msg("DB ListSecretsForTeam failed")
		respondError(c, ErrInternal)
		return
	}
	out := make([]secretResponse, len(rows))
	for i, row := range rows {
		out[i] = toSecretResponse(row)
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) GetSecret(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	name := c.Param("name")
	if err := validateSecretName(name); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	row, err := h.DB.GetSecretByName(c.Request.Context(), db.GetSecretByNameParams{
		TeamID: teamID, Name: name,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Secret not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("name", name).Msg("DB GetSecretByName failed")
		respondError(c, ErrInternal)
		return
	}
	c.JSON(http.StatusOK, toSecretResponse(row))
}

func (h *Handlers) PatchSecret(c *gin.Context) {
	if !h.requireEncryptor(c) {
		return
	}
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	name := c.Param("name")
	if err := validateSecretName(name); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	var req updateSecretRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateSecretValue(req.Value); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	// Look up first so a missing row returns 404 cleanly.
	existing, err := h.DB.GetSecretByName(c.Request.Context(), db.GetSecretByNameParams{
		TeamID: teamID, Name: name,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Secret not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("name", name).Msg("DB GetSecretByName failed")
		respondError(c, ErrInternal)
		return
	}

	enc, err := h.Encryptor.Encrypt(c.Request.Context(), []byte(req.Value))
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("KMS encrypt failed")
		respondError(c, ErrInternal)
		return
	}

	updated, err := h.DB.UpdateSecretValue(c.Request.Context(), db.UpdateSecretValueParams{
		ID:           existing.ID,
		TeamID:       teamID,
		Ciphertext:   enc.Ciphertext,
		EncryptedDek: enc.EncryptedDEK,
		KekID:        enc.KEKID,
	})
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("DB UpdateSecretValue failed")
		respondError(c, ErrInternal)
		return
	}

	go h.propagateSecretToHosts(context.WithoutCancel(c.Request.Context()), updated.ID, req.Value)

	c.JSON(http.StatusOK, toSecretResponse(updated))
}

func (h *Handlers) DeleteSecret(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	name := c.Param("name")
	if err := validateSecretName(name); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	row, err := h.DB.SoftDeleteSecretByName(c.Request.Context(), db.SoftDeleteSecretByNameParams{
		TeamID: teamID, Name: name,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "Secret not found", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("name", name).Msg("DB SoftDeleteSecretByName failed")
		respondError(c, ErrInternal)
		return
	}

	// Empty value = revoke.
	go h.propagateSecretToHosts(context.WithoutCancel(c.Request.Context()), row.ID, "")

	c.Status(http.StatusNoContent)
}

// propagateSecretToHosts fans out a new (or empty=revoke) value to every
// host that has a sandbox bound to the secret. Best-effort.
func (h *Handlers) propagateSecretToHosts(ctx context.Context, secretID uuid.UUID, realValue string) {
	if h.Hosts == nil {
		return
	}
	rows, err := h.DB.ListSandboxesForSecret(ctx, secretID)
	if err != nil {
		log.Error().Err(err).Str("secret_id", secretID.String()).Msg("propagate: list sandboxes")
		return
	}
	hosts := map[string]struct{}{}
	for _, r := range rows {
		hosts[r.HostID] = struct{}{}
	}
	for hostID := range hosts {
		client, herr := h.Hosts.ClientFor(ctx, hostID)
		if herr != nil {
			log.Error().Err(herr).Str("host_id", hostID).Msg("propagate: resolve host client")
			continue
		}
		if perr := client.PropagateSecret(ctx, secretID.String(), realValue); perr != nil {
			log.Error().Err(perr).Str("host_id", hostID).Msg("propagate: vmd PropagateSecret")
		}
	}
}

// ---------------------------------------------------------------------------
// Audit log read
// ---------------------------------------------------------------------------

const (
	auditDefaultLimit = 100
	auditMaxLimit     = 1000
)

type proxyAuditResponse struct {
	ID             int64   `json:"id"`
	Ts             string  `json:"ts"`
	SandboxID      string  `json:"sandbox_id"`
	SecretID       string  `json:"secret_id"`
	Provider       string  `json:"provider"`
	Method         string  `json:"method"`
	Path           string  `json:"path"`
	Status         int32   `json:"status"`
	UpstreamStatus *int32  `json:"upstream_status,omitempty"`
	LatencyMs      *int32  `json:"latency_ms,omitempty"`
	ErrorCode      *string `json:"error_code,omitempty"`
}

// GetSandboxAudit returns audit rows for a sandbox, paginated by row id
// descending. Pass `?before=<id>` for the next page.
func (h *Handlers) GetSandboxAudit(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

	// Team-scope check: sandbox must belong to the caller's team.
	if _, err := h.DB.GetSandbox(c.Request.Context(), db.GetSandboxParams{
		ID: sandboxID, TeamID: teamID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(c, ErrSandboxNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	limit, err := parseAuditLimit(c.Query("limit"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	before, err := parseAuditBefore(c.Query("before"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	rows, err := h.DB.ListAuditForSandbox(c.Request.Context(), db.ListAuditForSandboxParams{
		SandboxID: sandboxID,
		Column2:   before,
		Limit:     limit,
	})
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB ListAuditForSandbox failed")
		respondError(c, ErrInternal)
		return
	}

	out := make([]proxyAuditResponse, len(rows))
	for i, r := range rows {
		out[i] = proxyAuditResponse{
			ID:             r.ID,
			Ts:             r.Ts.UTC().Format(time.RFC3339Nano),
			SandboxID:      r.SandboxID.String(),
			SecretID:       r.SecretID.String(),
			Provider:       r.Provider,
			Method:         r.Method,
			Path:           r.Path,
			Status:         r.Status,
			UpstreamStatus: r.UpstreamStatus,
			LatencyMs:      r.LatencyMs,
			ErrorCode:      r.ErrorCode,
		}
	}
	c.JSON(http.StatusOK, out)
}

func parseAuditLimit(raw string) (int32, error) {
	if raw == "" {
		return auditDefaultLimit, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return 0, fmt.Errorf("limit must be a positive integer")
	}
	if v > auditMaxLimit {
		return 0, fmt.Errorf("limit must be <= %d", auditMaxLimit)
	}
	return int32(v), nil
}

func parseAuditBefore(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("before must be a non-negative integer")
	}
	return v, nil
}
