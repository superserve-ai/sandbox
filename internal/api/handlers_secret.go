package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

// providerUpstreamHost maps a provider name to the host the proxy will
// forward to. Used at sandbox-create time to reject configurations that
// reference a secret whose upstream is blocked by the customer's egress
// rules — better a 400 now than a 403 mid-flight from inside the VM.
var providerUpstreamHost = map[string]string{
	"anthropic": "api.anthropic.com",
}

// envKeyRE: classic env-var name conventions. Same shape secretNameRE
// uses but separated so we can evolve them independently.
var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateSecretsRefs validates the user-supplied secrets map: env-var
// keys are well-formed and secret names are well-formed. Doesn't hit the
// DB; that happens during binding resolution.
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

// resolveSecretBindings turns the user-supplied secrets map into the
// runtime bindings needed by vmd plus the rows that get written to
// sandbox_secret. Decrypts each value (KMS round-trip) and mints a
// sandbox-bound token. On any error returns a user-facing message.
func (h *Handlers) resolveSecretBindings(
	ctx context.Context,
	teamID, sandboxID uuid.UUID,
	refs map[string]string,
	netCfg *networkConfigRequest,
) ([]vmdclient.SecretBinding, []db.AddSandboxSecretParams, error) {
	if len(refs) == 0 {
		return nil, nil, nil
	}
	if h.Encryptor == nil || h.Signer == nil {
		log.Error().Msg("sandbox references secrets but Encryptor/Signer not configured")
		return nil, nil, errors.New("server is not configured for secret-backed sandboxes")
	}

	bindings := make([]vmdclient.SecretBinding, 0, len(refs))
	rows := make([]db.AddSandboxSecretParams, 0, len(refs))

	for envKey, secretName := range refs {
		row, err := h.DB.GetSecretByName(ctx, db.GetSecretByNameParams{
			TeamID: teamID, Name: secretName,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil, fmt.Errorf("secrets[%s]: secret %q not found", envKey, secretName)
			}
			log.Error().Err(err).Str("name", secretName).Msg("DB GetSecretByName during sandbox create")
			return nil, nil, errors.New("internal error resolving secrets")
		}
		if err := upstreamAllowedByEgress(row.Provider, netCfg); err != nil {
			return nil, nil, fmt.Errorf("secrets[%s]: %w", envKey, err)
		}

		plaintext, err := h.Encryptor.Decrypt(ctx, secrets.Encrypted{
			Ciphertext:   row.Ciphertext,
			EncryptedDEK: row.EncryptedDek,
			KEKID:        row.KekID,
		})
		if err != nil {
			log.Error().Err(err).Str("name", secretName).Msg("KMS decrypt during sandbox create")
			return nil, nil, errors.New("internal error decrypting secret")
		}

		token, err := h.Signer.Mint(time.Now(), sandboxID, row.ID, teamID)
		if err != nil {
			log.Error().Err(err).Msg("mint proxy token")
			return nil, nil, errors.New("internal error issuing token")
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

// upstreamAllowedByEgress checks that a provider's upstream host is
// reachable under the sandbox's egress rules. Returns an explanatory
// error suitable for a 400 response.
func upstreamAllowedByEgress(provider string, netCfg *networkConfigRequest) error {
	host, ok := providerUpstreamHost[provider]
	if !ok {
		// Unknown provider — let it through; the proxy will refuse later
		// if it can't route. This shouldn't happen for the providers we
		// allow at create time, but keep the check open in case the set
		// drifts.
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

// wrapTokenForProvider gives the SDK a key with the right shape so it
// accepts the env value without complaint. Anthropic only checks the
// `sk-ant-` prefix — wrapping our JWT keeps the client library happy.
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

// secretResponse is the customer-facing view. Never includes ciphertext or
// the wrapped DEK — those are server-side internals.
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

// secretNameRE — same shape as env-var name conventions: a leading letter
// (upper or lower) or underscore, followed by letters / digits / `_` / `-`.
// We don't allow the slashes or dots that template names accept because
// secret names map to a user-visible identifier in CLIs/dashboards and we
// want them to remain shell-safe and unambiguous.
var secretNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// supportedProviders gates the customer-facing field at create time.
// Customers can't invent providers — we'd have no upstream to forward
// to.
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
		return fmt.Errorf("unsupported provider %q", provider)
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
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
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

// PatchSecret rotates the secret's value. Re-encrypts with a fresh DEK
// and updates the row.
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
		respondErrorMsg(c, "bad_request", fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}
	if err := validateSecretValue(req.Value); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	// Look up so we can target by id (UpdateSecretValue is by id) and so a
	// missing row returns 404 cleanly.
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

	// Push the new value to every host running a sandbox that holds a
	// binding for this secret. Async so the API call returns quickly.
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

	// Empty real value = revoke. Run async so the API call returns
	// immediately; the in-flight calls already in transit upstream may
	// still succeed but no new ones can use the deleted secret.
	go h.propagateSecretToHosts(context.WithoutCancel(c.Request.Context()), row.ID, "")

	c.Status(http.StatusNoContent)
}

// propagateSecretToHosts groups live sandbox bindings by host and pushes
// the new (or empty) value to each host's vmd. Best-effort — failures
// are logged so ops can retry; on the next sandbox-create the proxy
// gets the latest value automatically anyway.
func (h *Handlers) propagateSecretToHosts(ctx context.Context, secretID uuid.UUID, realValue string) {
	if h.Hosts == nil {
		// No host registry means we can't fan out per-host; skip.
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

// GetSandboxAudit returns paginated audit rows for a sandbox. Pagination
// uses the descending row id as a cursor: pass `?before=<id>` to fetch
// the next page. Team scoping comes from the sandbox lookup — a customer
// can't read another team's rows by guessing UUIDs.
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
