package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/secrets"
)

// tokenSpec describes how to mint a fresh proxy token for one provider.
// Shape must match the upstream key format so SDK validators accept it.
type tokenSpec struct {
	Prefix   string
	BodyLen  int
	Alphabet string // "alnum" or "b64url"
}

// providerShortcut is a pre-baked credential template (auth config + hosts + token spec).
type providerShortcut struct {
	AuthType   string
	AuthConfig map[string]any
	Hosts      []string
	Token      tokenSpec
}

var providerShortcuts = map[string]providerShortcut{
	"anthropic": {
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "x-api-key"},
		Hosts:      []string{"api.anthropic.com"},
		Token:      tokenSpec{Prefix: "sk-ant-api03-", BodyLen: 48, Alphabet: "alnum"},
	},
	"openai": {
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.openai.com"},
		Token:      tokenSpec{Prefix: "sk-proj-", BodyLen: 64, Alphabet: "alnum"},
	},
	"github": {
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.github.com", "github.com"},
		Token:      tokenSpec{Prefix: "ghp_", BodyLen: 36, Alphabet: "alnum"},
	},
	"stripe": {
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.stripe.com"},
		// sk_test_ rather than sk_live_ so scanners don't flag the token as live payment data.
		Token: tokenSpec{Prefix: "sk_test_", BodyLen: 24, Alphabet: "alnum"},
	},
	"slack": {
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"slack.com"},
		Token:      tokenSpec{Prefix: "xoxb-", BodyLen: 43, Alphabet: "b64url"},
	},
	"linear": {
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "Authorization"},
		Hosts:      []string{"api.linear.app"},
		Token:      tokenSpec{Prefix: "lin_api_", BodyLen: 32, Alphabet: "alnum"},
	},
}

// defaultTokenSpec mints tokens for explicit-auth credentials (no provider shortcut).
var defaultTokenSpec = tokenSpec{Prefix: "ssrv_proxy_", BodyLen: 43, Alphabet: "b64url"}

func knownProviders() []string {
	out := make([]string, 0, len(providerShortcuts))
	for k := range providerShortcuts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// authConfigRequest is the typed auth block (bearer | basic | api-key | custom).
// For type=basic, value is the password; the user portion is preserved at egress.
type authConfigRequest struct {
	Type    string            `json:"type"`
	Header  string            `json:"header,omitempty"`  // api-key only
	Prefix  string            `json:"prefix,omitempty"`  // api-key only
	Headers map[string]string `json:"headers,omitempty"` // custom only
}

type createSecretRequest struct {
	Name     string             `json:"name"`
	Value    string             `json:"value"`
	Provider string             `json:"provider,omitempty"` // shortcut name (mutually exclusive with auth+hosts)
	Auth     *authConfigRequest `json:"auth,omitempty"`     // explicit auth config (with hosts)
	Hosts    []string           `json:"hosts,omitempty"`    // upstream allow list when auth is explicit
}

type updateSecretRequest struct {
	Value string `json:"value"`
}

type secretResponse struct {
	ID               uuid.UUID      `json:"id"`
	Name             string         `json:"name"`
	AuthType         string         `json:"auth_type"`
	AuthConfig       map[string]any `json:"auth_config"`
	ProviderShortcut *string        `json:"provider_shortcut,omitempty"`
	Hosts            []string       `json:"hosts"`
	CreatedAt        string         `json:"created_at"`
	UpdatedAt        string         `json:"updated_at"`
	LastUsedAt       *string        `json:"last_used_at,omitempty"`
}

func toSecretResponse(s db.Secret) secretResponse {
	resp := secretResponse{
		ID:               s.ID,
		Name:             s.Name,
		AuthType:         s.AuthType,
		ProviderShortcut: s.ProviderShortcut,
		Hosts:            s.Hosts,
		CreatedAt:        s.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:        s.UpdatedAt.UTC().Format(time.RFC3339),
	}
	cfg := map[string]any{}
	if len(s.AuthConfig) > 0 {
		_ = json.Unmarshal(s.AuthConfig, &cfg)
	}
	resp.AuthConfig = cfg
	if s.LastUsedAt.Valid {
		t := s.LastUsedAt.Time.UTC().Format(time.RFC3339)
		resp.LastUsedAt = &t
	}
	return resp
}

const (
	maxSecretNameLen  = 128
	maxSecretValueLen = 8 * 1024
	maxHostsPerSecret = 16
	maxCustomHeaders  = 8
)

// secretNameRE: leading letter/underscore, then alphanumerics / '_' / '-'.
var secretNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// hostRE accepts a bare hostname or one-level wildcard (no ports, paths, schemes).
var hostRE = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// headerNameRE matches RFC 7230 token-class characters.
var headerNameRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+$`)

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

func validateHosts(hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("hosts is required (at least one upstream)")
	}
	if len(hosts) > maxHostsPerSecret {
		return fmt.Errorf("hosts has %d entries, max is %d", len(hosts), maxHostsPerSecret)
	}
	for i, h := range hosts {
		h = strings.TrimSpace(h)
		if !hostRE.MatchString(h) {
			return fmt.Errorf("hosts[%d]: %q is not a valid hostname", i, h)
		}
		hosts[i] = h
	}
	return nil
}

func validateAuthConfig(auth *authConfigRequest) error {
	if auth == nil {
		return errors.New("auth is required when provider is not set")
	}
	switch auth.Type {
	case "bearer", "basic":
		if auth.Header != "" || auth.Prefix != "" || len(auth.Headers) > 0 {
			return fmt.Errorf("auth.type=%q does not accept header/prefix/headers", auth.Type)
		}
	case "api-key":
		if auth.Header == "" {
			return errors.New("auth.header is required for type=api-key")
		}
		if !headerNameRE.MatchString(auth.Header) {
			return fmt.Errorf("auth.header %q is not a valid header name", auth.Header)
		}
		if len(auth.Headers) > 0 {
			return errors.New("auth.headers is not allowed for type=api-key")
		}
	case "custom":
		if len(auth.Headers) == 0 {
			return errors.New("auth.headers is required for type=custom")
		}
		if len(auth.Headers) > maxCustomHeaders {
			return fmt.Errorf("auth.headers has %d entries, max is %d", len(auth.Headers), maxCustomHeaders)
		}
		for name, tmpl := range auth.Headers {
			if !headerNameRE.MatchString(name) {
				return fmt.Errorf("auth.headers: %q is not a valid header name", name)
			}
			if !strings.Contains(tmpl, "{{ value }}") {
				return fmt.Errorf("auth.headers[%s]: template must reference {{ value }} so the credential is actually injected", name)
			}
		}
		if auth.Header != "" || auth.Prefix != "" {
			return errors.New("auth.type=custom does not accept header/prefix; use headers map")
		}
	case "":
		return errors.New("auth.type is required")
	default:
		return fmt.Errorf("auth.type %q is not supported (got: bearer, basic, api-key, custom)", auth.Type)
	}
	return nil
}

// resolveAuth flattens the request into (auth_type, auth_config, hosts, provider_shortcut).
// Mutually exclusive: provider XOR (auth + hosts).
func resolveAuth(req createSecretRequest) (authType string, authConfig []byte, hosts []string, shortcut *string, err error) {
	hasProvider := req.Provider != ""
	hasExplicit := req.Auth != nil || len(req.Hosts) > 0

	if hasProvider && hasExplicit {
		err = errors.New("provider is mutually exclusive with auth/hosts; pick one")
		return
	}
	if !hasProvider && !hasExplicit {
		err = fmt.Errorf("must specify either provider (one of: %s) or auth + hosts", strings.Join(knownProviders(), ", "))
		return
	}

	if hasProvider {
		p, ok := providerShortcuts[req.Provider]
		if !ok {
			err = fmt.Errorf("provider %q is not supported (got: %s)", req.Provider, strings.Join(knownProviders(), ", "))
			return
		}
		authType = p.AuthType
		authConfig, err = json.Marshal(p.AuthConfig)
		if err != nil {
			return
		}
		hosts = append([]string(nil), p.Hosts...)
		s := req.Provider
		shortcut = &s
		return
	}

	if err = validateAuthConfig(req.Auth); err != nil {
		return
	}
	if err = validateHosts(req.Hosts); err != nil {
		return
	}
	authType = req.Auth.Type
	cfg := map[string]any{}
	switch authType {
	case "api-key":
		cfg["header"] = req.Auth.Header
		if req.Auth.Prefix != "" {
			cfg["prefix"] = req.Auth.Prefix
		}
	case "custom":
		cfg["headers"] = req.Auth.Headers
	}
	authConfig, err = json.Marshal(cfg)
	hosts = req.Hosts
	return
}

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
	if err := validateSecretValue(req.Value); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	authType, authConfig, hosts, shortcut, err := resolveAuth(req)
	if err != nil {
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
		TeamID:           teamID,
		Name:             req.Name,
		AuthType:         authType,
		AuthConfig:       authConfig,
		ProviderShortcut: shortcut,
		Hosts:            hosts,
		Ciphertext:       enc.Ciphertext,
		EncryptedDek:     enc.EncryptedDEK,
		KekID:            enc.KEKID,
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

	// Best-effort cache fanout; the daemon TTL is the fallback.
	go h.fanoutInvalidate(context.Background(), updated.ID)

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

	// Best-effort cache fanout; the daemon TTL is the fallback.
	go h.fanoutInvalidate(context.Background(), row.ID)

	c.Status(http.StatusNoContent)
}

// fanoutInvalidate calls InvalidateSecret on every host that has a sandbox
// bound to secretID. Best-effort; failures are logged.
func (h *Handlers) fanoutInvalidate(ctx context.Context, secretID uuid.UUID) {
	if h.Hosts == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := h.DB.ListSandboxesForSecret(ctx, secretID)
	if err != nil {
		log.Warn().Err(err).Str("secret_id", secretID.String()).Msg("fanout: list sandboxes for secret")
		return
	}
	hosts := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		if r.HostID != "" {
			hosts[r.HostID] = struct{}{}
		}
	}
	if len(hosts) == 0 {
		return
	}

	var wg sync.WaitGroup
	for hostID := range hosts {
		wg.Add(1)
		go func(hostID string) {
			defer wg.Done()
			client, herr := h.Hosts.ClientFor(ctx, hostID)
			if herr != nil {
				log.Warn().Err(herr).Str("host_id", hostID).Msg("fanout: resolve host client")
				return
			}
			if err := client.InvalidateSecret(ctx, secretID.String()); err != nil {
				log.Warn().Err(err).Str("host_id", hostID).Str("secret_id", secretID.String()).Msg("fanout: InvalidateSecret failed")
			}
		}(hostID)
	}
	wg.Wait()
}

// ListSandboxRevocations returns the active sandbox-revocation set for daemon bootstrap.
func (h *Handlers) ListSandboxRevocations(c *gin.Context) {
	rows, err := h.DB.ListActiveSandboxRevocations(c.Request.Context())
	if err != nil {
		log.Error().Err(err).Msg("DB ListActiveSandboxRevocations failed")
		respondError(c, ErrInternal)
		return
	}
	out := make([]string, 0, len(rows))
	for _, id := range rows {
		out = append(out, id.String())
	}
	c.JSON(http.StatusOK, gin.H{"sandboxes": out})
}

// fanoutSandboxRevoke calls RevokeSandbox on the daemon at hostID. Best-effort;
// the daemon picks it up via bootstrap on next restart if this call fails.
func (h *Handlers) fanoutSandboxRevoke(ctx context.Context, sandboxID uuid.UUID, hostID string) {
	if h.Hosts == nil || hostID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, err := h.Hosts.ClientFor(ctx, hostID)
	if err != nil {
		log.Warn().Err(err).Str("host_id", hostID).Msg("fanout revoke: resolve host client")
		return
	}
	if err := client.RevokeSandbox(ctx, sandboxID.String()); err != nil {
		log.Warn().Err(err).Str("host_id", hostID).Str("sandbox_id", sandboxID.String()).Msg("fanout revoke: RevokeSandbox failed")
	}
}

type decryptSecretRequest struct {
	TeamID   string `json:"team_id"`
	SecretID string `json:"secret_id"`
}

type decryptSecretResponse struct {
	Value string `json:"value"`
}

// DecryptSecret handles POST /internal/secrets/decrypt for the in-host daemon.
// Authenticated via INTERNAL_API_TOKEN; 404 for missing, soft-deleted, or cross-team.
func (h *Handlers) DecryptSecret(c *gin.Context) {
	if !h.requireEncryptor(c) {
		return
	}
	var req decryptSecretRequest
	if err := bindJSONStrict(c, &req); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	secretID, err := uuid.Parse(req.SecretID)
	if err != nil {
		respondErrorMsg(c, "bad_request", "secret_id is not a valid UUID", http.StatusBadRequest)
		return
	}
	teamID, err := uuid.Parse(req.TeamID)
	if err != nil {
		respondErrorMsg(c, "bad_request", "team_id is not a valid UUID", http.StatusBadRequest)
		return
	}

	row, err := h.DB.GetSecretByIDForDecrypt(c.Request.Context(), db.GetSecretByIDForDecryptParams{
		ID: secretID, TeamID: teamID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondErrorMsg(c, "not_found", "secret not found or revoked", http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("secret_id", secretID.String()).Msg("DB GetSecretByIDForDecrypt in DecryptSecret")
		respondError(c, ErrInternal)
		return
	}

	plaintext, err := h.Encryptor.Decrypt(c.Request.Context(), secrets.Encrypted{
		Ciphertext:   row.Ciphertext,
		EncryptedDEK: row.EncryptedDek,
		KEKID:        row.KekID,
	})
	if err != nil {
		log.Error().Err(err).Str("secret_id", secretID.String()).Msg("KMS decrypt in DecryptSecret")
		respondError(c, ErrInternal)
		return
	}

	// Best-effort last-used stamp.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.DB.TouchSecretLastUsed(ctx, secretID)
	}()

	c.JSON(http.StatusOK, decryptSecretResponse{Value: string(plaintext)})
}

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateSecretsRefs validates the `secrets` map on POST /sandboxes.
func validateSecretsRefs(refs map[string]string) error {
	if len(refs) == 0 {
		return nil
	}
	if len(refs) > envVarsMaxKeys {
		return fmt.Errorf("secrets has %d entries, max is %d", len(refs), envVarsMaxKeys)
	}
	for envKey, name := range refs {
		if !envKeyRE.MatchString(envKey) {
			return fmt.Errorf("secrets key %q is not a valid env-var name", envKey)
		}
		if err := validateSecretName(name); err != nil {
			return fmt.Errorf("secrets[%s]: %w", envKey, err)
		}
	}
	return nil
}

// resolveSecretBindingsForCreate returns sandbox_secret rows and the daemon-shipped
// metadata for the referenced secrets; cleartext stays in the vault.
func (h *Handlers) resolveSecretBindingsForCreate(
	ctx context.Context,
	teamID uuid.UUID,
	refs map[string]string,
) (bindings []db.AddSandboxSecretParams, meta []SecretBindingMeta, appErr *AppError) {
	if len(refs) == 0 {
		return nil, nil, nil
	}
	bindings = make([]db.AddSandboxSecretParams, 0, len(refs))
	meta = make([]SecretBindingMeta, 0, len(refs))

	for envKey, name := range refs {
		row, err := h.DB.GetSecretByName(ctx, db.GetSecretByNameParams{
			TeamID: teamID, Name: name,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, nil, NewAppError("secret_not_found",
					fmt.Sprintf("secrets[%s] references %q, which does not exist for this team", envKey, name),
					http.StatusBadRequest)
			}
			log.Error().Err(err).Str("name", name).Msg("DB GetSecretByName during sandbox create")
			return nil, nil, ErrInternal
		}
		bindings = append(bindings, db.AddSandboxSecretParams{
			SecretID: row.ID,
			EnvKey:   envKey,
		})
		token, terr := mintProxyToken(row.ProviderShortcut)
		if terr != nil {
			log.Error().Err(terr).Msg("mintProxyToken during sandbox create")
			return nil, nil, ErrInternal
		}
		meta = append(meta, SecretBindingMeta{
			SecretID:         row.ID,
			EnvKey:           envKey,
			AuthType:         row.AuthType,
			AuthConfig:       row.AuthConfig,
			ProviderShortcut: row.ProviderShortcut,
			Hosts:            row.Hosts,
			ProxyToken:       token,
		})
	}
	return bindings, meta, nil
}

// mintSecretsJWT builds the per-sandbox secrets JWT. Returns the signed JWT
// string. Callers pass the sandbox's veth source IP and the team's
// unmatched-host policy. network may be nil when no customer egress rules
// apply (e.g., resume path preserves snapshotted firewall rules).
func (h *Handlers) mintSecretsJWT(sandboxID, teamID, sourceIP, unmatchedHostPolicy string, network *networkConfigRequest, meta []SecretBindingMeta) (string, error) {
	if h.Signer == nil {
		return "", fmt.Errorf("secrets signer not configured")
	}
	claims := SecretsClaims{
		TeamID:              teamID,
		SourceIP:            sourceIP,
		UnmatchedHostPolicy: unmatchedHostPolicy,
	}
	if network != nil {
		claims.Allow = append(claims.Allow, network.AllowOut...)
		claims.Deny = append(claims.Deny, network.DenyOut...)
	}
	claims.Bindings = make([]SecretsBindingClaim, 0, len(meta))
	for _, m := range meta {
		var authCfg map[string]any
		if len(m.AuthConfig) > 0 {
			if err := json.Unmarshal(m.AuthConfig, &authCfg); err != nil {
				return "", fmt.Errorf("decode auth_config for env_key=%q: %w", m.EnvKey, err)
			}
		}
		claims.Bindings = append(claims.Bindings, SecretsBindingClaim{
			ProxyToken: m.ProxyToken,
			SecretID:   m.SecretID.String(),
			EnvKey:     m.EnvKey,
			Hosts:      m.Hosts,
			AuthType:   m.AuthType,
			AuthConfig: authCfg,
		})
	}
	return h.Signer.Sign(sandboxID, claims)
}

// mergeEnvVarsWithSecrets overlays per-binding proxy tokens onto envVars,
// returning a fresh map. Callers must have ensured the keys don't collide.
func mergeEnvVarsWithSecrets(envVars map[string]string, meta []SecretBindingMeta) map[string]string {
	if len(meta) == 0 {
		return envVars
	}
	out := make(map[string]string, len(envVars)+len(meta))
	for k, v := range envVars {
		out[k] = v
	}
	for _, m := range meta {
		out[m.EnvKey] = m.ProxyToken
	}
	return out
}

// SecretBindingMeta is the per-binding info shipped to the daemon and injected
// as the agent's env-var value. Carries no cleartext.
type SecretBindingMeta struct {
	SecretID         uuid.UUID
	EnvKey           string
	AuthType         string
	AuthConfig       []byte
	ProviderShortcut *string
	Hosts            []string
	ProxyToken       string
}

// mintProxyToken returns a fresh per-binding token shaped to match the upstream key format.
func mintProxyToken(providerShortcut *string) (string, error) {
	spec := defaultTokenSpec
	if providerShortcut != nil {
		if sc, ok := providerShortcuts[*providerShortcut]; ok && sc.Token.Prefix != "" {
			spec = sc.Token
		}
	}
	body, err := mintTokenBody(spec.BodyLen, spec.Alphabet)
	if err != nil {
		return "", err
	}
	return spec.Prefix + body, nil
}

const alnumAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// mintTokenBody returns n characters drawn from the named alphabet ("alnum" or "b64url").
func mintTokenBody(n int, alphabet string) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("invalid body length %d", n)
	}
	switch alphabet {
	case "alnum":
		return randomFromAlnum(n)
	case "b64url":
		raw := make([]byte, (n*6+7)/8)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("rand: %w", err)
		}
		s := base64.RawURLEncoding.EncodeToString(raw)
		return s[:n], nil
	default:
		return "", fmt.Errorf("unsupported alphabet %q", alphabet)
	}
}

// randomFromAlnum samples n bytes from alnumAlphabet with rejection sampling for uniformity.
func randomFromAlnum(n int) (string, error) {
	const aLen = byte(len(alnumAlphabet))
	cutoff := byte(256 - (256 % int(aLen)))

	out := make([]byte, n)
	buf := make([]byte, n*2)
	bufIdx := len(buf)
	for i := 0; i < n; {
		if bufIdx >= len(buf) {
			if _, err := rand.Read(buf); err != nil {
				return "", fmt.Errorf("rand: %w", err)
			}
			bufIdx = 0
		}
		b := buf[bufIdx]
		bufIdx++
		if b >= cutoff {
			continue
		}
		out[i] = alnumAlphabet[int(b)%int(aLen)]
		i++
	}
	return string(out), nil
}

const (
	auditDefaultLimit = 100
	auditMaxLimit     = 1000
)

type proxyAuditResponse struct {
	ID             int64   `json:"id"`
	Ts             string  `json:"ts"`
	SandboxID      string  `json:"sandbox_id"`
	SecretID       string  `json:"secret_id,omitempty"`
	Method         string  `json:"method"`
	Host           string  `json:"host"`
	Path           string  `json:"path"`
	Status         int32   `json:"status"`
	UpstreamStatus *int32  `json:"upstream_status,omitempty"`
	LatencyMs      *int32  `json:"latency_ms,omitempty"`
	ErrorCode      *string `json:"error_code,omitempty"`
}

func toAuditResponse(r db.ProxyAudit) proxyAuditResponse {
	resp := proxyAuditResponse{
		ID:             r.ID,
		Ts:             r.Ts.UTC().Format(time.RFC3339Nano),
		SandboxID:      r.SandboxID.String(),
		Method:         r.Method,
		Host:           r.Host,
		Path:           r.Path,
		Status:         r.Status,
		UpstreamStatus: r.UpstreamStatus,
		LatencyMs:      r.LatencyMs,
		ErrorCode:      r.ErrorCode,
	}
	if r.SecretID.Valid {
		resp.SecretID = uuid.UUID(r.SecretID.Bytes).String()
	}
	return resp
}

func (h *Handlers) GetSandboxAudit(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	sandboxID, err := parseSandboxID(c)
	if err != nil {
		return
	}

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
		out[i] = toAuditResponse(r)
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

