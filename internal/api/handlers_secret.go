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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"

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
	Display    string // human-readable label shown in console pickers
	AuthType   string
	AuthConfig map[string]any
	Hosts      []string
	Token      tokenSpec
}

var providerShortcuts = map[string]providerShortcut{
	"anthropic": {
		Display:    "Anthropic",
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "x-api-key"},
		Hosts:      []string{"api.anthropic.com"},
		Token:      tokenSpec{Prefix: "sk-ant-api03-", BodyLen: 48, Alphabet: "alnum"},
	},
	"openai": {
		Display:    "OpenAI",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.openai.com"},
		Token:      tokenSpec{Prefix: "sk-proj-", BodyLen: 64, Alphabet: "alnum"},
	},
	"github": {
		// REST uses Bearer; git over HTTPS uses Basic with x-access-token.
		Display:  "GitHub",
		AuthType: authTypePerHost,
		AuthConfig: map[string]any{
			"per_host": []map[string]any{
				{"hosts": []string{"api.github.com"}, "type": "bearer"},
				{"hosts": []string{"github.com"}, "type": "basic", "username": "x-access-token"},
			},
		},
		Hosts: []string{"api.github.com", "github.com"},
		Token: tokenSpec{Prefix: "ghp_", BodyLen: 36, Alphabet: "alnum"},
	},
	"stripe": {
		Display:    "Stripe",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.stripe.com"},
		// sk_test_ rather than sk_live_ so scanners don't flag the token as live payment data.
		Token: tokenSpec{Prefix: "sk_test_", BodyLen: 24, Alphabet: "alnum"},
	},
	"slack": {
		Display:    "Slack",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"slack.com"},
		Token:      tokenSpec{Prefix: "xoxb-", BodyLen: 43, Alphabet: "b64url"},
	},
	"linear": {
		Display:    "Linear",
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "Authorization"},
		Hosts:      []string{"api.linear.app"},
		Token:      tokenSpec{Prefix: "lin_api_", BodyLen: 32, Alphabet: "alnum"},
	},
	"xai": {
		Display:    "xAI",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.x.ai"},
		Token:      tokenSpec{Prefix: "xai-", BodyLen: 80, Alphabet: "alnum"},
	},
	"gemini": {
		// Native API takes the key in the x-goog-api-key header.
		Display:    "Google Gemini",
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "x-goog-api-key"},
		Hosts:      []string{"generativelanguage.googleapis.com"},
		Token:      tokenSpec{Prefix: "AIza", BodyLen: 35, Alphabet: "b64url"},
	},
	"perplexity": {
		Display:    "Perplexity",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.perplexity.ai"},
		Token:      tokenSpec{Prefix: "pplx-", BodyLen: 48, Alphabet: "alnum"},
	},
	"exa": {
		Display:    "Exa",
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "x-api-key"},
		Hosts:      []string{"api.exa.ai"},
		// Exa keys have no documented prefix; mint a prefixless body.
		Token: tokenSpec{BodyLen: 32, Alphabet: "alnum"},
	},
	"firecrawl": {
		Display:    "Firecrawl",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.firecrawl.dev"},
		Token:      tokenSpec{Prefix: "fc-", BodyLen: 36, Alphabet: "alnum"},
	},
	"gitlab": {
		Display:    "GitLab",
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "PRIVATE-TOKEN"},
		Hosts:      []string{"gitlab.com"},
		Token:      tokenSpec{Prefix: "glpat-", BodyLen: 20, Alphabet: "alnum"},
	},
	"vercel": {
		Display:    "Vercel",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.vercel.com"},
		Token:      tokenSpec{Prefix: "vcp_", BodyLen: 24, Alphabet: "alnum"},
	},
	"cloudflare": {
		Display:    "Cloudflare",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.cloudflare.com"},
		// Cloudflare API tokens are a 40-char alphanumeric string with no prefix.
		Token: tokenSpec{BodyLen: 40, Alphabet: "alnum"},
	},
	"asana": {
		Display:    "Asana",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"app.asana.com"},
		// Asana tokens are opaque with no stable prefix.
		Token: tokenSpec{BodyLen: 32, Alphabet: "alnum"},
	},
	"sentry": {
		Display:    "Sentry",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"sentry.io"},
		Token:      tokenSpec{Prefix: "sntrys_", BodyLen: 32, Alphabet: "alnum"},
	},
	"resend": {
		Display:    "Resend",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.resend.com"},
		Token:      tokenSpec{Prefix: "re_", BodyLen: 24, Alphabet: "alnum"},
	},
	"notion": {
		Display:    "Notion",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.notion.com"},
		Token:      tokenSpec{Prefix: "ntn_", BodyLen: 43, Alphabet: "alnum"},
	},
	"openrouter": {
		Display:    "OpenRouter",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"openrouter.ai"},
		Token:      tokenSpec{Prefix: "sk-or-v1-", BodyLen: 64, Alphabet: "alnum"},
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
// When PerHost is set, Type and the type-specific fields must be empty; each
// rule in PerHost carries its own shape.
type authConfigRequest struct {
	Type     string            `json:"type,omitempty"`
	Header   string            `json:"header,omitempty"`   // api-key only
	Prefix   string            `json:"prefix,omitempty"`   // api-key only
	Username string            `json:"username,omitempty"` // basic only — overrides preserve-inbound
	Headers  map[string]string `json:"headers,omitempty"`  // custom only
	PerHost  []perHostRule     `json:"per_host,omitempty"` // multi-rule, dispatched by upstream host
}

// perHostRule is one (hosts → auth shape) entry inside authConfigRequest.PerHost.
type perHostRule struct {
	Hosts    []string          `json:"hosts"`
	Type     string            `json:"type"`
	Header   string            `json:"header,omitempty"`
	Prefix   string            `json:"prefix,omitempty"`
	Username string            `json:"username,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
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
		if err := rejectOverbroadWildcard(h); err != nil {
			return fmt.Errorf("hosts[%d]: %w", i, err)
		}
		hosts[i] = h
	}
	return nil
}

// rejectOverbroadWildcard refuses wildcards rooted at a public suffix
// (`*.com`, `*.co.uk`). Private TLDs (.local, .test) aren't on Mozilla's
// PSL and so are allowed through.
func rejectOverbroadWildcard(host string) error {
	if !strings.HasPrefix(host, "*.") {
		return nil
	}
	base := strings.ToLower(host[2:])
	suffix, _ := publicsuffix.PublicSuffix(base)
	if base == suffix {
		return fmt.Errorf("wildcard %q is too broad — %q is a public suffix; narrow to a specific subdomain", host, base)
	}
	return nil
}

func validateAuthConfig(auth *authConfigRequest) error {
	if auth == nil {
		return errors.New("auth is required when provider is not set")
	}
	if len(auth.PerHost) > 0 {
		if auth.Type != "" || auth.Header != "" || auth.Prefix != "" || auth.Username != "" || len(auth.Headers) > 0 {
			return errors.New("auth.per_host is mutually exclusive with auth.type and the type-specific fields")
		}
		return nil // per-host rules validated separately against the hosts allowlist
	}
	if auth.Type == "" {
		return errors.New("auth.type or auth.per_host is required")
	}
	return validateAuthShape(auth.Type, auth.Header, auth.Prefix, auth.Username, auth.Headers, "auth")
}

// validateAuthShape validates one (type, fields) combo. fieldPath is the JSON
// pointer prefix used in error messages (e.g. "auth" or "auth.per_host[0]").
func validateAuthShape(authType, header, prefix, username string, headers map[string]string, fieldPath string) error {
	switch authType {
	case "bearer":
		if header != "" || prefix != "" || username != "" || len(headers) > 0 {
			return fmt.Errorf("%s.type=%q does not accept header/prefix/username/headers", fieldPath, authType)
		}
	case "basic":
		if header != "" || prefix != "" || len(headers) > 0 {
			return fmt.Errorf("%s.type=%q does not accept header/prefix/headers", fieldPath, authType)
		}
		if username != "" && strings.ContainsAny(username, ":\r\n") {
			return fmt.Errorf("%s.username may not contain ':' or CR/LF", fieldPath)
		}
	case "api-key":
		if header == "" {
			return fmt.Errorf("%s.header is required for type=api-key", fieldPath)
		}
		if !headerNameRE.MatchString(header) {
			return fmt.Errorf("%s.header %q is not a valid header name", fieldPath, header)
		}
		if len(headers) > 0 {
			return fmt.Errorf("%s.headers is not allowed for type=api-key", fieldPath)
		}
		if username != "" {
			return fmt.Errorf("%s.username is not allowed for type=api-key", fieldPath)
		}
	case "custom":
		if len(headers) == 0 {
			return fmt.Errorf("%s.headers is required for type=custom", fieldPath)
		}
		if len(headers) > maxCustomHeaders {
			return fmt.Errorf("%s.headers has %d entries, max is %d", fieldPath, len(headers), maxCustomHeaders)
		}
		for name, tmpl := range headers {
			if !headerNameRE.MatchString(name) {
				return fmt.Errorf("%s.headers: %q is not a valid header name", fieldPath, name)
			}
			if !strings.Contains(tmpl, "{{ value }}") {
				return fmt.Errorf("%s.headers[%s]: template must reference {{ value }} so the credential is actually injected", fieldPath, name)
			}
		}
		if header != "" || prefix != "" || username != "" {
			return fmt.Errorf("%s.type=custom does not accept header/prefix/username; use headers map", fieldPath)
		}
	case "":
		return fmt.Errorf("%s.type is required", fieldPath)
	default:
		return fmt.Errorf("%s.type %q is not supported (got: bearer, basic, api-key, custom)", fieldPath, authType)
	}
	return nil
}

// validatePerHostRules checks that every rule's hosts are reachable from
// the top-level allowlist (wildcard-aware), that no two rules' hosts overlap,
// and that each rule's auth fields validate against its declared type.
func validatePerHostRules(rules []perHostRule, allowedHosts []string) error {
	if len(rules) == 0 {
		return errors.New("auth.per_host must contain at least one rule")
	}
	if len(rules) > maxHostsPerSecret {
		return fmt.Errorf("auth.per_host has %d rules, max is %d", len(rules), maxHostsPerSecret)
	}
	type seenHost struct {
		ruleIdx int
		host    string
	}
	var seen []seenHost
	for i := range rules {
		r := &rules[i]
		if err := validateHosts(r.Hosts); err != nil {
			return fmt.Errorf("auth.per_host[%d]: %w", i, err)
		}
		for _, h := range r.Hosts {
			if !hostReachable(h, allowedHosts) {
				return fmt.Errorf("auth.per_host[%d].hosts: %q is not reachable from the top-level hosts allowlist", i, h)
			}
			for _, prev := range seen {
				if patternsOverlap(h, prev.host) {
					return fmt.Errorf("auth.per_host[%d].hosts: %q overlaps with auth.per_host[%d].hosts %q", i, h, prev.ruleIdx, prev.host)
				}
			}
			seen = append(seen, seenHost{i, h})
		}
		if err := validateAuthShape(r.Type, r.Header, r.Prefix, r.Username, r.Headers, fmt.Sprintf("auth.per_host[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// hostReachable reports whether at least one pattern in allowedHosts matches
// every host that h could refer to. Mirrors the daemon's matchHost semantics
// so validation and runtime agree on what "reachable" means.
func hostReachable(h string, allowedHosts []string) bool {
	for _, p := range allowedHosts {
		if patternCovers(p, h) {
			return true
		}
	}
	return false
}

// patternCovers returns true if every host matched by inner is also matched
// by outer. Both args may be exact hosts or `*.suffix` wildcards.
func patternCovers(outer, inner string) bool {
	outer = strings.ToLower(strings.TrimSpace(outer))
	inner = strings.ToLower(strings.TrimSpace(inner))
	if outer == inner {
		return true
	}
	outerWild := strings.HasPrefix(outer, "*.")
	innerWild := strings.HasPrefix(inner, "*.")
	if !outerWild {
		// An exact outer can only cover an identical exact inner (handled above).
		return false
	}
	outerSuffix := outer[1:] // ".X"
	outerBare := outer[2:]   // "X"
	if !innerWild {
		// Wildcard *.X covers exact host h iff h ends in ".X" and h != "X".
		return strings.HasSuffix(inner, outerSuffix) && inner != outerBare
	}
	// Wildcard *.X covers wildcard *.Y iff Y ends in .X (so every host matched
	// by *.Y also has the .X suffix). The bare-domain exclusion is preserved
	// at runtime by matchHost on each individual host.
	return strings.HasSuffix(inner[1:], outerSuffix)
}

// patternsOverlap returns true if a and b share at least one host they both
// match. Used at create time to reject ambiguous per-host rules.
func patternsOverlap(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == b {
		return true
	}
	aWild := strings.HasPrefix(a, "*.")
	bWild := strings.HasPrefix(b, "*.")
	switch {
	case !aWild && !bWild:
		return false
	case aWild && !bWild:
		suf, bare := a[1:], a[2:]
		return strings.HasSuffix(b, suf) && b != bare
	case !aWild && bWild:
		suf, bare := b[1:], b[2:]
		return strings.HasSuffix(a, suf) && a != bare
	default:
		// Two wildcards *.X and *.Y overlap iff one suffix-contains the other:
		// every host *.foo.example.com matches is also matched by *.example.com.
		aSuf, bSuf := a[1:], b[1:]
		return strings.HasSuffix(aSuf, bSuf) || strings.HasSuffix(bSuf, aSuf)
	}
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
	if len(req.Auth.PerHost) > 0 {
		if err = validatePerHostRules(req.Auth.PerHost, req.Hosts); err != nil {
			return
		}
		authType = authTypePerHost
		authConfig, err = marshalPerHostConfig(req.Auth.PerHost)
		hosts = req.Hosts
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
	case "basic":
		if req.Auth.Username != "" {
			cfg["username"] = req.Auth.Username
		}
	case "custom":
		cfg["headers"] = req.Auth.Headers
	}
	authConfig, err = json.Marshal(cfg)
	hosts = req.Hosts
	return
}

// authTypePerHost is the auth_type sentinel for multi-rule secrets. The
// daemon dispatches by upstream host using the rules embedded in auth_config.
const authTypePerHost = "per_host"

// marshalPerHostConfig serializes the rule list into auth_config jsonb shape.
func marshalPerHostConfig(rules []perHostRule) ([]byte, error) {
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		entry := map[string]any{
			"hosts": r.Hosts,
			"type":  r.Type,
		}
		switch r.Type {
		case "basic":
			if r.Username != "" {
				entry["username"] = r.Username
			}
		case "api-key":
			entry["header"] = r.Header
			if r.Prefix != "" {
				entry["prefix"] = r.Prefix
			}
		case "custom":
			entry["headers"] = r.Headers
		}
		out = append(out, entry)
	}
	return json.Marshal(map[string]any{"per_host": out})
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
	if !h.requireTeamSettingsWrite(c, teamID) {
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

	meta, _ := json.Marshal(map[string]any{
		"auth_type":         authType,
		"provider_shortcut": shortcut,
		"hosts":             hosts,
	})
	h.logSecretActivity(c.Request.Context(), row.ID, teamID, actorIDFromContext(c), "created", "success", row.Name, meta)

	c.JSON(http.StatusCreated, toSecretResponse(row))
}

func (h *Handlers) ListSecrets(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSettingsRead(c, teamID) {
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
	if !h.requireTeamSettingsRead(c, teamID) {
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
	if !h.requireTeamSettingsWrite(c, teamID) {
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

	h.logSecretActivity(c.Request.Context(), updated.ID, teamID, actorIDFromContext(c), "rotated", "success", updated.Name, nil)

	c.JSON(http.StatusOK, toSecretResponse(updated))
}

func (h *Handlers) DeleteSecret(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSettingsWrite(c, teamID) {
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

	h.logSecretActivity(c.Request.Context(), row.ID, teamID, actorIDFromContext(c), "deleted", "success", row.Name, nil)

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

// ListSandboxRevocations returns the active revocation set for daemon bootstrap:
// whole sandboxes and individual detached proxy tokens.
func (h *Handlers) ListSandboxRevocations(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.DB.ListActiveSandboxRevocations(ctx)
	if err != nil {
		log.Error().Err(err).Msg("DB ListActiveSandboxRevocations failed")
		respondError(c, ErrInternal)
		return
	}
	sandboxes := make([]string, 0, len(rows))
	for _, id := range rows {
		sandboxes = append(sandboxes, id.String())
	}

	tokenRows, err := h.DB.ListActiveRevokedProxyTokens(ctx)
	if err != nil {
		log.Error().Err(err).Msg("DB ListActiveRevokedProxyTokens failed")
		respondError(c, ErrInternal)
		return
	}
	tokens := make([]gin.H, 0, len(tokenRows))
	for _, t := range tokenRows {
		tokens = append(tokens, gin.H{"sandbox_id": t.SandboxID.String(), "proxy_token": t.ProxyToken})
	}

	c.JSON(http.StatusOK, gin.H{"sandboxes": sandboxes, "proxy_tokens": tokens})
}

// GetSandboxEgressRules serves a sandbox's current egress rules to the secrets
// proxy, which fetches them live rather than reading stale values from the JWT.
// Internal endpoint (daemon-authed), so it is not team-scoped.
func (h *Handlers) GetSandboxEgressRules(c *gin.Context) {
	sandboxID, err := uuid.Parse(c.Param("sandbox_id"))
	if err != nil {
		respondErrorMsg(c, "bad_request", "invalid sandbox id", http.StatusBadRequest)
		return
	}
	row, err := h.DB.GetSandboxEgressContext(c.Request.Context(), sandboxID)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.Status(http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("sandbox_id", sandboxID.String()).Msg("DB GetSandboxEgressContext failed")
		respondError(c, ErrInternal)
		return
	}
	var cfg persistedEgressConfig
	if len(row.NetworkConfig) > 0 {
		if uerr := json.Unmarshal(row.NetworkConfig, &cfg); uerr != nil {
			log.Warn().Err(uerr).Str("sandbox_id", sandboxID.String()).Msg("parse network_config for egress rules")
		}
	}
	allow := append(append([]string{}, cfg.Egress.AllowedCIDRs...), cfg.Egress.AllowedDomains...)
	c.JSON(http.StatusOK, gin.H{
		"allow":                 allow,
		"deny":                  cfg.Egress.DeniedCIDRs,
		"unmatched_host_policy": row.UnmatchedHostPolicy,
	})
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
		_ = h.DB.TouchSecretLastUsed(ctx, db.TouchSecretLastUsedParams{ID: secretID, TeamID: teamID})
	}()

	c.JSON(http.StatusOK, decryptSecretResponse{Value: string(plaintext)})
}

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateSecretsRefs validates the `secrets` map on POST /sandboxes.
func validateSecretsRefs(refs map[string]string) error {
	if len(refs) == 0 {
		return nil
	}
	// Each secret becomes one JWT binding; cap at that limit here (before boot)
	// rather than failing later at JWT mint, after the VM is already restored.
	if len(refs) > SecretsBindingsCap {
		return fmt.Errorf("secrets has %d entries, max is %d", len(refs), SecretsBindingsCap)
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

// loadSecretBindingMeta rebuilds a sandbox's binding metadata from the DB. The
// stored proxy token is reused so re-minting a JWT doesn't rotate stand-ins; a
// binding stored before tokens were persisted gets one minted on the fly.
func (h *Handlers) loadSecretBindingMeta(ctx context.Context, sandboxID uuid.UUID) ([]SecretBindingMeta, error) {
	rows, err := h.DB.ListSandboxSecretBindingMeta(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	meta := make([]SecretBindingMeta, 0, len(rows))
	for _, r := range rows {
		token := ""
		if r.ProxyToken != nil {
			token = *r.ProxyToken
		}
		if token == "" {
			t, terr := mintProxyToken(r.ProviderShortcut)
			if terr != nil {
				return nil, terr
			}
			// Persist-or-adopt: the returned token is the authoritative stored one
			// (ours, or a concurrent writer's via COALESCE), so the token we ship in
			// the JWT/env below always matches what detach can revoke.
			stored, perr := h.DB.ClaimSandboxSecretProxyToken(ctx, db.ClaimSandboxSecretProxyTokenParams{
				SandboxID: sandboxID, EnvKey: r.EnvKey, ProxyToken: &t,
			})
			if perr != nil {
				return nil, fmt.Errorf("persist minted proxy token for %q: %w", r.EnvKey, perr)
			}
			if stored == nil {
				return nil, fmt.Errorf("persist minted proxy token for %q: no token returned", r.EnvKey)
			}
			token = *stored
		}
		meta = append(meta, SecretBindingMeta{
			SecretID:         r.SecretID,
			EnvKey:           r.EnvKey,
			AuthType:         r.AuthType,
			AuthConfig:       r.AuthConfig,
			ProviderShortcut: r.ProviderShortcut,
			Hosts:            r.Hosts,
			ProxyToken:       token,
		})
	}
	return meta, nil
}

// applySecretBindings mints the secrets JWT for meta and injects it, with the secret
// env vars, into a live sandbox. Empty meta injects no JWT. InjectSandboxEnv merges,
// so it can add or update an env var but not remove one.
func (h *Handlers) applySecretBindings(ctx context.Context, sandbox db.Sandbox, meta []SecretBindingMeta) error {
	vmd, err := h.vmdForHost(ctx, sandbox.HostID)
	if err != nil {
		return fmt.Errorf("resolve vmd for host: %w", err)
	}
	var jwt string
	if len(meta) > 0 {
		sourceIP := ""
		if sandbox.IpAddress != nil {
			sourceIP = sandbox.IpAddress.String()
		}
		jwt, err = h.mintSecretsJWT(sandbox.ID.String(), sandbox.TeamID.String(), sourceIP, meta)
		if err != nil {
			return fmt.Errorf("mint secrets jwt: %w", err)
		}
	}
	if err := vmd.InjectSandboxEnv(ctx, sandbox.ID.String(), mergeEnvVarsWithSecrets(nil, meta), jwt); err != nil {
		return fmt.Errorf("inject sandbox env: %w", err)
	}
	return nil
}

// mintSecretsJWT builds the per-sandbox secrets JWT. Returns the signed JWT
// string. The sandbox's veth source IP binds the token; egress rules are not
// carried here — the proxy fetches them live from GetSandboxEgressRules.
func (h *Handlers) mintSecretsJWT(sandboxID, teamID, sourceIP string, meta []SecretBindingMeta) (string, error) {
	if h.Signer == nil {
		return "", fmt.Errorf("secrets signer not configured")
	}
	claims := SecretsClaims{
		TeamID:   teamID,
		SourceIP: sourceIP,
	}
	claims.Bindings = make([]SecretsBindingClaim, 0, len(meta))
	for _, m := range meta {
		var authCfg map[string]any
		if len(m.AuthConfig) > 0 {
			if err := json.Unmarshal(m.AuthConfig, &authCfg); err != nil {
				return "", fmt.Errorf("decode auth_config for env_key=%q: %w", m.EnvKey, err)
			}
		}
		binding := SecretsBindingClaim{
			ProxyToken: m.ProxyToken,
			SecretID:   m.SecretID.String(),
			EnvKey:     m.EnvKey,
			Hosts:      m.Hosts,
		}
		if m.AuthType == authTypePerHost {
			rules, rerr := perHostRulesFromConfig(authCfg)
			if rerr != nil {
				return "", fmt.Errorf("decode per_host rules for env_key=%q: %w", m.EnvKey, rerr)
			}
			binding.Rules = rules
		} else {
			binding.AuthType = m.AuthType
			binding.AuthConfig = authCfg
		}
		claims.Bindings = append(claims.Bindings, binding)
	}
	return h.Signer.Sign(sandboxID, claims)
}

// perHostRulesFromConfig converts the jsonb per_host blob into JWT rule claims.
func perHostRulesFromConfig(cfg map[string]any) ([]SecretsBindingRuleClaim, error) {
	raw, ok := cfg["per_host"]
	if !ok {
		return nil, errors.New("auth_config missing per_host entry")
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("auth_config.per_host is not a list")
	}
	out := make([]SecretsBindingRuleClaim, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("per_host[%d] is not an object", i)
		}
		rule := SecretsBindingRuleClaim{}
		if h, ok := m["hosts"].([]any); ok {
			rule.Hosts = make([]string, 0, len(h))
			for _, hv := range h {
				if s, ok := hv.(string); ok {
					rule.Hosts = append(rule.Hosts, s)
				}
			}
		}
		rule.AuthType, _ = m["type"].(string)
		if v, ok := m["username"].(string); ok {
			rule.Username = v
		}
		if v, ok := m["header"].(string); ok {
			rule.Header = v
		}
		if v, ok := m["prefix"].(string); ok {
			rule.Prefix = v
		}
		if hs, ok := m["headers"].(map[string]any); ok {
			rule.Headers = make(map[string]string, len(hs))
			for k, v := range hs {
				if s, ok := v.(string); ok {
					rule.Headers[k] = s
				}
			}
		}
		out = append(out, rule)
	}
	return out, nil
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
		if sc, ok := providerShortcuts[*providerShortcut]; ok && sc.Token.BodyLen > 0 {
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
	SandboxName    *string `json:"sandbox_name,omitempty"` // populated for cross-sandbox views; null for deleted sandboxes
	SecretID       string  `json:"secret_id,omitempty"`
	Method         string  `json:"method"`
	Host           string  `json:"host"`
	Path           string  `json:"path"`
	Status         int32   `json:"status"`
	UpstreamStatus *int32  `json:"upstream_status,omitempty"`
	LatencyMs      *int32  `json:"latency_ms,omitempty"`
	ErrorCode      *string `json:"error_code,omitempty"`
}

// toAuditResponseFromSecret renders a row from ListAuditForSecret. SandboxName
// is nil when the sandbox referenced in the audit row has been deleted.
func toAuditResponseFromSecret(r db.ListAuditForSecretRow) proxyAuditResponse {
	resp := proxyAuditResponse{
		ID:             r.ID,
		Ts:             r.Ts.UTC().Format(time.RFC3339Nano),
		SandboxID:      r.SandboxID.String(),
		SandboxName:    r.SandboxName,
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

// GetSecretAudit returns the per-secret audit log: every egress request that
// used this credential across every sandbox it was bound to.
func (h *Handlers) GetSecretAudit(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSettingsRead(c, teamID) {
		return
	}
	name := c.Param("name")
	if err := validateSecretName(name); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	secret, err := h.DB.GetSecretByName(c.Request.Context(), db.GetSecretByNameParams{
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
	minStatus, maxStatus, err := parseStatusFilter(c.Query("status"))
	if err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}

	var cursorID *int64
	if before > 0 {
		cursorID = &before
	}
	rows, err := h.DB.ListAuditForSecret(c.Request.Context(), db.ListAuditForSecretParams{
		SecretID:  pgtype.UUID{Bytes: secret.ID, Valid: true},
		TeamID:    teamID,
		CursorID:  cursorID,
		StatusMin: minStatus,
		StatusMax: maxStatus,
		RowLimit:  limit,
	})
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("DB ListAuditForSecret failed")
		respondError(c, ErrInternal)
		return
	}

	out := make([]proxyAuditResponse, len(rows))
	for i, r := range rows {
		out[i] = toAuditResponseFromSecret(r)
	}
	c.JSON(http.StatusOK, out)
}

// sandboxBoundResponse is one row of "sandboxes bound to this secret".
type sandboxBoundResponse struct {
	SandboxID   string `json:"sandbox_id"`
	SandboxName string `json:"sandbox_name"`
	EnvKey      string `json:"env_key"`
	Status      string `json:"status"`
}

// GetSecretSandboxes returns the active sandboxes that have this secret
// bound, with the env-var name each binding uses.
func (h *Handlers) GetSecretSandboxes(c *gin.Context) {
	teamID, err := teamIDFromContext(c)
	if err != nil {
		return
	}
	if !h.requireTeamSettingsRead(c, teamID) {
		return
	}
	name := c.Param("name")
	if err := validateSecretName(name); err != nil {
		respondErrorMsg(c, "bad_request", err.Error(), http.StatusBadRequest)
		return
	}
	secret, err := h.DB.GetSecretByName(c.Request.Context(), db.GetSecretByNameParams{
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

	rows, err := h.DB.ListSandboxesBoundToSecret(c.Request.Context(), db.ListSandboxesBoundToSecretParams{
		SecretID: secret.ID,
		TeamID:   teamID,
	})
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("DB ListSandboxesBoundToSecret failed")
		respondError(c, ErrInternal)
		return
	}
	out := make([]sandboxBoundResponse, len(rows))
	for i, r := range rows {
		out[i] = sandboxBoundResponse{
			SandboxID:   r.ID.String(),
			SandboxName: r.Name,
			EnvKey:      r.EnvKey,
			Status:      string(r.Status),
		}
	}
	c.JSON(http.StatusOK, out)
}

// parseStatusFilter accepts "", "2xx", "3xx", "4xx", "5xx", or "errors"
// (errors = anything ≥ 400). Returns (min, max) inclusive bounds. "" means
// no filter (0, 9999 — the sentinel the sqlc query expects).
func parseStatusFilter(raw string) (int32, int32, error) {
	switch raw {
	case "":
		return 0, 9999, nil
	case "2xx":
		return 200, 299, nil
	case "3xx":
		return 300, 399, nil
	case "4xx":
		return 400, 499, nil
	case "5xx":
		return 500, 599, nil
	case "errors":
		return 400, 9999, nil
	default:
		return 0, 0, fmt.Errorf("status must be one of: 2xx, 3xx, 4xx, 5xx, errors")
	}
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

// providerResponse is one entry of the provider catalog returned by
// GET /providers. Backend-of-record so consumers stay in sync with the
// in-memory providerShortcuts map.
type providerResponse struct {
	Name       string         `json:"name"`
	Display    string         `json:"display"`
	AuthType   string         `json:"auth_type"`
	AuthConfig map[string]any `json:"auth_config"`
	Hosts      []string       `json:"hosts"`
	TokenShape string         `json:"token_shape"` // prefix + body-len hint for UX ("sk-ant-api03-...")
}

// ListProviders returns the built-in provider catalog in canonical order so
// the console always picks the same default. No team-scope check — the
// catalog is identical across teams.
func (h *Handlers) ListProviders(c *gin.Context) {
	out := make([]providerResponse, 0, len(providerShortcuts))
	for _, name := range knownProviders() {
		p := providerShortcuts[name]
		out = append(out, providerResponse{
			Name:       name,
			Display:    p.Display,
			AuthType:   p.AuthType,
			AuthConfig: p.AuthConfig,
			Hosts:      append([]string(nil), p.Hosts...),
			TokenShape: p.Token.Prefix + "...",
		})
	}
	c.JSON(http.StatusOK, out)
}
