package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestValidateSecretName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty", "", "required"},
		{"whitespace only", "   ", "required"},
		{"valid simple", "anthropic-prod", ""},
		{"valid underscore start", "_internal", ""},
		{"valid alphanumeric mix", "Stripe_Key2", ""},
		{"starts with digit", "1anthropic", "must start with"},
		{"starts with hyphen", "-anthropic", "must start with"},
		{"contains space", "anthropic prod", "must start with"},
		{"contains slash", "anthropic/prod", "must start with"},
		{"too long", strings.Repeat("a", maxSecretNameLen+1), "exceeds"},
		{"max length boundary", strings.Repeat("a", maxSecretNameLen), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSecretName(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("want no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateSecretValue(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"empty rejected", "", "required"},
		{"single byte allowed", "x", ""},
		{"realistic key allowed", "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", ""},
		{"exceeds cap", strings.Repeat("a", maxSecretValueLen+1), "exceeds"},
		{"max length boundary", strings.Repeat("a", maxSecretValueLen), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSecretValue(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("want no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateHosts(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr string
	}{
		{"empty rejected", []string{}, "required"},
		{"nil rejected", nil, "required"},
		{"single hostname", []string{"api.openai.com"}, ""},
		{"multiple", []string{"api.github.com", "github.com"}, ""},
		{"wildcard subdomain", []string{"*.github.com"}, ""},
		{"too many", repeatHost("api.example.com", maxHostsPerSecret+1), "max is"},
		{"invalid: path included", []string{"api.openai.com/v1"}, "is not a valid hostname"},
		{"invalid: scheme prefix", []string{"https://api.openai.com"}, "is not a valid hostname"},
		{"invalid: port suffix", []string{"api.openai.com:443"}, "is not a valid hostname"},
		{"invalid: bare TLD", []string{"localhost"}, "is not a valid hostname"},
		{"invalid: empty string", []string{""}, "is not a valid hostname"},
		{"invalid: bare wildcard", []string{"*"}, "is not a valid hostname"},
		{"invalid: nested wildcard", []string{"*.*.example.com"}, "is not a valid hostname"},
		{"whitespace trimmed", []string{"  api.openai.com  "}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Defensive copy: validateHosts mutates in place (whitespace trim).
			input := append([]string(nil), tc.input...)
			err := validateHosts(input)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("want no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func repeatHost(host string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = host
	}
	return out
}

func TestValidateAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   *authConfigRequest
		wantErr string
	}{
		{"nil rejected", nil, "required"},
		{"empty type", &authConfigRequest{}, "auth.type or auth.per_host is required"},
		{"unsupported type", &authConfigRequest{Type: "oauth"}, "not supported"},

		// bearer
		{"bearer ok", &authConfigRequest{Type: "bearer"}, ""},
		{"bearer rejects header", &authConfigRequest{Type: "bearer", Header: "x-foo"}, "does not accept"},
		{"bearer rejects prefix", &authConfigRequest{Type: "bearer", Prefix: "X "}, "does not accept"},
		{"bearer rejects headers map", &authConfigRequest{Type: "bearer", Headers: map[string]string{"a": "{{ value }}"}}, "does not accept"},

		// basic
		{"basic ok", &authConfigRequest{Type: "basic"}, ""},
		{"basic rejects header", &authConfigRequest{Type: "basic", Header: "x-foo"}, "does not accept"},

		// api-key
		{"api-key needs header", &authConfigRequest{Type: "api-key"}, "header is required"},
		{"api-key ok minimal", &authConfigRequest{Type: "api-key", Header: "x-api-key"}, ""},
		{"api-key ok with prefix", &authConfigRequest{Type: "api-key", Header: "Authorization", Prefix: "ApiKey "}, ""},
		{"api-key invalid header chars", &authConfigRequest{Type: "api-key", Header: "x api key"}, "is not a valid header name"},
		{"api-key rejects headers map", &authConfigRequest{Type: "api-key", Header: "x-api-key", Headers: map[string]string{"a": "{{ value }}"}}, "not allowed"},

		// custom
		{"custom needs headers", &authConfigRequest{Type: "custom"}, "headers is required"},
		{"custom ok", &authConfigRequest{Type: "custom", Headers: map[string]string{"X-Api-Key": "Bearer {{ value }}"}}, ""},
		{"custom rejects header field", &authConfigRequest{Type: "custom", Header: "x-foo", Headers: map[string]string{"X-A": "{{ value }}"}}, "does not accept"},
		{"custom rejects template without {{ value }}", &authConfigRequest{Type: "custom", Headers: map[string]string{"X-Api-Key": "static"}}, "must reference {{ value }}"},
		{"custom rejects bad header name", &authConfigRequest{Type: "custom", Headers: map[string]string{"X Api Key": "{{ value }}"}}, "is not a valid header name"},
		{"custom too many headers",
			&authConfigRequest{Type: "custom", Headers: repeatHeaderMap("h%d", "v {{ value }}", maxCustomHeaders+1)},
			"max is"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAuthConfig(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("want no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func repeatHeaderMap(keyFmt, val string, n int) map[string]string {
	out := make(map[string]string, n)
	for i := 0; i < n; i++ {
		out[strings.ReplaceAll(keyFmt, "%d", itoa(i))] = val
	}
	return out
}

func itoa(n int) string {
	// avoid strconv to keep this helper self-contained
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func TestResolveAuth(t *testing.T) {
	t.Run("provider shortcut populates auth_type, config, hosts", func(t *testing.T) {
		req := createSecretRequest{Name: "anthropic-prod", Value: "v", Provider: "anthropic"}
		authType, cfgJSON, hosts, shortcut, err := resolveAuth(req)
		if err != nil {
			t.Fatal(err)
		}
		if authType != "api-key" {
			t.Errorf("want api-key, got %q", authType)
		}
		var cfg map[string]any
		if jErr := json.Unmarshal(cfgJSON, &cfg); jErr != nil {
			t.Fatal(jErr)
		}
		if cfg["header"] != "x-api-key" {
			t.Errorf("want header=x-api-key, got %v", cfg["header"])
		}
		if len(hosts) != 1 || hosts[0] != "api.anthropic.com" {
			t.Errorf("want hosts=[api.anthropic.com], got %v", hosts)
		}
		if shortcut == nil || *shortcut != "anthropic" {
			t.Errorf("want shortcut=anthropic, got %v", shortcut)
		}
	})

	t.Run("provider shortcut: github carries both hosts", func(t *testing.T) {
		req := createSecretRequest{Name: "gh-prod", Value: "v", Provider: "github"}
		_, _, hosts, _, err := resolveAuth(req)
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(hosts)
		want := []string{"api.github.com", "github.com"}
		if len(hosts) != 2 || hosts[0] != want[0] || hosts[1] != want[1] {
			t.Errorf("want %v, got %v", want, hosts)
		}
	})

	t.Run("explicit auth config wins", func(t *testing.T) {
		req := createSecretRequest{
			Name:  "linear-prod",
			Value: "v",
			Auth:  &authConfigRequest{Type: "api-key", Header: "Authorization"},
			Hosts: []string{"api.linear.app"},
		}
		authType, cfgJSON, hosts, shortcut, err := resolveAuth(req)
		if err != nil {
			t.Fatal(err)
		}
		if authType != "api-key" {
			t.Errorf("want api-key, got %q", authType)
		}
		var cfg map[string]any
		_ = json.Unmarshal(cfgJSON, &cfg)
		if cfg["header"] != "Authorization" {
			t.Errorf("want Authorization, got %v", cfg["header"])
		}
		if len(hosts) != 1 || hosts[0] != "api.linear.app" {
			t.Errorf("want hosts=[api.linear.app], got %v", hosts)
		}
		if shortcut != nil {
			t.Errorf("want nil shortcut on explicit auth, got %v", shortcut)
		}
	})

	t.Run("bearer explicit emits empty config (no extra knobs)", func(t *testing.T) {
		req := createSecretRequest{
			Name:  "stripe-prod",
			Value: "v",
			Auth:  &authConfigRequest{Type: "bearer"},
			Hosts: []string{"api.stripe.com"},
		}
		_, cfgJSON, _, _, err := resolveAuth(req)
		if err != nil {
			t.Fatal(err)
		}
		if string(cfgJSON) != "{}" {
			t.Errorf("want empty cfg {}, got %s", string(cfgJSON))
		}
	})

	t.Run("custom auth emits headers map in config", func(t *testing.T) {
		req := createSecretRequest{
			Name:  "internal-prod",
			Value: "v",
			Auth:  &authConfigRequest{Type: "custom", Headers: map[string]string{"X-Api-Key": "Bearer {{ value }}"}},
			Hosts: []string{"api.internal"},
		}
		_, cfgJSON, _, _, err := resolveAuth(req)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		_ = json.Unmarshal(cfgJSON, &cfg)
		headers, ok := cfg["headers"].(map[string]any)
		if !ok || headers["X-Api-Key"] != "Bearer {{ value }}" {
			t.Errorf("want headers map preserved, got %v", cfg)
		}
	})

	t.Run("mutual exclusion: provider + auth rejected", func(t *testing.T) {
		req := createSecretRequest{
			Name:     "x",
			Value:    "v",
			Provider: "anthropic",
			Auth:     &authConfigRequest{Type: "bearer"},
		}
		_, _, _, _, err := resolveAuth(req)
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("want mutually exclusive error, got %v", err)
		}
	})

	t.Run("mutual exclusion: provider + hosts rejected", func(t *testing.T) {
		req := createSecretRequest{
			Name:     "x",
			Value:    "v",
			Provider: "anthropic",
			Hosts:    []string{"api.anthropic.com"},
		}
		_, _, _, _, err := resolveAuth(req)
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("want mutually exclusive error, got %v", err)
		}
	})

	t.Run("neither provider nor auth rejected", func(t *testing.T) {
		req := createSecretRequest{Name: "x", Value: "v"}
		_, _, _, _, err := resolveAuth(req)
		if err == nil || !strings.Contains(err.Error(), "must specify") {
			t.Errorf("want must-specify error, got %v", err)
		}
	})

	t.Run("unknown provider lists known ones", func(t *testing.T) {
		req := createSecretRequest{Name: "x", Value: "v", Provider: "datadog"}
		_, _, _, _, err := resolveAuth(req)
		if err == nil {
			t.Fatal("want error")
		}
		msg := err.Error()
		for _, p := range knownProviders() {
			if !strings.Contains(msg, p) {
				t.Errorf("error should mention %q, got %q", p, msg)
			}
		}
	})
}

func TestValidateSecretsRefs(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]string
		wantErr string
	}{
		{"empty allowed", nil, ""},
		{"single binding", map[string]string{"ANTHROPIC_API_KEY": "anthropic-prod"}, ""},
		{"too many bindings",
			repeatStrMap("KEY%d", "name", envVarsMaxKeys+1),
			"max is"},
		{"invalid env var key (digit start)", map[string]string{"1KEY": "anthropic-prod"}, "is not a valid env-var name"},
		{"invalid env var key (hyphen)", map[string]string{"MY-KEY": "anthropic-prod"}, "is not a valid env-var name"},
		{"valid env var key with underscore", map[string]string{"_KEY": "anthropic-prod"}, ""},
		{"invalid secret name", map[string]string{"KEY": "1invalid"}, "must start with"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSecretsRefs(tc.input)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("want no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func repeatStrMap(keyFmt, val string, n int) map[string]string {
	out := make(map[string]string, n)
	for i := 0; i < n; i++ {
		out[strings.ReplaceAll(keyFmt, "%d", itoa(i))] = val
	}
	return out
}

func TestProviderShortcutsAllValid(t *testing.T) {
	for name, sc := range providerShortcuts {
		t.Run(name, func(t *testing.T) {
			if sc.AuthType == "" {
				t.Fatal("AuthType empty")
			}
			if len(sc.Hosts) == 0 {
				t.Fatal("Hosts empty")
			}
			hosts := append([]string(nil), sc.Hosts...)
			if err := validateHosts(hosts); err != nil {
				t.Fatalf("Hosts fail validation: %v", err)
			}
			req := createSecretRequest{Name: "x", Value: "v", Provider: name}
			authType, _, gotHosts, shortcut, err := resolveAuth(req)
			if err != nil {
				t.Fatalf("resolveAuth: %v", err)
			}
			if authType != sc.AuthType {
				t.Errorf("auth_type drift: want %q got %q", sc.AuthType, authType)
			}
			if len(gotHosts) != len(sc.Hosts) {
				t.Errorf("hosts drift: want %v got %v", sc.Hosts, gotHosts)
			}
			if shortcut == nil || *shortcut != name {
				t.Errorf("shortcut name drift: want %q got %v", name, shortcut)
			}
		})
	}
}

func TestMintProxyTokenMatchesProviderSpec(t *testing.T) {
	alnumRE := regexp.MustCompile(`^[A-Za-z0-9]+$`)
	b64urlRE := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	for name, sc := range providerShortcuts {
		t.Run(name, func(t *testing.T) {
			n := name
			tok, err := mintProxyToken(&n)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(tok, sc.Token.Prefix) {
				t.Errorf("token %q missing prefix %q", tok, sc.Token.Prefix)
			}
			body := strings.TrimPrefix(tok, sc.Token.Prefix)
			if len(body) != sc.Token.BodyLen {
				t.Errorf("body length: want %d, got %d (%q)", sc.Token.BodyLen, len(body), body)
			}
			switch sc.Token.Alphabet {
			case "alnum":
				if !alnumRE.MatchString(body) {
					t.Errorf("alnum body must be [A-Za-z0-9]+, got %q", body)
				}
			case "b64url":
				if !b64urlRE.MatchString(body) {
					t.Errorf("b64url body must be [A-Za-z0-9_-]+, got %q", body)
				}
			default:
				t.Errorf("unknown alphabet %q in catalog", sc.Token.Alphabet)
			}
		})
	}
}

// TestMintProxyTokenPassesUpstreamStrictRegex pins minted tokens to upstream key formats.
func TestMintProxyTokenPassesUpstreamStrictRegex(t *testing.T) {
	cases := []struct {
		provider string
		regex    string
	}{
		{"github", `^ghp_[a-zA-Z0-9]{36}$`},
		{"anthropic", `^sk-ant-api03-[A-Za-z0-9]{48}$`},
		{"stripe", `^sk_test_[A-Za-z0-9]+$`},
		{"linear", `^lin_api_[A-Za-z0-9]+$`},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			re := regexp.MustCompile(tc.regex)
			p := tc.provider
			tok, err := mintProxyToken(&p)
			if err != nil {
				t.Fatal(err)
			}
			if !re.MatchString(tok) {
				t.Errorf("minted token %q does not match upstream regex %s", tok, tc.regex)
			}
		})
	}
}

func TestMintProxyTokenFallsBackToDefaultSpec(t *testing.T) {
	tok, err := mintProxyToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, defaultTokenSpec.Prefix) {
		t.Errorf("token %q missing default prefix %q", tok, defaultTokenSpec.Prefix)
	}
	body := strings.TrimPrefix(tok, defaultTokenSpec.Prefix)
	if len(body) != defaultTokenSpec.BodyLen {
		t.Errorf("default body length: want %d, got %d", defaultTokenSpec.BodyLen, len(body))
	}
}

func TestMintProxyTokenUniqueness(t *testing.T) {
	name := "anthropic"
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		tok, err := mintProxyToken(&name)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token after %d mints — CSPRNG broken", i)
		}
		seen[tok] = struct{}{}
	}
}

func TestRandomFromAlnumDistribution(t *testing.T) {
	// Every alphabet character should appear in a 10k sample.
	const samples = 10000
	s, err := randomFromAlnum(samples)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[byte]int, 62)
	for i := 0; i < len(s); i++ {
		seen[s[i]]++
	}
	if len(seen) != 62 {
		t.Errorf("expected all 62 alnum characters across %d samples, got %d distinct", samples, len(seen))
	}
}

func TestMergeEnvVarsWithSecrets(t *testing.T) {
	envVars := map[string]string{"MODE": "prod", "PORT": "8080"}
	meta := []SecretBindingMeta{
		{EnvKey: "ANTHROPIC_API_KEY", ProxyToken: "sk-ant-proxy-aaa"},
		{EnvKey: "GITHUB_TOKEN", ProxyToken: "ghp_proxy_bbb"},
	}
	out := mergeEnvVarsWithSecrets(envVars, meta)

	if out["MODE"] != "prod" {
		t.Errorf("env_var overlay should preserve customer values, got %v", out)
	}
	if out["ANTHROPIC_API_KEY"] != "sk-ant-proxy-aaa" {
		t.Errorf("proxy token missing: %v", out)
	}
	if out["GITHUB_TOKEN"] != "ghp_proxy_bbb" {
		t.Errorf("proxy token missing: %v", out)
	}
	if _, ok := envVars["ANTHROPIC_API_KEY"]; ok {
		t.Error("input map was mutated; need a fresh map")
	}
}

func TestMergeEnvVarsWithSecretsNoBindingsIsCheap(t *testing.T) {
	envVars := map[string]string{"MODE": "prod"}
	out := mergeEnvVarsWithSecrets(envVars, nil)
	if out["MODE"] != "prod" {
		t.Errorf("env_vars passthrough broken")
	}
}

func TestKnownProvidersStable(t *testing.T) {
	want := []string{"anthropic", "asana", "cloudflare", "exa", "firecrawl", "gemini", "github", "gitlab", "linear", "notion", "openai", "openrouter", "perplexity", "resend", "sentry", "slack", "stripe", "vercel", "xai"}
	got := knownProviders()
	if len(got) != len(want) {
		t.Fatalf("provider count drift: want %d (%v), got %d (%v)", len(want), want, len(got), got)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("provider list drift at [%d]: want %q, got %q (full got=%v)", i, p, got[i], got)
		}
	}
}

func TestValidatePerHostRulesRejectsOverlap(t *testing.T) {
	rules := []perHostRule{
		{Hosts: []string{"api.github.com"}, Type: "bearer"},
		{Hosts: []string{"api.github.com"}, Type: "basic"},
	}
	err := validatePerHostRules(rules, []string{"api.github.com"})
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("want overlap error, got %v", err)
	}
}

func TestValidatePerHostRulesRejectsHostOutsideAllowlist(t *testing.T) {
	rules := []perHostRule{
		{Hosts: []string{"github.com"}, Type: "basic", Username: "x-access-token"},
	}
	err := validatePerHostRules(rules, []string{"api.github.com"})
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("want reachability error, got %v", err)
	}
}

func TestValidatePerHostRulesRejectsWildcardExactOverlap(t *testing.T) {
	// "*.example.com" and "api.example.com" both match api.example.com — ambiguous.
	rules := []perHostRule{
		{Hosts: []string{"*.example.com"}, Type: "bearer"},
		{Hosts: []string{"api.example.com"}, Type: "basic"},
	}
	err := validatePerHostRules(rules, []string{"*.example.com", "api.example.com"})
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("want overlap error, got %v", err)
	}
}

func TestValidatePerHostRulesRejectsNestedWildcardOverlap(t *testing.T) {
	// "*.example.com" covers everything "*.foo.example.com" covers — overlap.
	rules := []perHostRule{
		{Hosts: []string{"*.example.com"}, Type: "bearer"},
		{Hosts: []string{"*.foo.example.com"}, Type: "basic"},
	}
	err := validatePerHostRules(rules, []string{"*.example.com", "*.foo.example.com"})
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("want overlap error, got %v", err)
	}
}

func TestValidatePerHostRulesAllowsWildcardCoverageOfExactRuleHost(t *testing.T) {
	// Top-level "*.example.com" should make "api.example.com" reachable.
	rules := []perHostRule{
		{Hosts: []string{"api.example.com"}, Type: "bearer"},
	}
	err := validatePerHostRules(rules, []string{"*.example.com"})
	if err != nil {
		t.Errorf("wildcard allowlist should cover exact rule host: %v", err)
	}
}

func TestValidatePerHostRulesAllowsNonOverlappingWildcards(t *testing.T) {
	// Two wildcards on disjoint domains must not be flagged as overlapping.
	rules := []perHostRule{
		{Hosts: []string{"*.example.com"}, Type: "bearer"},
		{Hosts: []string{"*.other.com"}, Type: "basic"},
	}
	err := validatePerHostRules(rules, []string{"*.example.com", "*.other.com"})
	if err != nil {
		t.Errorf("disjoint wildcards must not overlap: %v", err)
	}
}

func TestPatternCovers(t *testing.T) {
	cases := []struct {
		outer, inner string
		want         bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "other.example.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false}, // wildcard excludes bare
		{"*.example.com", "api.foo.example.com", true},
		{"*.example.com", "*.foo.example.com", true},
		{"*.foo.example.com", "*.example.com", false}, // narrow doesn't cover wide
		{"*.com", "*.example.com", true},
		{"api.example.com", "*.example.com", false}, // exact doesn't cover wildcard
	}
	for _, c := range cases {
		if got := patternCovers(c.outer, c.inner); got != c.want {
			t.Errorf("patternCovers(%q, %q) = %v, want %v", c.outer, c.inner, got, c.want)
		}
	}
}

func TestPatternsOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "other.example.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "*.example.com", true},
		{"*.example.com", "*.foo.example.com", true}, // narrower nested inside wider
		{"*.example.com", "*.other.com", false},
		{"*.com", "*.example.com", true},
	}
	for _, c := range cases {
		if got := patternsOverlap(c.a, c.b); got != c.want {
			t.Errorf("patternsOverlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestValidatePerHostRulesPropagatesPerTypeValidation(t *testing.T) {
	rules := []perHostRule{
		{Hosts: []string{"api.example.com"}, Type: "api-key"}, // missing header
	}
	err := validatePerHostRules(rules, []string{"api.example.com"})
	if err == nil || !strings.Contains(err.Error(), "header is required") {
		t.Errorf("want missing-header error, got %v", err)
	}
}

func TestValidateAuthConfigRejectsMixingLegacyAndPerHost(t *testing.T) {
	auth := &authConfigRequest{
		Type:    "bearer",
		PerHost: []perHostRule{{Hosts: []string{"api.example.com"}, Type: "bearer"}},
	}
	err := validateAuthConfig(auth)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("want mutual-exclusion error, got %v", err)
	}
}

func TestResolveAuthEmitsPerHostShape(t *testing.T) {
	// Explicit per-host secret → auth_type=per_host, auth_config carries the rules.
	req := createSecretRequest{
		Name: "gh", Value: "github_pat_xxx",
		Auth: &authConfigRequest{
			PerHost: []perHostRule{
				{Hosts: []string{"api.github.com"}, Type: "bearer"},
				{Hosts: []string{"github.com"}, Type: "basic", Username: "x-access-token"},
			},
		},
		Hosts: []string{"api.github.com", "github.com"},
	}
	authType, authConfig, hosts, shortcut, err := resolveAuth(req)
	if err != nil {
		t.Fatalf("resolveAuth: %v", err)
	}
	if authType != authTypePerHost {
		t.Errorf("auth_type: want per_host, got %q", authType)
	}
	if shortcut != nil {
		t.Errorf("shortcut should be nil for explicit auth")
	}
	if len(hosts) != 2 {
		t.Errorf("hosts: want 2, got %v", hosts)
	}
	var cfg map[string]any
	if err := json.Unmarshal(authConfig, &cfg); err != nil {
		t.Fatalf("auth_config JSON: %v", err)
	}
	list, ok := cfg["per_host"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("per_host shape drift: %v", cfg)
	}
}

func TestGitHubProviderShortcutEmitsPerHost(t *testing.T) {
	// github now emits per-host config so a single PAT covers both api.github.com
	// (Bearer) and github.com (Basic with x-access-token).
	req := createSecretRequest{Name: "gh", Value: "github_pat_xxx", Provider: "github"}
	authType, authConfig, _, shortcut, err := resolveAuth(req)
	if err != nil {
		t.Fatalf("resolveAuth: %v", err)
	}
	if authType != authTypePerHost {
		t.Errorf("github should emit per_host auth_type, got %q", authType)
	}
	if shortcut == nil || *shortcut != "github" {
		t.Errorf("shortcut metadata lost: %v", shortcut)
	}
	var cfg map[string]any
	if err := json.Unmarshal(authConfig, &cfg); err != nil {
		t.Fatalf("auth_config JSON: %v", err)
	}
	list, _ := cfg["per_host"].([]any)
	if len(list) != 2 {
		t.Fatalf("github should have 2 rules, got %d", len(list))
	}
	// Verify rule 0 is bearer for api.github.com.
	r0 := list[0].(map[string]any)
	if r0["type"] != "bearer" {
		t.Errorf("rule 0 type: %v", r0["type"])
	}
	// Verify rule 1 is basic with x-access-token username for github.com.
	r1 := list[1].(map[string]any)
	if r1["type"] != "basic" || r1["username"] != "x-access-token" {
		t.Errorf("rule 1 shape: %v", r1)
	}
}

func TestPerHostRulesFromConfig(t *testing.T) {
	// Round-trip a per_host jsonb config through the JWT-claim translator.
	cfg := map[string]any{
		"per_host": []any{
			map[string]any{
				"hosts": []any{"api.github.com"},
				"type":  "bearer",
			},
			map[string]any{
				"hosts":    []any{"github.com"},
				"type":     "basic",
				"username": "x-access-token",
			},
		},
	}
	rules, err := perHostRulesFromConfig(cfg)
	if err != nil {
		t.Fatalf("perHostRulesFromConfig: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rule count: %d", len(rules))
	}
	if rules[0].AuthType != "bearer" || rules[0].Hosts[0] != "api.github.com" {
		t.Errorf("rule 0 drift: %+v", rules[0])
	}
	if rules[1].AuthType != "basic" || rules[1].Username != "x-access-token" {
		t.Errorf("rule 1 drift: %+v", rules[1])
	}
}

func TestRejectOverbroadWildcardOnPublicSuffix(t *testing.T) {
	cases := []struct {
		host      string
		wantError bool
	}{
		{"api.example.com", false},
		{"*.example.com", false},
		{"*.example.co.uk", false},
		{"*.bbc.co.uk", false},
		{"*.com", true},            // public suffix
		{"*.co.uk", true},          // multi-label public suffix
		{"*.io", true},             // public suffix
		{"*.us", true},             // public suffix
		{"*.example.local", false}, // private TLD not in PSL
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			err := rejectOverbroadWildcard(c.host)
			if (err != nil) != c.wantError {
				t.Errorf("rejectOverbroadWildcard(%q) = %v, wantError=%v", c.host, err, c.wantError)
			}
		})
	}
}

func TestParseStatusFilter(t *testing.T) {
	cases := []struct {
		in            string
		wantMin       int32
		wantMax       int32
		wantErrSubstr string
	}{
		{"", 0, 9999, ""},
		{"2xx", 200, 299, ""},
		{"3xx", 300, 399, ""},
		{"4xx", 400, 499, ""},
		{"5xx", 500, 599, ""},
		{"errors", 400, 9999, ""},
		{"bogus", 0, 0, "status must be one of"},
		{"200", 0, 0, "status must be one of"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			min, max, err := parseStatusFilter(c.in)
			if c.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if min != c.wantMin || max != c.wantMax {
					t.Errorf("got (%d, %d), want (%d, %d)", min, max, c.wantMin, c.wantMax)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErrSubstr) {
				t.Errorf("want err containing %q, got %v", c.wantErrSubstr, err)
			}
		})
	}
}

func TestListProvidersReturnsCatalog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	r := gin.New()
	r.GET("/providers", h.ListProviders)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/providers", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status: %d", w.Code)
	}
	var got []providerResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(providerShortcuts) {
		t.Fatalf("provider count: got %d, want %d", len(got), len(providerShortcuts))
	}
	wantNames := knownProviders()
	for i, p := range got {
		if p.Name != wantNames[i] {
			t.Errorf("order drift at [%d]: got %q want %q", i, p.Name, wantNames[i])
		}
		if p.Display == "" {
			t.Errorf("display empty for %q", p.Name)
		}
		if p.TokenShape == "" {
			t.Errorf("token_shape empty for %q", p.Name)
		}
	}
}

func TestProviderShortcutsHaveDisplayNames(t *testing.T) {
	for name, p := range providerShortcuts {
		if p.Display == "" {
			t.Errorf("provider %q missing Display field", name)
		}
	}
}

// resolveSecretBindingsForCreate now fetches all referenced secrets in one
// batched query. This exercises the mapping, de-duplication of shared names,
// and the not-found error.
func TestResolveSecretBindingsForCreate_Batches(t *testing.T) {
	teamID := uuid.New()
	shortcut := "anthropic"
	secA := db.Secret{ID: uuid.New(), TeamID: teamID, Name: "anthropic-key", AuthType: "bearer", ProviderShortcut: &shortcut}
	secB := db.Secret{ID: uuid.New(), TeamID: teamID, Name: "openai-key", AuthType: "bearer"}
	byName := map[string]db.Secret{secA.Name: secA, secB.Name: secB}

	var queryCount int
	mock := &mockDBTX{
		queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
			if !strings.Contains(sql, "GetSecretsByNames") {
				t.Fatalf("unexpected query: %s", sql)
			}
			queryCount++
			names := args[1].([]string)
			rows := make([]func(dest ...any) error, 0, len(names))
			for _, n := range names {
				if s, ok := byName[n]; ok {
					rows = append(rows, secretRow(s).scanFn)
				}
			}
			return &scanRows{rows: rows}, nil
		},
	}
	h := &Handlers{DB: db.New(mock)}

	t.Run("distinct secrets, one query", func(t *testing.T) {
		queryCount = 0
		bindings, meta, appErr := h.resolveSecretBindingsForCreate(context.Background(), teamID, map[string]string{
			"ANTHROPIC_API_KEY": "anthropic-key",
			"OPENAI_API_KEY":    "openai-key",
		})
		if appErr != nil {
			t.Fatalf("unexpected error: %+v", appErr)
		}
		if queryCount != 1 {
			t.Fatalf("expected 1 batched query, got %d", queryCount)
		}
		if len(bindings) != 2 || len(meta) != 2 {
			t.Fatalf("expected 2 bindings/meta, got %d/%d", len(bindings), len(meta))
		}
	})

	t.Run("shared name de-duplicated", func(t *testing.T) {
		queryCount = 0
		bindings, _, appErr := h.resolveSecretBindingsForCreate(context.Background(), teamID, map[string]string{
			"KEY_ONE": "anthropic-key",
			"KEY_TWO": "anthropic-key",
		})
		if appErr != nil {
			t.Fatalf("unexpected error: %+v", appErr)
		}
		if len(bindings) != 2 {
			t.Fatalf("both env keys must bind, got %d", len(bindings))
		}
		if bindings[0].SecretID != secA.ID || bindings[1].SecretID != secA.ID {
			t.Fatalf("both bindings must reference the shared secret")
		}
	})

	t.Run("missing secret is a 400", func(t *testing.T) {
		_, _, appErr := h.resolveSecretBindingsForCreate(context.Background(), teamID, map[string]string{
			"GHOST": "does-not-exist",
		})
		if appErr == nil || appErr.Code != "secret_not_found" {
			t.Fatalf("expected secret_not_found, got %+v", appErr)
		}
	})
}
