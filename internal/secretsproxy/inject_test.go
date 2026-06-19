package secretsproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// stubVault returns canned values keyed by secret id. Caller's teamID must
// equal stubVault.teamID (empty defaults to "team-1") or fetch is revoked.
type stubVault struct {
	teamID string
	values map[string]string
	err    error
	calls  int
}

func (s *stubVault) FetchCredential(_ context.Context, teamID, secretID string) (string, error) {
	s.calls++
	if s.err != nil {
		return "", s.err
	}
	want := s.teamID
	if want == "" {
		want = "team-1"
	}
	if teamID != want {
		return "", ErrCredentialRevoked
	}
	v, ok := s.values[secretID]
	if !ok {
		return "", ErrCredentialRevoked
	}
	return v, nil
}

func newReq(method, host string, headers map[string]string) *http.Request {
	r, _ := http.NewRequest(method, "https://"+host+"/v1/things", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func sandboxWithBindings(bindings map[string]Binding) *Scope {
	if bindings == nil {
		bindings = map[string]Binding{}
	}
	return &Scope{
		SandboxID: "sb-1",
		TeamID:    "team-1",
		SourceIP:  "10.0.0.1",
		Bindings:  bindings,
	}
}

func TestHostAllowedByEgress(t *testing.T) {
	rules := func(allow, deny []string, policy string) EgressRules {
		return EgressRules{Allow: allow, Deny: deny, UnmatchedHostPolicy: policy}
	}
	t.Run("passthrough default when no rules", func(t *testing.T) {
		if ok, _ := hostAllowedByEgress("api.openai.com", nil, rules(nil, nil, "passthrough")); !ok {
			t.Error("want allow on empty rules + passthrough policy")
		}
	})
	t.Run("deny policy + no rules blocks all", func(t *testing.T) {
		ok, reason := hostAllowedByEgress("api.openai.com", nil, rules(nil, nil, "deny"))
		if ok {
			t.Error("want deny under default-deny policy")
		}
		if reason != "unmatched_host_denied" {
			t.Errorf("reason = %q, want unmatched_host_denied", reason)
		}
	})
	t.Run("allow short-circuits before deny", func(t *testing.T) {
		if ok, _ := hostAllowedByEgress("api.openai.com", nil, rules([]string{"api.openai.com"}, []string{"0.0.0.0/0"}, "passthrough")); !ok {
			t.Error("allow match should win even with a broad deny configured")
		}
	})
	t.Run("non-allow falls through to implicit-deny", func(t *testing.T) {
		ok, reason := hostAllowedByEgress("evil.com", nil, rules([]string{"api.openai.com"}, nil, "passthrough"))
		if ok {
			t.Error("want implicit-deny when allow list non-empty and no match")
		}
		if reason != "host_not_allowed" {
			t.Errorf("reason = %q, want host_not_allowed", reason)
		}
	})
	t.Run("wildcard host matches", func(t *testing.T) {
		if ok, _ := hostAllowedByEgress("api.openai.com", nil, rules([]string{"*.openai.com"}, nil, "passthrough")); !ok {
			t.Error("wildcard should match subdomain")
		}
		if ok, _ := hostAllowedByEgress("other.com", nil, rules([]string{"*.openai.com"}, nil, "passthrough")); ok {
			t.Error("wildcard should not match unrelated host")
		}
	})
}

func TestBearerInjectionEndToEnd(t *testing.T) {
	binding := Binding{
		SecretID:   "sec-anthropic",
		EnvKey:     "ANTHROPIC_API_KEY",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.anthropic.com"},
	}
	st := sandboxWithBindings(map[string]Binding{"proxy-tok-anth": binding})
	vault := &stubVault{values: map[string]string{"sec-anthropic": "sk-ant-REAL-KEY"}}

	req := newReq("POST", "api.anthropic.com", map[string]string{
		"Authorization": "Bearer proxy-tok-anth",
		"User-Agent":    "agent/1.0",
	})

	out, err := injectRequest(context.Background(), st, vault, req, "api.anthropic.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Fatalf("want allow, got %+v", out)
	}
	if len(out.MatchedSecretIDs) != 1 || out.MatchedSecretIDs[0] != "sec-anthropic" {
		t.Errorf("secret_id not captured for audit: %+v", out)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-ant-REAL-KEY" {
		t.Errorf("Authorization not swapped: got %q", got)
	}
	if req.Header.Get("User-Agent") != "agent/1.0" {
		t.Errorf("unrelated headers should pass through")
	}
}

func TestInjectionRefusesRevokedProxyToken(t *testing.T) {
	binding := Binding{
		SecretID:   "sec-anthropic",
		EnvKey:     "ANTHROPIC_API_KEY",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.anthropic.com"},
	}
	st := sandboxWithBindings(map[string]Binding{"proxy-tok-anth": binding})
	vault := &stubVault{values: map[string]string{"sec-anthropic": "sk-ant-REAL-KEY"}}

	req := newReq("POST", "api.anthropic.com", map[string]string{
		"Authorization": "Bearer proxy-tok-anth",
	})

	revoked := func(tok string) bool { return tok == "proxy-tok-anth" }
	out, err := injectRequest(context.Background(), st, vault, req, "api.anthropic.com", nil, EgressRules{}, revoked)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != revokedAction {
		t.Fatalf("want revoked, got %+v", out)
	}
	if out.Reason != "proxy_token_revoked" {
		t.Errorf("reason = %q, want proxy_token_revoked", out.Reason)
	}
	// The stand-in token must NOT be swapped for the real credential.
	if got := req.Header.Get("Authorization"); got != "Bearer proxy-tok-anth" {
		t.Errorf("revoked request must not be swapped: got %q", got)
	}
}

func TestBasicInjectionMatchesPasswordAndPreservesUser(t *testing.T) {
	// Daemon matches on the password portion only and preserves the user.
	binding := Binding{
		SecretID:   "sec-jira",
		AuthType:   "basic",
		AuthConfig: map[string]any{},
		Hosts:      []string{"yoursite.atlassian.net"},
	}
	proxyToken := "ssrv_proxy_jira_aaa"
	st := sandboxWithBindings(map[string]Binding{proxyToken: binding})
	vault := &stubVault{values: map[string]string{"sec-jira": "real-jira-pat"}}

	clientAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user@example.com:"+proxyToken))
	req := newReq("GET", "yoursite.atlassian.net", map[string]string{
		"Authorization": clientAuth,
	})

	out, err := injectRequest(context.Background(), st, vault, req, "yoursite.atlassian.net", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Fatalf("want allow, got %+v", out)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user@example.com:real-jira-pat"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("basic injection mangled headers: want %q, got %q", want, got)
	}
}

func TestBasicMatchRejectsWrongPassword(t *testing.T) {
	binding := Binding{
		SecretID: "sec-jira", AuthType: "basic",
		AuthConfig: map[string]any{}, Hosts: []string{"api.example.com"},
	}
	st := sandboxWithBindings(map[string]Binding{"correct-tok": binding})
	vault := &stubVault{values: map[string]string{"sec-jira": "x"}}

	// Different password must not match.
	wrong := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:other-tok"))
	req := newReq("GET", "api.example.com", map[string]string{"Authorization": wrong})

	out, err := injectRequest(context.Background(), st, vault, req, "api.example.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Errorf("want allow (passthrough — no matching binding), got %+v", out)
	}
	if got := req.Header.Get("Authorization"); got != wrong {
		t.Errorf("passthrough should not mutate Authorization, got %q", got)
	}
}

func TestBasicInjectionFallsBackToXUserWhenAgentSendsNoUser(t *testing.T) {
	// Empty-user input substitutes "x" so the upstream doesn't reject the request.
	binding := Binding{
		SecretID: "sec-x", AuthType: "basic",
		AuthConfig: map[string]any{}, Hosts: []string{"api.example.com"},
	}
	tok := "proxy-aaa"
	st := sandboxWithBindings(map[string]Binding{tok: binding})
	vault := &stubVault{values: map[string]string{"sec-x": "real-pw"}}

	emptyUser := "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+tok))
	req := newReq("GET", "api.example.com", map[string]string{"Authorization": emptyUser})
	out, err := injectRequest(context.Background(), st, vault, req, "api.example.com", nil, EgressRules{}, nil)
	if err != nil || out.Action != "allow" {
		t.Fatalf("want allow, got %+v err=%v", out, err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x:real-pw"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("basic empty-user fallback: want %q, got %q", want, got)
	}
}

func TestDecodeBasicAuthEdgeCases(t *testing.T) {
	cases := []struct {
		name   string
		header string
		ok     bool
		user   string
		pw     string
	}{
		{"not basic", "Bearer xyz", false, "", ""},
		{"empty after Basic", "Basic ", false, "", ""},
		{"malformed base64", "Basic !@#$", false, "", ""},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), false, "", ""},
		{"happy", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p")), true, "u", "p"},
		{"colon in password", "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p:more")), true, "u", "p:more"},
		{"raw-url base64", "Basic " + base64.RawURLEncoding.EncodeToString([]byte("u:p")), true, "u", "p"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, p, ok := decodeBasicAuth(tc.header)
			if ok != tc.ok || u != tc.user || p != tc.pw {
				t.Errorf("want (%q,%q,%v), got (%q,%q,%v)", tc.user, tc.pw, tc.ok, u, p, ok)
			}
		})
	}
}

func TestAPIKeyInjectionUsesConfiguredHeader(t *testing.T) {
	binding := Binding{
		SecretID:   "sec-anthropic",
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "x-api-key"},
		Hosts:      []string{"api.anthropic.com"},
	}
	st := sandboxWithBindings(map[string]Binding{"sk-ant-proxy-aaa": binding})
	vault := &stubVault{values: map[string]string{"sec-anthropic": "sk-ant-REAL"}}

	req := newReq("POST", "api.anthropic.com", map[string]string{
		"x-api-key": "sk-ant-proxy-aaa",
	})
	out, err := injectRequest(context.Background(), st, vault, req, "api.anthropic.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Fatalf("want allow, got %+v", out)
	}
	if got := req.Header.Get("x-api-key"); got != "sk-ant-REAL" {
		t.Errorf("api-key swap: want sk-ant-REAL, got %q", got)
	}
}

func TestAPIKeyInjectionWithPrefix(t *testing.T) {
	binding := Binding{
		SecretID:   "sec-x",
		AuthType:   "api-key",
		AuthConfig: map[string]any{"header": "Authorization", "prefix": "ApiKey "},
		Hosts:      []string{"api.example.com"},
	}
	st := sandboxWithBindings(map[string]Binding{"prox-tok": binding})
	vault := &stubVault{values: map[string]string{"sec-x": "REAL"}}

	req := newReq("GET", "api.example.com", map[string]string{"Authorization": "ApiKey prox-tok"})
	out, err := injectRequest(context.Background(), st, vault, req, "api.example.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Fatalf("want allow, got %+v", out)
	}
	if got := req.Header.Get("Authorization"); got != "ApiKey REAL" {
		t.Errorf("api-key prefix swap: want %q, got %q", "ApiKey REAL", got)
	}
}

func TestCustomInjectionSetsMultipleHeaders(t *testing.T) {
	binding := Binding{
		SecretID: "sec-acme",
		AuthType: "custom",
		AuthConfig: map[string]any{
			"headers": map[string]string{
				"X-Api-Key":   "Bearer {{ value }}",
				"X-Tenant-Id": "static-tenant-123",
			},
		},
		Hosts: []string{"api.acme.internal"},
	}
	st := sandboxWithBindings(map[string]Binding{"proxy-acme": binding})
	vault := &stubVault{values: map[string]string{"sec-acme": "REAL-ACME"}}

	req := newReq("POST", "api.acme.internal", map[string]string{
		"X-Api-Key": "Bearer proxy-acme",
	})
	out, err := injectRequest(context.Background(), st, vault, req, "api.acme.internal", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Fatalf("want allow, got %+v", out)
	}
	if got := req.Header.Get("X-Api-Key"); got != "Bearer REAL-ACME" {
		t.Errorf("X-Api-Key not swapped: %q", got)
	}
	if got := req.Header.Get("X-Tenant-Id"); got != "static-tenant-123" {
		t.Errorf("static header not set: %q", got)
	}
}

func TestStripThenSetStripsClientPlantedHeader(t *testing.T) {
	// A second Authorization value planted by the client must be stripped.
	binding := Binding{
		SecretID:   "sec-openai",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.openai.com"},
	}
	st := sandboxWithBindings(map[string]Binding{"proxy-openai-aaa": binding})
	vault := &stubVault{values: map[string]string{"sec-openai": "sk-REAL"}}

	req := newReq("POST", "api.openai.com", map[string]string{
		"Authorization": "Bearer proxy-openai-aaa",
	})
	req.Header.Add("Authorization", "Bearer planted-evil-key")

	out, err := injectRequest(context.Background(), st, vault, req, "api.openai.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Fatalf("want allow, got %+v", out)
	}
	values := req.Header.Values("Authorization")
	if len(values) != 1 {
		t.Fatalf("want exactly one Authorization value after strip-then-set, got %d (%v)", len(values), values)
	}
	if values[0] != "Bearer sk-REAL" {
		t.Errorf("Authorization value: want %q, got %q", "Bearer sk-REAL", values[0])
	}
}

func TestCustomTemplateRejectsCRLFInResolvedValue(t *testing.T) {
	// CRLF in the resolved value must fail rather than smuggle a header line.
	binding := Binding{
		SecretID:   "sec-bad",
		AuthType:   "custom",
		AuthConfig: map[string]any{"headers": map[string]string{"X-Token": "Bearer {{ value }}"}},
		Hosts:      []string{"api.bad.example"},
	}
	st := sandboxWithBindings(map[string]Binding{"proxy-bad": binding})
	vault := &stubVault{values: map[string]string{"sec-bad": "innocent\r\nX-Evil: planted"}}

	req := newReq("GET", "api.bad.example", map[string]string{"X-Token": "Bearer proxy-bad"})
	_, err := injectRequest(context.Background(), st, vault, req, "api.bad.example", nil, EgressRules{}, nil)
	if err == nil {
		t.Fatal("want CRLF-guard error")
	}
}

func TestNoMatchingBindingFallsThroughToPassthrough(t *testing.T) {
	st := sandboxWithBindings(nil) // no bindings
	vault := &stubVault{}

	req := newReq("GET", "api.openai.com", map[string]string{
		"Authorization": "Bearer client-managed-key",
	})
	out, err := injectRequest(context.Background(), st, vault, req, "api.openai.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "allow" {
		t.Errorf("want allow on passthrough, got %+v", out)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer client-managed-key" {
		t.Errorf("passthrough should not mutate Authorization, got %q", got)
	}
}

func TestCredentialHostMismatchDenied(t *testing.T) {
	binding := Binding{
		SecretID:   "sec-openai",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.openai.com"}, // only openai
	}
	st := sandboxWithBindings(map[string]Binding{"proxy-openai-aaa": binding})
	vault := &stubVault{values: map[string]string{"sec-openai": "sk-REAL"}}

	req := newReq("POST", "evil.example.com", map[string]string{
		"Authorization": "Bearer proxy-openai-aaa",
	})
	out, err := injectRequest(context.Background(), st, vault, req, "evil.example.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "deny" {
		t.Errorf("want deny on credential/host mismatch, got %+v", out)
	}
	if out.Reason != "credential_host_mismatch" {
		t.Errorf("reason = %q, want credential_host_mismatch", out.Reason)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer proxy-openai-aaa" {
		t.Errorf("Authorization should be untouched on deny, got %q", got)
	}
}

func TestRevokedCredentialSurfacesAsRevoked(t *testing.T) {
	binding := Binding{
		SecretID:   "sec-revoked",
		AuthType:   "bearer",
		AuthConfig: map[string]any{},
		Hosts:      []string{"api.example.com"},
	}
	st := sandboxWithBindings(map[string]Binding{"proxy-tok": binding})
	vault := &stubVault{err: ErrCredentialRevoked}

	req := newReq("GET", "api.example.com", map[string]string{"Authorization": "Bearer proxy-tok"})
	out, err := injectRequest(context.Background(), st, vault, req, "api.example.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "revoked" {
		t.Errorf("want revoked action, got %+v", out)
	}
	if len(out.MatchedSecretIDs) != 1 || out.MatchedSecretIDs[0] != "sec-revoked" {
		t.Errorf("want secret id in outcome, got %+v", out)
	}
}

// fakeClock returns a deterministic time.Time; Advance crosses TTL boundaries without sleep.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newCachedVaultWithClock(upstream VaultClient, ttl time.Duration, clock *fakeClock) *cachedVault {
	cv := NewCachedVault(upstream, VaultCacheOptions{
		TTL:      ttl,
		IdleTTL:  time.Hour,
		Capacity: 256,
	})
	cv.now = clock.Now
	return cv
}

// TestCachedVaultIsTeamScoped: same secretID under a different teamID must not hit the cache.
func TestCachedVaultIsTeamScoped(t *testing.T) {
	upstream := &stubVault{teamID: "team-A", values: map[string]string{"s": "secret-A"}}
	cv := newCachedVaultWithClock(upstream, time.Hour, newFakeClock())

	// Prime cache as team-A.
	v, err := cv.FetchCredential(context.Background(), "team-A", "s")
	if err != nil || v != "secret-A" {
		t.Fatalf("team-A fetch: v=%q err=%v", v, err)
	}

	// Same secretID from team-B must NOT hit the team-A entry.
	_, err = cv.FetchCredential(context.Background(), "team-B", "s")
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("team-B fetch must be revoked, got err=%v", err)
	}
}

func TestCachedVaultServesFromCache(t *testing.T) {
	upstream := &stubVault{values: map[string]string{"s": "v1"}}
	cv := newCachedVaultWithClock(upstream, 10*time.Second, newFakeClock())

	v, err := cv.FetchCredential(context.Background(), "team-1", "s")
	if err != nil || v != "v1" {
		t.Fatalf("first fetch: v=%q err=%v", v, err)
	}
	// Mutate the upstream — the cache should still return the original.
	upstream.values["s"] = "v2"
	v, err = cv.FetchCredential(context.Background(), "team-1", "s")
	if err != nil || v != "v1" {
		t.Fatalf("cached fetch: v=%q err=%v", v, err)
	}
}

func TestCachedVaultRefreshesAfterTTL(t *testing.T) {
	clock := newFakeClock()
	upstream := &stubVault{values: map[string]string{"s": "v1"}}
	cv := newCachedVaultWithClock(upstream, 10*time.Second, clock)

	_, _ = cv.FetchCredential(context.Background(), "team-1", "s")
	upstream.values["s"] = "v2"
	clock.advance(11 * time.Second) // past TTL
	v, err := cv.FetchCredential(context.Background(), "team-1", "s")
	if err != nil || v != "v2" {
		t.Errorf("after TTL: want v2, got v=%q err=%v", v, err)
	}
}

func TestCachedVaultInvalidate(t *testing.T) {
	clock := newFakeClock()
	upstream := &stubVault{values: map[string]string{"s": "v1"}}
	cv := newCachedVaultWithClock(upstream, time.Hour, clock)

	_, _ = cv.FetchCredential(context.Background(), "team-1", "s")
	upstream.values["s"] = "v2"
	cv.Invalidate("s") // forces a refetch on next access regardless of TTL
	v, _ := cv.FetchCredential(context.Background(), "team-1", "s")
	if v != "v2" {
		t.Errorf("Invalidate should force refetch, got %q", v)
	}
}

func TestCachedVaultPropagatesError(t *testing.T) {
	cv := newCachedVaultWithClock(&stubVault{err: errors.New("boom")}, time.Second, newFakeClock())
	_, err := cv.FetchCredential(context.Background(), "team-1", "s")
	if err == nil || err.Error() != "boom" {
		t.Errorf("want boom error, got %v", err)
	}
}

// githubPerHostBinding mirrors what the JWT resolver builds for a github
// provider-shortcut secret.
func githubPerHostBinding(secretID string) Binding {
	return Binding{
		SecretID: secretID,
		EnvKey:   "GITHUB_TOKEN",
		Hosts:    []string{"api.github.com", "github.com"},
		Rules: []BindingRule{
			{Hosts: []string{"api.github.com"}, AuthType: "bearer"},
			{Hosts: []string{"github.com"}, AuthType: "basic", AuthConfig: map[string]any{"username": "x-access-token"}},
		},
	}
}

func TestPerHostDispatchPicksBearerForRESTHost(t *testing.T) {
	// api.github.com → Bearer rule wins, swap into Authorization header verbatim.
	proxyTok := "ghp_proxy_token_aaaa"
	st := sandboxWithBindings(map[string]Binding{proxyTok: githubPerHostBinding("sec-gh")})
	vault := &stubVault{values: map[string]string{"sec-gh": "github_pat_REAL"}}

	req := newReq("GET", "api.github.com", map[string]string{
		"Authorization": "Bearer " + proxyTok,
	})
	out, err := injectRequest(context.Background(), st, vault, req, "api.github.com", nil, EgressRules{}, nil)
	if err != nil || out.Action != "allow" {
		t.Fatalf("want allow, got %+v err=%v", out, err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer github_pat_REAL" {
		t.Errorf("Bearer rule should swap header verbatim, got %q", got)
	}
}

func TestPerHostDispatchPicksBasicForGitHost(t *testing.T) {
	// github.com → Basic rule wins, with username forced to x-access-token
	// regardless of what the client sent.
	proxyTok := "ghp_proxy_token_bbbb"
	st := sandboxWithBindings(map[string]Binding{proxyTok: githubPerHostBinding("sec-gh")})
	vault := &stubVault{values: map[string]string{"sec-gh": "github_pat_REAL"}}

	// git over HTTPS sends username=x-access-token and password=<PAT>.
	inbound := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+proxyTok))
	req := newReq("GET", "github.com", map[string]string{"Authorization": inbound})

	out, err := injectRequest(context.Background(), st, vault, req, "github.com", nil, EgressRules{}, nil)
	if err != nil || out.Action != "allow" {
		t.Fatalf("want allow, got %+v err=%v", out, err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:github_pat_REAL"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Basic rule with username override: want %q, got %q", want, got)
	}
}

func TestPerHostBasicUsernameOverridesInbound(t *testing.T) {
	// Even if the agent sent a different Basic username, the rule's username
	// is authoritative — prevents an agent from picking a wrong username that
	// the upstream silently rejects.
	binding := Binding{
		SecretID: "sec-x", Hosts: []string{"git.example.com"},
		Rules: []BindingRule{
			{Hosts: []string{"git.example.com"}, AuthType: "basic", AuthConfig: map[string]any{"username": "forced-user"}},
		},
	}
	tok := "proxy-xyz"
	st := sandboxWithBindings(map[string]Binding{tok: binding})
	vault := &stubVault{values: map[string]string{"sec-x": "REAL"}}

	inbound := "Basic " + base64.StdEncoding.EncodeToString([]byte("agent-picked:"+tok))
	req := newReq("GET", "git.example.com", map[string]string{"Authorization": inbound})
	out, err := injectRequest(context.Background(), st, vault, req, "git.example.com", nil, EgressRules{}, nil)
	if err != nil || out.Action != "allow" {
		t.Fatalf("want allow, got %+v err=%v", out, err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("forced-user:REAL"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("rule username should override inbound: want %q got %q", want, got)
	}
}

func TestPerHostNoMatchingRuleDeniesAsHostMismatch(t *testing.T) {
	// Binding's allowlist reaches the host (so the egress check passes), but
	// none of the per-host rules cover it — fail closed.
	binding := Binding{
		SecretID: "sec-x",
		// allowlist explicitly includes both hosts so egress passes the first
		// hostMatchesCredential check; per-host rules are stricter.
		Hosts: []string{"api.github.com", "github.com", "raw.githubusercontent.com"},
		Rules: []BindingRule{
			{Hosts: []string{"api.github.com"}, AuthType: "bearer"},
			{Hosts: []string{"github.com"}, AuthType: "basic", AuthConfig: map[string]any{"username": "x-access-token"}},
		},
	}
	tok := "ghp_proxy_token_cccc"
	st := sandboxWithBindings(map[string]Binding{tok: binding})
	vault := &stubVault{values: map[string]string{"sec-x": "REAL"}}

	req := newReq("GET", "raw.githubusercontent.com", map[string]string{
		"Authorization": "Bearer " + tok,
	})
	out, err := injectRequest(context.Background(), st, vault, req, "raw.githubusercontent.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "deny" || out.Reason != "credential_host_mismatch" {
		t.Errorf("want credential_host_mismatch, got %+v", out)
	}
	// Strip-then-set invariant: a denied request still has its original header.
	if got := req.Header.Get("Authorization"); got != "Bearer "+tok {
		t.Errorf("denied request should not have its header swapped, got %q", got)
	}
}

func TestPerHostScannerMatchesBasicShapeOnRuleBindings(t *testing.T) {
	// A binding with no top-level AuthType (multi-rule) must still match
	// requests in any of the rule shapes.
	binding := githubPerHostBinding("sec-gh")
	binding.AuthType = "" // multi-rule bindings carry no top-level type
	tok := "ghp_proxy_token_dddd"
	st := sandboxWithBindings(map[string]Binding{tok: binding})
	vault := &stubVault{values: map[string]string{"sec-gh": "github_pat_REAL"}}

	bearReq := newReq("GET", "api.github.com", map[string]string{"Authorization": "Bearer " + tok})
	if out, _ := injectRequest(context.Background(), st, vault, bearReq, "api.github.com", nil, EgressRules{}, nil); out.Action != "allow" {
		t.Errorf("bearer-shaped request must match bearer rule, got %+v", out)
	}

	basicHdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok))
	basicReq := newReq("GET", "github.com", map[string]string{"Authorization": basicHdr})
	if out, _ := injectRequest(context.Background(), st, vault, basicReq, "github.com", nil, EgressRules{}, nil); out.Action != "allow" {
		t.Errorf("basic-shaped request must match basic rule, got %+v", out)
	}
}

func TestDispatchAuthShapeLegacySingleRule(t *testing.T) {
	// Legacy single-rule bindings (no Rules) keep working unchanged.
	b := Binding{AuthType: "bearer", AuthConfig: nil, Hosts: []string{"api.example.com"}}
	authType, cfg, ok := dispatchAuthShape(b, "api.example.com")
	if !ok || authType != "bearer" || cfg != nil {
		t.Errorf("legacy dispatch: got (%q, %v, %v), want (bearer, nil, true)", authType, cfg, ok)
	}
}

func TestMultiBindingSwapsAllMatchedHeaders(t *testing.T) {
	// When a request carries proxy tokens for multiple bindings, every one
	// of them must be swapped — not just the first match.
	bA := Binding{
		SecretID: "sec-A", AuthType: "custom",
		AuthConfig: map[string]any{"headers": map[string]string{"X-Header-A": "{{ value }}"}},
		Hosts:      []string{"api.example.com"},
	}
	bB := Binding{
		SecretID: "sec-B", AuthType: "custom",
		AuthConfig: map[string]any{"headers": map[string]string{"X-Header-B": "{{ value }}"}},
		Hosts:      []string{"api.example.com"},
	}
	tokA := "proxy-tok-A"
	tokB := "proxy-tok-B"
	st := sandboxWithBindings(map[string]Binding{tokA: bA, tokB: bB})
	vault := &stubVault{values: map[string]string{
		"sec-A": "REAL-VALUE-A",
		"sec-B": "REAL-VALUE-B",
	}}

	req := newReq("GET", "api.example.com", map[string]string{
		"X-Header-A": tokA,
		"X-Header-B": tokB,
	})
	out, err := injectRequest(context.Background(), st, vault, req, "api.example.com", nil, EgressRules{}, nil)
	if err != nil || out.Action != "allow" {
		t.Fatalf("want allow, got %+v err=%v", out, err)
	}
	if got := req.Header.Get("X-Header-A"); got != "REAL-VALUE-A" {
		t.Errorf("X-Header-A: want REAL-VALUE-A, got %q", got)
	}
	if got := req.Header.Get("X-Header-B"); got != "REAL-VALUE-B" {
		t.Errorf("X-Header-B: want REAL-VALUE-B, got %q (binding B's swap was skipped)", got)
	}
	if len(out.MatchedSecretIDs) != 2 {
		t.Errorf("want 2 matched secret IDs for audit, got %v", out.MatchedSecretIDs)
	}
}

func TestMultiBindingDeterministicOrder(t *testing.T) {
	// Outcome ordering must be deterministic across runs even though
	// scope.Bindings is a Go map (which iterates in randomized order).
	bA := Binding{SecretID: "sec-A", AuthType: "bearer", Hosts: []string{"api.example.com"}}
	bB := Binding{SecretID: "sec-B", AuthType: "custom",
		AuthConfig: map[string]any{"headers": map[string]string{"X-B": "{{ value }}"}},
		Hosts:      []string{"api.example.com"},
	}
	st := sandboxWithBindings(map[string]Binding{
		"proxy-A": bA, "proxy-B": bB,
	})
	vault := &stubVault{values: map[string]string{"sec-A": "RA", "sec-B": "RB"}}

	for i := 0; i < 20; i++ {
		req := newReq("GET", "api.example.com", map[string]string{
			"Authorization": "Bearer proxy-A",
			"X-B":           "proxy-B",
		})
		out, _ := injectRequest(context.Background(), st, vault, req, "api.example.com", nil, EgressRules{}, nil)
		if len(out.MatchedSecretIDs) != 2 ||
			out.MatchedSecretIDs[0] != "sec-A" || out.MatchedSecretIDs[1] != "sec-B" {
			t.Fatalf("iteration %d: matched IDs not sorted: %v", i, out.MatchedSecretIDs)
		}
	}
}

func TestMultiBindingRevocationAbortsRequest(t *testing.T) {
	// If any matched binding is revoked, the whole request must abort —
	// no partial swap leaving one header with a real value and another with
	// a (now meaningless) proxy token.
	bA := Binding{
		SecretID: "sec-OK", AuthType: "custom",
		AuthConfig: map[string]any{"headers": map[string]string{"X-A": "{{ value }}"}},
		Hosts:      []string{"api.example.com"},
	}
	bB := Binding{
		SecretID: "sec-REVOKED", AuthType: "custom",
		AuthConfig: map[string]any{"headers": map[string]string{"X-B": "{{ value }}"}},
		Hosts:      []string{"api.example.com"},
	}
	st := sandboxWithBindings(map[string]Binding{
		"proxy-A": bA, "proxy-B": bB,
	})
	// stubVault returns the OK value for sec-OK; sec-REVOKED isn't in the map.
	vault := &stubVault{values: map[string]string{"sec-OK": "REAL-OK"}}

	req := newReq("GET", "api.example.com", map[string]string{
		"X-A": "proxy-A",
		"X-B": "proxy-B",
	})
	out, err := injectRequest(context.Background(), st, vault, req, "api.example.com", nil, EgressRules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != "revoked" {
		t.Errorf("want revoked action, got %+v", out)
	}
	// X-A must not have been swapped — resolution failed before any apply.
	if got := req.Header.Get("X-A"); got != "proxy-A" {
		t.Errorf("X-A should be untouched on revocation; got %q", got)
	}
	if got := req.Header.Get("X-B"); got != "proxy-B" {
		t.Errorf("X-B should be untouched on revocation; got %q", got)
	}
}

func TestCachedVaultEvictsLRUWhenCapacityReached(t *testing.T) {
	// Cache must bound its size: once capacity is reached, the least
	// recently used entry is evicted on insert. Without this, the cache
	// grows unbounded for sandboxes with many short-lived secrets.
	clock := &fakeClock{t: time.Now()}
	upstream := &stubVault{values: map[string]string{"a": "A", "b": "B", "c": "C"}}
	cv := NewCachedVault(upstream, VaultCacheOptions{
		TTL:      time.Hour,
		IdleTTL:  time.Hour,
		Capacity: 2,
	})
	cv.now = clock.Now

	for _, sid := range []string{"a", "b", "c"} {
		if _, err := cv.FetchCredential(context.Background(), "team-1", sid); err != nil {
			t.Fatal(err)
		}
	}

	if cv.order.Len() != 2 {
		t.Errorf("cache len = %d, want 2 (capacity bound)", cv.order.Len())
	}
	// "a" was the oldest insert; should be evicted.
	if _, ok := cv.entries[cacheKey{teamID: "team-1", secretID: "a"}]; ok {
		t.Error("expected oldest entry 'a' to be evicted")
	}
	if _, ok := cv.entries[cacheKey{teamID: "team-1", secretID: "c"}]; !ok {
		t.Error("newest entry 'c' must be present")
	}
}

func TestCachedVaultLRUOrderPromotedOnHit(t *testing.T) {
	// A cache hit must move the entry to the front of the LRU list,
	// otherwise frequently-accessed entries get evicted prematurely.
	clock := &fakeClock{t: time.Now()}
	upstream := &stubVault{values: map[string]string{"a": "A", "b": "B", "c": "C"}}
	cv := NewCachedVault(upstream, VaultCacheOptions{
		TTL: time.Hour, IdleTTL: time.Hour, Capacity: 2,
	})
	cv.now = clock.Now

	_, _ = cv.FetchCredential(context.Background(), "team-1", "a")
	_, _ = cv.FetchCredential(context.Background(), "team-1", "b")
	// Touch "a" — must move it to front.
	_, _ = cv.FetchCredential(context.Background(), "team-1", "a")
	// Insert "c" — now "b" should be the LRU victim, not "a".
	_, _ = cv.FetchCredential(context.Background(), "team-1", "c")

	if _, ok := cv.entries[cacheKey{teamID: "team-1", secretID: "a"}]; !ok {
		t.Error("touched 'a' was prematurely evicted")
	}
	if _, ok := cv.entries[cacheKey{teamID: "team-1", secretID: "b"}]; ok {
		t.Error("'b' should have been LRU-evicted in favor of touched 'a'")
	}
}

func TestCachedVaultIdleTTLEvictsStaleEntry(t *testing.T) {
	// An entry that hasn't been accessed in IdleTTL is dropped on the next
	// access attempt and re-fetched, bounding memory for never-revisited
	// entries even when capacity isn't reached.
	clock := &fakeClock{t: time.Now()}
	upstream := &stubVault{values: map[string]string{"a": "A"}}
	cv := NewCachedVault(upstream, VaultCacheOptions{
		TTL: time.Hour, IdleTTL: 5 * time.Minute, Capacity: 1024,
	})
	cv.now = clock.Now

	_, _ = cv.FetchCredential(context.Background(), "team-1", "a")
	if upstream.calls != 1 {
		t.Fatalf("upstream calls after first fetch: got %d, want 1", upstream.calls)
	}

	// Advance past idle TTL with no access.
	clock.advance(6 * time.Minute)
	_, _ = cv.FetchCredential(context.Background(), "team-1", "a")
	if upstream.calls != 2 {
		t.Errorf("idle-evicted entry should trigger a re-fetch, got %d upstream calls", upstream.calls)
	}
}
