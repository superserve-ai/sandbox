package steps

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/superserve-ai/sandbox/internal/qm/adminlink"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// How long the probes wait for a freshly routed tenant to answer. A new
// host rule takes a minute or two to reach every edge, and the container
// runs database migrations before anything listens, so the health check is
// the patient one; by the time the smoke test runs the stack is up and a
// failure there is a real failure, not a slow start.
const (
	defaultHealthTimeout = 10 * time.Minute
	defaultSmokeTimeout  = 2 * time.Minute
	defaultProbeInterval = 5 * time.Second
)

// healthCheck waits for the tenant to answer on its public URL through the
// load balancer. Read-only, so Rollback has nothing to do.
type healthCheck struct {
	c Clients
}

func (healthCheck) Name() string { return "health_check" }

func (s healthCheck) Ready(provisioner.Env) error { return nil }

func (s healthCheck) Run(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	base, err := probeBase(t)
	if err != nil {
		return err
	}
	// The container serves /healthz on its public port only once migrations
	// have run and core, web-ui and portal are all up, so a 200 here means
	// the whole stack is live — not merely that Cloud Run is routing.
	return waitFor(ctx, s.c, s.c.HealthTimeout, base+"/healthz", func(status int, _ string) error {
		if status == http.StatusOK {
			return nil
		}
		return fmt.Errorf("GET /healthz returned %d", status)
	})
}

func (healthCheck) Rollback(context.Context, *provisioner.Tenant) error {
	return provisioner.Skip("nothing to undo")
}

// smoke exercises the deployed stack end to end. Read-only.
//
// The sign-in check is the reason this step exists as something separate
// from the health check. A tenant whose auth broker has no email transport
// answers /healthz perfectly and 503s the first time anybody tries to sign
// in — which is exactly how the reference tenant shipped, unnoticed,
// because the signed admin link bypasses the broker. So the assertion here
// is on /idp/authorize specifically, and a 5xx from it fails the provision.
type smoke struct {
	c Clients
}

func (smoke) Name() string { return "smoke" }

func (s smoke) Ready(provisioner.Env) error { return nil }

func (s smoke) Run(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	base, err := probeBase(t)
	if err != nil {
		return err
	}
	if err := waitFor(ctx, s.c, s.c.SmokeTimeout, base+"/", func(status int, _ string) error {
		if status < 500 {
			return nil
		}
		return fmt.Errorf("GET / returned %d", status)
	}); err != nil {
		return err
	}
	target, err := authorizeURL(base)
	if err != nil {
		return err
	}
	return waitFor(ctx, s.c, s.c.SmokeTimeout, target, func(status int, body string) error {
		if status < 500 {
			return nil
		}
		// The broker renders its "email delivery isn't configured" page as
		// HTML, so the first line of it is worth carrying into the event:
		// it is the difference between "the tenant is still starting" and
		// "this tenant can never be signed into".
		if body != "" {
			return fmt.Errorf("sign-in fails closed: GET /idp/authorize returned %d — %s", status, body)
		}
		return fmt.Errorf("sign-in fails closed: GET /idp/authorize returned %d", status)
	})
}

func (smoke) Rollback(context.Context, *provisioner.Tenant) error {
	return provisioner.Skip("nothing to undo")
}

// authorizeURL is a well-formed authorization request: the broker rejects a
// malformed one with a 4xx, which would pass a "not 5xx" assertion without
// having exercised anything. The PKCE challenge is a throwaway — no code is
// ever exchanged — but it has to be present and correctly shaped.
func authorizeURL(base string) (string, error) {
	u, err := url.Parse(base + "/idp/authorize")
	if err != nil {
		return "", fmt.Errorf("build the sign-in probe url: %w", err)
	}
	state, err := randomHex(16)
	if err != nil {
		return "", err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return "", err
	}
	verifier := make([]byte, 32)
	if _, err := rand.Read(verifier); err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	// The client id and redirect URI the tenant's supervisor configures the
	// portal with; anything else is a 4xx from the broker.
	q.Set("client_id", "qm-portal")
	q.Set("redirect_uri", base+"/auth/callback")
	q.Set("scope", "openid email")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkceChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// pkceChallenge is the S256 code challenge for verifier: base64url of its
// SHA-256, unpadded.
func pkceChallenge(verifier []byte) string {
	sum := sha256.Sum256([]byte(base64.RawURLEncoding.EncodeToString(verifier)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// probeBase is the origin the probes address, from the row rather than
// derived: the tenant is not reachable until the cloud_run step recorded it.
func probeBase(t *provisioner.Tenant) (string, error) {
	if t.Row.PublicUrl == nil {
		return "", fmt.Errorf("the tenant has no public URL recorded")
	}
	return strings.TrimSuffix(*t.Row.PublicUrl, "/"), nil
}

// probeBodyLimit bounds how much of a failing response is read for the
// event message.
const probeBodyLimit = 2048

// waitFor polls target until check passes, timeout elapses, or ctx is done,
// and reports the last failure. Redirects are not followed: a 302 to the
// sign-in page is a perfectly good answer, and following it would test
// whatever it points at instead.
func waitFor(ctx context.Context, c Clients, timeout time.Duration, target string, check func(status int, body string) error) error {
	client, interval := c.HTTP, c.ProbeInterval
	if client == nil {
		client = defaultProbeClient()
	}
	if timeout <= 0 {
		timeout = defaultSmokeTimeout
	}
	if interval <= 0 {
		interval = defaultProbeInterval
	}
	deadline := time.Now().Add(timeout)
	var last error
	for {
		status, body, err := probe(ctx, client, target)
		switch {
		case err != nil:
			last = err
		default:
			if last = check(status, body); last == nil {
				return nil
			}
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w (last attempt: %v)", ctx.Err(), last)
		}
		if !time.Now().Add(interval).Before(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last attempt: %v)", ctx.Err(), last)
		case <-time.After(interval):
		}
	}
}

func probe(ctx context.Context, client *http.Client, target string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var body string
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, probeBodyLimit))
		body = summarize(string(raw))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, probeBodyLimit))
	return resp.StatusCode, body, nil
}

// summarize strips tags and collapses whitespace so an HTML error page
// reads as one line in the event log.
func summarize(body string) string {
	var b strings.Builder
	depth := 0
	for _, r := range body {
		switch {
		case r == '<':
			depth++
		case r == '>':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func defaultProbeClient() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// adminLink proves the tenant is ready for the console's admin sign-in:
// the portal session secret exists and a link can be minted against the
// public URL. The link itself is discarded, never recorded.
type adminLink struct {
	c Clients
}

func (adminLink) Name() string { return "admin_link" }

// Ready: minting a link needs the tenant's portal session secret, so this
// step needs a store in every mode.
func (s adminLink) Ready(provisioner.Env) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	return nil
}

func (s adminLink) Run(ctx context.Context, t *provisioner.Tenant) error {
	if s.c.Secrets == nil {
		return errNoSecretStore
	}
	if t.Row.PublicUrl == nil {
		return provisioner.Skip("no public URL recorded yet")
	}
	secret, err := s.c.Secrets.Get(ctx, t.SecretName(secrets.PortalSessionSecret))
	if err != nil {
		return err
	}
	jti, err := adminlink.NewJTI()
	if err != nil {
		return err
	}
	_, err = adminlink.Mint(*t.Row.PublicUrl, string(secret), t.Row.AdminEmail, timeNow(), jti)
	return err
}

func (adminLink) Rollback(context.Context, *provisioner.Tenant) error {
	return provisioner.Skip("nothing to undo")
}
