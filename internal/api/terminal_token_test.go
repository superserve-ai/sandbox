package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// newTestSigner creates a Handlers with a fresh signing keypair and returns
// the matching verifier so tests can decode the issued token end-to-end.
func newTestSigner(t *testing.T) (*auth.Signer, *auth.Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return auth.NewSigner(priv), auth.NewVerifier(pub)
}

func tokenRequest(sandboxID string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/terminal-token", nil)
}

func TestIssueTerminalToken_Success(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	signer, verifier := newTestSigner(t)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return sandboxRow(db.Sandbox{
				ID:     sandboxID,
				TeamID: teamID,
				Name:   "term-test",
				Status: db.SandboxStatusActive,
			})
		},
	}

	h := &Handlers{
		DB:           db.New(mock),
		Signer:       signer,
		Config:       &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"},
	}

	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, tokenRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	body := parseJSON(t, w)
	tok, _ := body["token"].(string)
	url, _ := body["url"].(string)
	if tok == "" || url == "" {
		t.Fatalf("missing token/url in response: %v", body)
	}
	if !strings.Contains(url, sandboxID.String()) {
		t.Errorf("url does not contain sandbox id: %s", url)
	}
	if !strings.HasPrefix(url, "wss://") {
		t.Errorf("url should be wss://: %s", url)
	}
	if !strings.HasSuffix(url, "/terminal") {
		t.Errorf("url should end at /terminal (no query params): %s", url)
	}
	if strings.Contains(url, "?") {
		t.Errorf("url must not contain query params (token leak risk): %s", url)
	}
	subprotocol, _ := body["subprotocol"].(string)
	if subprotocol != TerminalSubprotocol {
		t.Errorf("subprotocol = %q, want %q", subprotocol, TerminalSubprotocol)
	}

	// Round-trip the token through the verifier to confirm it's well-formed
	// and bound to the right sandbox/team.
	p, err := verifier.Verify(tok, time.Now(), auth.ScopeTerminal)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if p.SandboxID != sandboxID.String() {
		t.Errorf("token sandbox_id = %q, want %q", p.SandboxID, sandboxID)
	}
	if p.TeamID != teamID.String() {
		t.Errorf("token team_id = %q, want %q", p.TeamID, teamID)
	}
}

func TestIssueTerminalToken_IdleSandboxRejected(t *testing.T) {
	// Idle sandboxes must be rejected — the bridge does not auto-wake,
	// so issuing a token would mint an unusable capability. Caller must
	// resume the sandbox first.
	teamID := uuid.New()
	sandboxID := uuid.New()
	signer, _ := newTestSigner(t)

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return sandboxRow(db.Sandbox{
				ID: sandboxID, TeamID: teamID, Name: "idle-box",
				Status: db.SandboxStatusIdle,
			})
		},
	}
	h := &Handlers{DB: db.New(mock), Signer:       signer, Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"}}

	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, tokenRequest(sandboxID.String()))

	if w.Code != http.StatusConflict {
		t.Errorf("idle sandbox should be rejected with 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIssueTerminalToken_TransientStateRejected(t *testing.T) {
	// Transient states (starting, pausing) and terminal states (failed,
	// deleted) must be rejected — no point handing out a terminal token
	// against a sandbox the bridge can't actually attach to.
	cases := []db.SandboxStatus{
		db.SandboxStatusStarting,
		db.SandboxStatusPausing,
		db.SandboxStatusFailed,
		db.SandboxStatusDeleted,
	}
	for _, status := range cases {
		t.Run(string(status), func(t *testing.T) {
			teamID := uuid.New()
			sandboxID := uuid.New()
			signer, _ := newTestSigner(t)
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
					return sandboxRow(db.Sandbox{
						ID: sandboxID, TeamID: teamID, Name: "x",
						Status: status,
					})
				},
			}
			h := &Handlers{DB: db.New(mock), Signer:       signer, Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"}}

			w := httptest.NewRecorder()
			setupTestRouter(h, teamID.String()).ServeHTTP(w, tokenRequest(sandboxID.String()))

			if w.Code != http.StatusConflict {
				t.Errorf("status %s: got %d, want 409", status, w.Code)
			}
		})
	}
}

func TestIssueTerminalToken_NotFound(t *testing.T) {
	signer, _ := newTestSigner(t)
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
	}
	h := &Handlers{DB: db.New(mock), Signer:       signer, Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"}}

	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, tokenRequest(uuid.New().String()))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestIssueTerminalToken_NoTeam(t *testing.T) {
	signer, _ := newTestSigner(t)
	h := &Handlers{DB: db.New(&mockDBTX{}), Signer:       signer, Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"}}

	w := httptest.NewRecorder()
	setupTestRouter(h, "").ServeHTTP(w, tokenRequest(uuid.New().String()))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestIssueTerminalToken_BadSandboxID(t *testing.T) {
	signer, _ := newTestSigner(t)
	h := &Handlers{DB: db.New(&mockDBTX{}), Signer:       signer, Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"}}

	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, tokenRequest("not-a-uuid"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
