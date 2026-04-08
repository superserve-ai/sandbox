package api

import (
	"context"
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

func fileTokenRequest(sandboxID string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/file-token", nil)
}

func TestIssueFileToken_Success(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	signer, verifier := newTestSigner(t)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return sandboxRow(db.Sandbox{
				ID:     sandboxID,
				TeamID: teamID,
				Name:   "files-test",
				Status: db.SandboxStatusActive,
			})
		},
	}

	h := &Handlers{
		DB:     db.New(mock),
		Signer: signer,
		Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"},
	}

	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, fileTokenRequest(sandboxID.String()))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	body := parseJSON(t, w)
	tok, _ := body["token"].(string)
	url, _ := body["url"].(string)
	if tok == "" || url == "" {
		t.Fatalf("missing token/url in response: %v", body)
	}

	// The edge-proxy URL must be the bare /files base for this sandbox:
	// https over the boxd port, the sandbox ID as the host label prefix,
	// no query string. Callers append ?path=... and attach the token
	// themselves.
	if !strings.HasPrefix(url, "https://boxd-"+sandboxID.String()+".") {
		t.Errorf("url must start with https://boxd-<sandboxID>., got %q", url)
	}
	if !strings.HasSuffix(url, "/files") {
		t.Errorf("url must end at /files (no query string), got %q", url)
	}
	if strings.Contains(url, "?") {
		t.Errorf("url must not contain query params (token leak risk): %s", url)
	}

	// expires_at must be present and in the future — if the handler
	// forgets to set it, it would serialize as the zero time.
	expires, _ := body["expires_at"].(string)
	if expires == "" {
		t.Error("missing expires_at")
	}

	// Round-trip the token through the verifier to confirm it's
	// well-formed, has scope=files, and is bound to this sandbox+team.
	p, err := verifier.Verify(tok, time.Now(), auth.ScopeFiles)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if p.SandboxID != sandboxID.String() {
		t.Errorf("token sandbox_id = %q, want %q", p.SandboxID, sandboxID)
	}
	if p.TeamID != teamID.String() {
		t.Errorf("token team_id = %q, want %q", p.TeamID, teamID)
	}
	if p.Scope != auth.ScopeFiles {
		t.Errorf("token scope = %q, want %q", p.Scope, auth.ScopeFiles)
	}
}

// TestIssueFileToken_WrongScopeRejected proves that a minted files token
// cannot stand in for a terminal token (or vice versa). The scopes are
// namespaces, and the verifier must reject a scope mismatch even if
// everything else about the token is valid.
func TestIssueFileToken_WrongScopeRejected(t *testing.T) {
	teamID := uuid.New()
	sandboxID := uuid.New()

	signer, verifier := newTestSigner(t)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return sandboxRow(db.Sandbox{
				ID: sandboxID, TeamID: teamID, Name: "x",
				Status: db.SandboxStatusActive,
			})
		},
	}
	h := &Handlers{
		DB:     db.New(mock),
		Signer: signer,
		Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"},
	}

	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, fileTokenRequest(sandboxID.String()))

	tok, _ := parseJSON(t, w)["token"].(string)
	if _, err := verifier.Verify(tok, time.Now(), auth.ScopeTerminal); err == nil {
		t.Fatal("files token verified under ScopeTerminal — scope gate is broken")
	}
}

func TestIssueFileToken_IdleSandboxRejected(t *testing.T) {
	// Idle sandboxes must be rejected: the data-plane bridge has no
	// auto-wake, so a files token against a dormant VM would be unusable.
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
	h := &Handlers{
		DB:     db.New(mock),
		Signer: signer,
		Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"},
	}

	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, fileTokenRequest(sandboxID.String()))

	if w.Code != http.StatusConflict {
		t.Errorf("idle sandbox should be 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIssueFileToken_TransientStateRejected(t *testing.T) {
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
			h := &Handlers{
				DB:     db.New(mock),
				Signer: signer,
				Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"},
			}

			w := httptest.NewRecorder()
			setupTestRouter(h, teamID.String()).ServeHTTP(w, fileTokenRequest(sandboxID.String()))

			if w.Code != http.StatusConflict {
				t.Errorf("status %s: got %d, want 409", status, w.Code)
			}
		})
	}
}

func TestIssueFileToken_NotFound(t *testing.T) {
	signer, _ := newTestSigner(t)
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
	}
	h := &Handlers{
		DB:     db.New(mock),
		Signer: signer,
		Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"},
	}

	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, fileTokenRequest(uuid.New().String()))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestIssueFileToken_NoTeam(t *testing.T) {
	signer, _ := newTestSigner(t)
	h := &Handlers{
		DB:     db.New(&mockDBTX{}),
		Signer: signer,
		Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"},
	}

	w := httptest.NewRecorder()
	setupTestRouter(h, "").ServeHTTP(w, fileTokenRequest(uuid.New().String()))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestIssueFileToken_BadSandboxID(t *testing.T) {
	signer, _ := newTestSigner(t)
	h := &Handlers{
		DB:     db.New(&mockDBTX{}),
		Signer: signer,
		Config: &config.Config{EdgeProxyDomain: "sandbox.superserve.ai"},
	}

	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w, fileTokenRequest("not-a-uuid"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
