package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
)

// The real grpcVMDClient wraps RPC errors with fmt.Errorf("gRPC …: %w", err);
// handlers must classify through the wrapping, so the stubs return wrapped
// errors too.
func grpcNotFound(msg string) error {
	return fmt.Errorf("gRPC UpdateSandboxPreviewPolicy: %w", status.Error(codes.NotFound, msg))
}

func grpcUnavailable(msg string) error {
	return fmt.Errorf("gRPC UpdateSandboxPreviewPolicy: %w", status.Error(codes.Unavailable, msg))
}

var previewTestSeed = []byte("test-seed-for-hmac-32-bytes-min!!")

type previewHandlerEnv struct {
	sandboxID uuid.UUID
	teamID    uuid.UUID
	sb        db.Sandbox
	vmd       *stubVMD
	handlers  *Handlers
	router    *gin.Engine
}

// newPreviewHandlerEnv wires a Handlers instance whose DB serves one sandbox
// row (preview_access=private, version 1 unless the test mutates env.sb
// before requests run) and whose bump query returns version+1.
func newPreviewHandlerEnv(t *testing.T) *previewHandlerEnv {
	t.Helper()
	env := &previewHandlerEnv{
		sandboxID: uuid.New(),
		teamID:    uuid.New(),
		vmd:       &stubVMD{},
	}
	env.sb = db.Sandbox{
		ID:                  env.sandboxID,
		TeamID:              env.teamID,
		Name:                "preview-sb",
		Status:              db.SandboxStatusActive,
		HostID:              "host-1",
		PreviewAccess:       auth.PreviewAccessPrivate,
		PreviewTokenVersion: 1,
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "preview_token_version + 1"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int32) = env.sb.PreviewTokenVersion + 1
					return nil
				}}
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(env.sb)
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	env.handlers = &Handlers{
		VMD:    env.vmd,
		DB:     db.New(mock),
		Config: &config.Config{SandboxAccessTokenSeed: previewTestSeed},
	}

	gin.SetMode(gin.TestMode)
	env.router = gin.New()
	env.router.Use(func(c *gin.Context) {
		c.Set("team_id", env.teamID.String())
		c.Next()
	})
	env.router.POST("/sandboxes/:sandbox_id/preview-token", env.handlers.MintSandboxPreviewToken)
	env.router.POST("/sandboxes/:sandbox_id/preview-token/rotate", env.handlers.RotateSandboxPreviewToken)
	env.router.PATCH("/sandboxes/:sandbox_id", env.handlers.PatchSandbox)
	return env
}

func (e *previewHandlerEnv) do(method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func TestMintPreviewToken_DefaultSandboxWide(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	w := env.do(http.MethodPost, "/sandboxes/"+env.sandboxID.String()+"/preview-token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := parseJSON(t, w)

	if body["header"] != auth.PreviewTokenHeader {
		t.Errorf("header = %v, want %v", body["header"], auth.PreviewTokenHeader)
	}
	if body["query_param"] != auth.PreviewTokenQueryParam {
		t.Errorf("query_param = %v, want %v", body["query_param"], auth.PreviewTokenQueryParam)
	}
	if body["preview_access"] != auth.PreviewAccessPrivate {
		t.Errorf("preview_access = %v, want private", body["preview_access"])
	}
	if _, present := body["expires_at"]; present {
		t.Error("expires_at present on a non-expiring token")
	}

	tok, _ := body["token"].(string)
	// The minted token must verify for any port at the row's version...
	if !auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 1, 3000, tok) {
		t.Error("minted token does not verify for port 3000 at version 1")
	}
	if !auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 1, 8080, tok) {
		t.Error("minted token is unexpectedly port-scoped")
	}
	// ...and die on rotation.
	if auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 2, 3000, tok) {
		t.Error("minted token still verifies after a version bump")
	}
}

func TestMintPreviewToken_PortScopedWithExpiry(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	w := env.do(http.MethodPost, "/sandboxes/"+env.sandboxID.String()+"/preview-token",
		`{"port": 3000, "expires_in_seconds": 3600}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := parseJSON(t, w)

	expiresAt, _ := body["expires_at"].(string)
	parsed, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Fatalf("expires_at %q is not RFC3339: %v", expiresAt, err)
	}
	if until := time.Until(parsed); until < 55*time.Minute || until > 65*time.Minute {
		t.Errorf("expires_at %v is not ~1h out", parsed)
	}

	tok, _ := body["token"].(string)
	if !auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 1, 3000, tok) {
		t.Error("token does not verify on its own port")
	}
	if auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 1, 8080, tok) {
		t.Error("port-scoped token verifies on a different port")
	}
}

func TestMintPreviewToken_Validation(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	base := "/sandboxes/" + env.sandboxID.String() + "/preview-token"
	cases := map[string]string{
		"privileged port": `{"port": 80}`,
		"port too big":    `{"port": 70000}`,
		"expiry too long": `{"expires_in_seconds": 999999999}`,
		"negative expiry": `{"expires_in_seconds": -1}`,
		"unknown field":   `{"prot": 3000}`,
	}
	for name, body := range cases {
		if w := env.do(http.MethodPost, base, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body: %s", name, w.Code, w.Body.String())
		}
	}
}

func TestMintPreviewToken_SeedMissing500(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.handlers.Config = &config.Config{}
	w := env.do(http.MethodPost, "/sandboxes/"+env.sandboxID.String()+"/preview-token", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestRotatePreviewToken_BumpsAndPushes(t *testing.T) {
	env := newPreviewHandlerEnv(t)

	var pushedAccess string
	var pushedVersion int64
	env.vmd.updatePreviewFn = func(_ context.Context, id, access string, version int64) error {
		if id != env.sandboxID.String() {
			t.Errorf("vmd push id = %q, want %q", id, env.sandboxID)
		}
		pushedAccess, pushedVersion = access, version
		return nil
	}

	w := env.do(http.MethodPost, "/sandboxes/"+env.sandboxID.String()+"/preview-token/rotate", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if pushedAccess != auth.PreviewAccessPrivate || pushedVersion != 2 {
		t.Errorf("vmd push = (%q, %d), want (private, 2)", pushedAccess, pushedVersion)
	}

	body := parseJSON(t, w)
	if v, _ := body["preview_token_version"].(float64); int(v) != 2 {
		t.Errorf("preview_token_version = %v, want 2", body["preview_token_version"])
	}
	tok, _ := body["token"].(string)
	if !auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 2, 3000, tok) {
		t.Error("rotated token does not verify at the new version")
	}
	if auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 1, 3000, tok) {
		t.Error("rotated token verifies at the old version")
	}
}

func TestRotatePreviewToken_VMDHardErrorIs500(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.vmd.updatePreviewFn = func(context.Context, string, string, int64) error {
		return grpcUnavailable("vmd down")
	}
	w := env.do(http.MethodPost, "/sandboxes/"+env.sandboxID.String()+"/preview-token/rotate", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the host push fails", w.Code)
	}
}

func TestRotatePreviewToken_VMDNotFoundIsOK(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.vmd.updatePreviewFn = func(context.Context, string, string, int64) error {
		return grpcNotFound("no record on host")
	}
	w := env.do(http.MethodPost, "/sandboxes/"+env.sandboxID.String()+"/preview-token/rotate", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (NotFound means next restore seeds the version)", w.Code)
	}
}

func TestPatchSandbox_PreviewAccess(t *testing.T) {
	env := newPreviewHandlerEnv(t)

	var pushedAccess string
	var pushedVersion int64
	env.vmd.updatePreviewFn = func(_ context.Context, id, access string, version int64) error {
		pushedAccess, pushedVersion = access, version
		return nil
	}

	w := env.do(http.MethodPatch, "/sandboxes/"+env.sandboxID.String(), `{"preview_access": "public"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if pushedAccess != auth.PreviewAccessPublic || pushedVersion != 1 {
		t.Errorf("vmd push = (%q, %d), want (public, 1)", pushedAccess, pushedVersion)
	}
}

func TestPatchSandbox_PreviewAccessInvalidValue(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	w := env.do(http.MethodPatch, "/sandboxes/"+env.sandboxID.String(), `{"preview_access": "friends-only"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestPatchSandbox_PreviewAccessVMDHardErrorIs500(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.vmd.updatePreviewFn = func(context.Context, string, string, int64) error {
		return grpcUnavailable("vmd down")
	}
	w := env.do(http.MethodPatch, "/sandboxes/"+env.sandboxID.String(), `{"preview_access": "private"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — a policy the host can't enforce must not report success", w.Code)
	}
}

func TestPatchSandbox_PreviewAccessVMDNotFoundSucceeds(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.vmd.updatePreviewFn = func(context.Context, string, string, int64) error {
		return grpcNotFound("no record on host")
	}
	w := env.do(http.MethodPatch, "/sandboxes/"+env.sandboxID.String(), `{"preview_access": "private"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (no host record — applies on next restore)", w.Code)
	}
}
