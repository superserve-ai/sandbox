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
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/auth"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

var previewTestSeed = []byte("test-seed-for-hmac-32-bytes-min!!")

// The real grpcVMDClient wraps RPC errors with fmt.Errorf("gRPC …: %w", err);
// handlers classify through the wrapping, so the stubs wrap too.
func grpcNotFound(msg string) error {
	return fmt.Errorf("gRPC UpdateSandboxPreviewPolicy: %w", status.Error(codes.NotFound, msg))
}

func grpcUnavailable(msg string) error {
	return fmt.Errorf("gRPC UpdateSandboxPreviewPolicy: %w", status.Error(codes.Unavailable, msg))
}

// portRows is a pgx.Rows over published-port rows for ListPublishedPorts.
type portRows struct {
	rows   [][2]int32 // {port, token_version}
	access string     // access column returned for every row
	i      int
}

func (r *portRows) Close()                                       {}
func (r *portRows) Err() error                                   { return nil }
func (r *portRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *portRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *portRows) Next() bool                                   { r.i++; return r.i <= len(r.rows) }
func (r *portRows) Values() ([]any, error)                       { return nil, nil }
func (r *portRows) RawValues() [][]byte                          { return nil }
func (r *portRows) Conn() *pgx.Conn                              { return nil }
func (r *portRows) Scan(dest ...any) error {
	row := r.rows[r.i-1]
	*dest[0].(*int32) = row[0]
	*dest[1].(*int32) = row[1]
	*dest[2].(*string) = r.access
	return nil
}

type previewHandlerEnv struct {
	sandboxID uuid.UUID
	teamID    uuid.UUID
	sb        db.Sandbox
	vmd       *stubVMD
	handlers  *Handlers
	router    *gin.Engine

	// Controllable query results (adjust before a request).
	getPortVersion   int32           // GetPublishedPort → this version; 0 => ErrNoRows
	publishToVersion int32           // PublishPort RETURNING token_version
	bumpToVersion    int32           // BumpPublishedPortVersion RETURNING token_version
	bumpNoRow        bool            // BumpPublishedPortVersion → ErrNoRows (unpublished)
	unpublishRows    int64           // rows affected by UnpublishPort
	policyRevision   int64           // BumpPreviewPolicyRevision → this revision
	listPorts        [][2]int32      // ListPublishedPorts rows (post-mutation state)
	listAccess       string          // access column for every listed/loaded port row
	disabledFlags    map[string]bool // feature_enabled(key) → !disabledFlags[key]
	hostCaps         []string        // host row capability advertisement
}

func newPreviewHandlerEnv(t *testing.T) *previewHandlerEnv {
	t.Helper()
	env := &previewHandlerEnv{
		sandboxID:        uuid.New(),
		teamID:           uuid.New(),
		vmd:              &stubVMD{},
		getPortVersion:   1,
		publishToVersion: 1,
		bumpToVersion:    2,
		unpublishRows:    1,
		policyRevision:   5,
		listPorts:        [][2]int32{{3000, 1}},
		listAccess:       auth.PreviewAccessPrivate,
		disabledFlags:    map[string]bool{},
		hostCaps:         []string{auth.HostCapabilityPreviewPorts, auth.HostCapabilityPreviewPortTokens},
	}
	env.sb = db.Sandbox{
		ID:            env.sandboxID,
		TeamID:        env.teamID,
		Name:          "preview-sb",
		Status:        db.SandboxStatusActive,
		HostID:        "host-1",
		PreviewAccess: auth.PreviewAccessPrivate,
	}

	portFromArgs := func(args []any) int32 {
		if len(args) >= 2 {
			if p, ok := args[1].(int32); ok {
				return p
			}
		}
		return 0
	}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "feature_enabled"):
				return &mockRow{scanFn: func(dest ...any) error {
					key, _ := args[0].(string)
					*dest[0].(*bool) = !env.disabledFlags[key]
					return nil
				}}
			case strings.Contains(sql, "FROM host"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*string) = env.sb.HostID
					*dest[1].(*string) = "vmd:50051"
					*dest[2].(*string) = "proxy:443"
					*dest[3].(*string) = "test-region"
					*dest[4].(*string) = "active"
					*dest[5].(*int32) = 1
					*dest[6].(*int32) = 1
					*dest[7].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: time.Now(), Valid: true}
					*dest[8].(*time.Time) = time.Now()
					*dest[9].(*time.Time) = time.Now()
					*dest[10].(*[]string) = env.hostCaps
					return nil
				}}
			case strings.Contains(sql, "preview_policy_revision = preview_policy_revision + 1"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int64) = env.policyRevision
					return nil
				}}
			case strings.Contains(sql, "token_version = token_version + 1"):
				if env.bumpNoRow {
					return errorRow(pgx.ErrNoRows)
				}
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int32) = portFromArgs(args)
					*dest[1].(*int32) = env.bumpToVersion
					*dest[2].(*string) = env.listAccess
					return nil
				}}
			case strings.Contains(sql, "INSERT INTO sandbox_published_port"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int32) = portFromArgs(args)
					*dest[1].(*int32) = env.publishToVersion
					// Echo the requested access back, like the real upsert.
					if len(args) >= 3 {
						if a, ok := args[2].(string); ok {
							*dest[2].(*string) = a
							return nil
						}
					}
					*dest[2].(*string) = env.listAccess
					return nil
				}}
			case strings.Contains(sql, "sandbox_published_port"): // GetPublishedPort
				if env.getPortVersion == 0 {
					return errorRow(pgx.ErrNoRows)
				}
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*int32) = portFromArgs(args)
					*dest[1].(*int32) = env.getPortVersion
					*dest[2].(*string) = env.listAccess
					return nil
				}}
			case strings.Contains(sql, "FROM sandbox"):
				return sandboxRow(env.sb)
			default:
				return activityRow()
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "sandbox_published_port") {
				return &portRows{rows: env.listPorts, access: env.listAccess}, nil
			}
			return emptyRows{}, nil
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "DELETE FROM sandbox_published_port") {
				return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", env.unpublishRows)), nil
			}
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
	env.router.GET("/sandboxes/:sandbox_id/preview-ports", env.handlers.ListSandboxPreviewPorts)
	env.router.POST("/sandboxes/:sandbox_id/preview-ports", env.handlers.PublishSandboxPreviewPort)
	env.router.DELETE("/sandboxes/:sandbox_id/preview-ports/:port", env.handlers.UnpublishSandboxPreviewPort)
	env.router.POST("/sandboxes/:sandbox_id/preview-ports/:port/token", env.handlers.MintSandboxPreviewToken)
	env.router.POST("/sandboxes/:sandbox_id/preview-ports/:port/token/rotate", env.handlers.RotateSandboxPreviewToken)
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

func (e *previewHandlerEnv) base() string {
	return "/sandboxes/" + e.sandboxID.String() + "/preview-ports"
}

// ---------------------------------------------------------------------------
// Publish / unpublish / list
// ---------------------------------------------------------------------------

func TestPublishPort_PushesFullSetToHost(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	var pushedAccess string
	var pushed map[int32]vmdclient.PortPolicy
	env.vmd.updatePreviewFn = func(_ context.Context, _ string, access string, ports map[int32]vmdclient.PortPolicy, _ int64) error {
		pushedAccess, pushed = access, ports
		return nil
	}

	w := env.do(http.MethodPost, env.base(), `{"port": 3000}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if pushedAccess != auth.PreviewAccessPrivate || pushed[3000].Version != 1 {
		t.Errorf("vmd push = (%q, %v), want (private, {3000:1})", pushedAccess, pushed)
	}
	body := parseJSON(t, w)
	if v, _ := body["token_version"].(float64); int(v) != 1 {
		t.Errorf("token_version = %v, want 1", body["token_version"])
	}
}

func TestPublishPort_InvalidPort400(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	for _, body := range []string{`{"port": 80}`, `{"port": 70000}`, `{"prt": 3000}`} {
		if w := env.do(http.MethodPost, env.base(), body); w.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, w.Code)
		}
	}
}

func TestPublishPort_VMDHardErrorIs500(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.vmd.updatePreviewFn = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
		return grpcUnavailable("vmd down")
	}
	if w := env.do(http.MethodPost, env.base(), `{"port": 3000}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when host push fails", w.Code)
	}
}

func TestPublishPort_VMDNotFoundIsOK(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.vmd.updatePreviewFn = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
		return grpcNotFound("no record on host")
	}
	if w := env.do(http.MethodPost, env.base(), `{"port": 3000}`); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (NotFound → applies on next restore)", w.Code)
	}
}

func TestUnpublishPort_PushesResultingSetWithRevision(t *testing.T) {
	// The pushed set is the post-mutation published set (read inside the same
	// transaction as the delete + revision bump), tagged with the bumped
	// revision so vmd can order it against concurrent pushes.
	env := newPreviewHandlerEnv(t)
	env.policyRevision = 9
	env.listPorts = [][2]int32{{8080, 2}} // state after 3000 is removed

	var pushed map[int32]vmdclient.PortPolicy
	var pushedRev int64
	env.vmd.updatePreviewFn = func(_ context.Context, _, _ string, ports map[int32]vmdclient.PortPolicy, rev int64) error {
		pushed, pushedRev = ports, rev
		return nil
	}

	w := env.do(http.MethodDelete, env.base()+"/3000", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if _, still := pushed[3000]; still || pushed[8080].Version != 2 {
		t.Errorf("pushed set = %v, want {8080:2}", pushed)
	}
	if pushedRev != 9 {
		t.Errorf("pushed revision = %d, want 9 (the bumped policy revision)", pushedRev)
	}
}

func TestUnpublishPort_HostPushFailureIs500(t *testing.T) {
	// A failed host push is a 500: the DB change committed but the host didn't
	// get it. That is recoverable — a retry re-bumps the revision and re-pushes,
	// and vmd accepts the higher revision — so this is not split-brain.
	env := newPreviewHandlerEnv(t)
	env.vmd.updatePreviewFn = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
		return grpcUnavailable("vmd down")
	}
	if w := env.do(http.MethodDelete, env.base()+"/3000", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when host push fails", w.Code)
	}
}

func TestUnpublishPort_IdempotentRetryRepairsHost(t *testing.T) {
	// The reviewer's scenario: DB row already gone but the host still routes
	// the port (stale enforcement copy). A repeat DELETE must re-bump, re-push
	// the corrected allowlist, and succeed — never 404 without touching the
	// host.
	env := newPreviewHandlerEnv(t)
	env.listPorts = [][2]int32{{8080, 2}} // 3000 already absent from the DB
	env.unpublishRows = 0                 // delete affects no rows

	var pushed map[int32]vmdclient.PortPolicy
	called := false
	env.vmd.updatePreviewFn = func(_ context.Context, _, _ string, ports map[int32]vmdclient.PortPolicy, _ int64) error {
		called, pushed = true, ports
		return nil
	}

	w := env.do(http.MethodDelete, env.base()+"/3000", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (idempotent); body: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("host never received the corrected allowlist on retry")
	}
	if _, still := pushed[3000]; still || pushed[8080].Version != 2 {
		t.Errorf("pushed set = %v, want {8080:2}", pushed)
	}
}

func TestUnpublishPort_LastPortPushesEmptySet(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.listPorts = nil // post-delete state: nothing left published
	var pushed map[int32]vmdclient.PortPolicy
	called := false
	env.vmd.updatePreviewFn = func(_ context.Context, _, _ string, ports map[int32]vmdclient.PortPolicy, _ int64) error {
		called, pushed = true, ports
		return nil
	}
	w := env.do(http.MethodDelete, env.base()+"/3000", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if !called || len(pushed) != 0 {
		t.Errorf("expected empty set pushed to host, got called=%v ports=%v", called, pushed)
	}
}

func TestListPreviewPorts_ReturnsSetNoTokens(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.listPorts = [][2]int32{{3000, 1}, {8080, 3}}
	w := env.do(http.MethodGet, env.base(), "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token\"") || strings.Contains(w.Body.String(), "spv1.") {
		t.Errorf("list response leaked a token: %s", w.Body.String())
	}
	body := parseJSON(t, w)
	if body["preview_access"] != auth.PreviewAccessPrivate {
		t.Errorf("preview_access = %v", body["preview_access"])
	}
	ports, _ := body["ports"].([]any)
	if len(ports) != 2 {
		t.Fatalf("ports len = %d, want 2", len(ports))
	}
}

// ---------------------------------------------------------------------------
// Mint (write-gated, port must be published)
// ---------------------------------------------------------------------------

func TestMintToken_PublishedPort(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.getPortVersion = 1
	w := env.do(http.MethodPost, env.base()+"/3000/token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := parseJSON(t, w)
	if body["header"] != auth.PreviewTokenHeader || body["query_param"] != auth.PreviewTokenQueryParam {
		t.Errorf("carrier names wrong: %v / %v", body["header"], body["query_param"])
	}
	tok, _ := body["token"].(string)
	if !auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 3000, 1, tok) {
		t.Error("minted token does not verify for port 3000 v1")
	}
	if auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 3001, 1, tok) {
		t.Error("minted token verifies for a different port")
	}
}

func TestMintToken_UnpublishedPort404(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.getPortVersion = 0 // GetPublishedPort → ErrNoRows
	if w := env.do(http.MethodPost, env.base()+"/3000/token", ""); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unpublished port", w.Code)
	}
}

func TestMintToken_ExpiryValidation(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	if w := env.do(http.MethodPost, env.base()+"/3000/token", `{"expires_in_seconds": 999999999}`); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestMintToken_SeedMissing500(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.handlers.Config = &config.Config{}
	if w := env.do(http.MethodPost, env.base()+"/3000/token", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Rotate (per-port version)
// ---------------------------------------------------------------------------

func TestRotateToken_BumpsOnlyThisPort(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.bumpToVersion = 2
	env.listPorts = [][2]int32{{3000, 2}, {8080, 1}} // 8080 untouched

	var pushed map[int32]vmdclient.PortPolicy
	env.vmd.updatePreviewFn = func(_ context.Context, _, _ string, ports map[int32]vmdclient.PortPolicy, _ int64) error {
		pushed = ports
		return nil
	}

	w := env.do(http.MethodPost, env.base()+"/3000/token/rotate", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if pushed[3000].Version != 2 || pushed[8080].Version != 1 {
		t.Errorf("pushed set = %v, want {3000:2, 8080:1}", pushed)
	}
	body := parseJSON(t, w)
	tok, _ := body["token"].(string)
	if !auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 3000, 2, tok) {
		t.Error("rotated token does not verify at new version")
	}
	if auth.VerifyPreviewToken(previewTestSeed, env.sandboxID.String(), 3000, 1, tok) {
		t.Error("rotated token still verifies at old version")
	}
}

func TestRotateToken_UnpublishedPort404(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.bumpNoRow = true // BumpPublishedPortVersion → ErrNoRows
	if w := env.do(http.MethodPost, env.base()+"/3000/token/rotate", ""); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unpublished port", w.Code)
	}
}

func TestRotateToken_VMDHardErrorIs500(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.vmd.updatePreviewFn = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
		return grpcUnavailable("vmd down")
	}
	if w := env.do(http.MethodPost, env.base()+"/3000/token/rotate", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when host push fails", w.Code)
	}
}

// ---------------------------------------------------------------------------
// PATCH preview_access still works, and pushes the published set
// ---------------------------------------------------------------------------

func TestPatchSandbox_PreviewAccessPushesPublishedSet(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.listPorts = [][2]int32{{3000, 1}}
	var pushedAccess string
	var pushed map[int32]vmdclient.PortPolicy
	env.vmd.updatePreviewFn = func(_ context.Context, _, access string, ports map[int32]vmdclient.PortPolicy, _ int64) error {
		pushedAccess, pushed = access, ports
		return nil
	}
	env.router.PATCH("/sandboxes/:sandbox_id", env.handlers.PatchSandbox)

	w := env.do(http.MethodPatch, "/sandboxes/"+env.sandboxID.String(), `{"preview_access": "public"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if pushedAccess != auth.PreviewAccessPublic || pushed[3000].Version != 1 {
		t.Errorf("vmd push = (%q, %v), want (public, {3000:1})", pushedAccess, pushed)
	}
}

// ---------------------------------------------------------------------------
// Per-port access modes and rollout gates
// ---------------------------------------------------------------------------

// Publishing defaults the port's mode from the sandbox policy (private here)
// and both the response and the vmd push carry it.
func TestPublishPort_DefaultsAccessFromSandboxPolicy(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	var pushed map[int32]vmdclient.PortPolicy
	env.vmd.updatePreviewFn = func(_ context.Context, _, _ string, ports map[int32]vmdclient.PortPolicy, _ int64) error {
		pushed = ports
		return nil
	}
	w := env.do(http.MethodPost, env.base(), `{"port": 3000}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if parseJSON(t, w)["access"] != auth.PreviewAccessPrivate {
		t.Errorf("response access = %v, want private (sandbox default)", parseJSON(t, w)["access"])
	}
	if pushed[3000].Access != auth.PreviewAccessPrivate {
		t.Errorf("pushed access = %q, want private", pushed[3000].Access)
	}
}

// An explicit access overrides the sandbox default — and a PUBLIC publish must
// not consult the private-access flag (only private enablement is gated on it).
func TestPublishPort_ExplicitPublicAccess(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.disabledFlags[flagPreviewPortPrivateAccess] = true
	env.listAccess = auth.PreviewAccessPublic // post-mutation published set
	var pushed map[int32]vmdclient.PortPolicy
	env.vmd.updatePreviewFn = func(_ context.Context, _, _ string, ports map[int32]vmdclient.PortPolicy, _ int64) error {
		pushed = ports
		return nil
	}
	w := env.do(http.MethodPost, env.base(), `{"port": 3000, "access": "public"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if parseJSON(t, w)["access"] != auth.PreviewAccessPublic {
		t.Errorf("response access = %v, want public", parseJSON(t, w)["access"])
	}
	if pushed[3000].Access != auth.PreviewAccessPublic {
		t.Errorf("pushed access = %q, want public", pushed[3000].Access)
	}
}

func TestPublishPort_InvalidAccess400(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	for _, body := range []string{
		`{"port": 3000, "access": "legacy_public"}`,
		`{"port": 3000, "access": "open"}`,
	} {
		if w := env.do(http.MethodPost, env.base(), body); w.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, w.Code)
		}
	}
}

// Publication is flag-gated; the vmd must never see a push for a rejected
// publish.
func TestPublishPort_PublicationFlagOff403(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.disabledFlags[flagPreviewPortPublication] = true
	pushed := false
	env.vmd.updatePreviewFn = func(context.Context, string, string, map[int32]vmdclient.PortPolicy, int64) error {
		pushed = true
		return nil
	}
	if w := env.do(http.MethodPost, env.base(), `{"port": 3000}`); w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 with publication flag off", w.Code)
	}
	if pushed {
		t.Error("rejected publish still pushed policy to the host")
	}
}

func TestPublishPort_PrivateFlagOff403(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.disabledFlags[flagPreviewPortPrivateAccess] = true
	// Sandbox default is private, so a bare publish resolves to private.
	if w := env.do(http.MethodPost, env.base(), `{"port": 3000}`); w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 with private-access flag off", w.Code)
	}
}

// A host that does not advertise enforcement cannot accept a publish: the API
// fails instead of recording a policy nothing enforces.
func TestPublishPort_HostWithoutCapabilities409(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.hostCaps = nil
	if w := env.do(http.MethodPost, env.base(), `{"port": 3000, "access": "public"}`); w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 when the host advertises nothing", w.Code)
	}
}

// Port publication alone is not enough for a PRIVATE port — token
// verification must also be advertised. A public port on the same host is
// fine.
func TestPublishPort_PrivateNeedsTokensCapability(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.hostCaps = []string{auth.HostCapabilityPreviewPorts}
	if w := env.do(http.MethodPost, env.base(), `{"port": 3000, "access": "private"}`); w.Code != http.StatusConflict {
		t.Fatalf("private publish: status = %d, want 409 without the tokens capability", w.Code)
	}
	if w := env.do(http.MethodPost, env.base(), `{"port": 3000, "access": "public"}`); w.Code != http.StatusOK {
		t.Fatalf("public publish: status = %d, want 200 with only the ports capability; body: %s", w.Code, w.Body.String())
	}
}

// Revocation is never gated: with every flag off and a host that advertises
// nothing, unpublish and rotate still work. Turning a flag off must not
// strand a customer with credentials they cannot revoke.
func TestUnpublishAndRotate_UngatedByFlagsAndCapabilities(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.disabledFlags[flagPreviewPortPublication] = true
	env.disabledFlags[flagPreviewPortPrivateAccess] = true
	env.hostCaps = nil

	if w := env.do(http.MethodDelete, env.base()+"/3000", ""); w.Code != http.StatusNoContent {
		t.Fatalf("unpublish: status = %d, want 204 (revocation is ungated); body: %s", w.Code, w.Body.String())
	}
	if w := env.do(http.MethodPost, env.base()+"/3000/token/rotate", ""); w.Code != http.StatusOK {
		t.Fatalf("rotate: status = %d, want 200 (revocation is ungated); body: %s", w.Code, w.Body.String())
	}
}

func TestMintToken_ResponseCarriesPortAccess(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	w := env.do(http.MethodPost, env.base()+"/3000/token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if parseJSON(t, w)["access"] != auth.PreviewAccessPrivate {
		t.Errorf("token response access = %v, want private", parseJSON(t, w)["access"])
	}
}

// PATCHing the sandbox policy is enablement: flag-gated and host-checked.
func TestPatchPreviewAccess_FlagOff403(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.disabledFlags[flagPreviewPortPublication] = true
	env.router.PATCH("/sandboxes/:sandbox_id", env.handlers.PatchSandbox)
	w := env.do(http.MethodPatch, "/sandboxes/"+env.sandboxID.String(), `{"preview_access": "public"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 with publication flag off; body: %s", w.Code, w.Body.String())
	}
}

// Moving to strict "public" still needs token enforcement when an existing
// published port is private — its mode survives the sandbox-level change.
func TestPatchPreviewAccess_ExistingPrivatePortNeedsTokensCapability(t *testing.T) {
	env := newPreviewHandlerEnv(t)
	env.hostCaps = []string{auth.HostCapabilityPreviewPorts}
	env.router.PATCH("/sandboxes/:sandbox_id", env.handlers.PatchSandbox)

	// Existing port is private (env.listAccess default) → 409.
	w := env.do(http.MethodPatch, "/sandboxes/"+env.sandboxID.String(), `{"preview_access": "public"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 while a private port exists; body: %s", w.Code, w.Body.String())
	}

	// All ports public → the ports capability alone suffices.
	env.listAccess = auth.PreviewAccessPublic
	w = env.do(http.MethodPatch, "/sandboxes/"+env.sandboxID.String(), `{"preview_access": "public"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 with only public ports; body: %s", w.Code, w.Body.String())
	}
}
