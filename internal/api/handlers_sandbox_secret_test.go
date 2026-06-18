package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/secrets"
)

// noopEncryptor satisfies secrets.Encryptor so requireEncryptor passes; attach
// and detach never call it (they move stand-in tokens, not plaintext).
type noopEncryptor struct{}

func (noopEncryptor) Encrypt(context.Context, []byte) (secrets.Encrypted, error) {
	return secrets.Encrypted{}, nil
}
func (noopEncryptor) Decrypt(context.Context, secrets.Encrypted) ([]byte, error) { return nil, nil }

// scanRows is an iterable pgx.Rows backed by a list of per-row Scan funcs.
type scanRows struct {
	rows []func(dest ...any) error
	i    int
}

func (r *scanRows) Close()                                       {}
func (r *scanRows) Err() error                                   { return nil }
func (r *scanRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *scanRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *scanRows) Next() bool {
	if r.i >= len(r.rows) {
		return false
	}
	r.i++
	return true
}
func (r *scanRows) Scan(dest ...any) error { return r.rows[r.i-1](dest...) }
func (r *scanRows) Values() ([]any, error) { return nil, nil }
func (r *scanRows) RawValues() [][]byte    { return nil }
func (r *scanRows) Conn() *pgx.Conn        { return nil }

// secretRow populates a Secret from GetSecretByName's 14-column Scan.
func secretRow(s db.Secret) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = s.ID
		*dest[1].(*uuid.UUID) = s.TeamID
		*dest[2].(*string) = s.Name
		*dest[3].(*string) = s.AuthType
		*dest[4].(*[]byte) = s.AuthConfig
		*dest[5].(**string) = s.ProviderShortcut
		*dest[6].(*[]string) = s.Hosts
		*dest[7].(*[]byte) = s.Ciphertext
		*dest[8].(*[]byte) = s.EncryptedDek
		*dest[9].(*string) = s.KekID
		// created_at, updated_at, last_used_at, deleted_at unused by the handler.
		return nil
	}}
}

// bindingMetaRow scans one ListSandboxSecretBindingMeta row (7 columns).
func bindingMetaRow(secretID uuid.UUID, envKey, authType string, token string) func(dest ...any) error {
	return func(dest ...any) error {
		*dest[0].(*uuid.UUID) = secretID
		*dest[1].(*string) = envKey
		tok := token
		*dest[2].(**string) = &tok
		*dest[3].(*string) = authType
		*dest[4].(*[]byte) = nil
		*dest[5].(**string) = nil
		*dest[6].(*[]string) = []string{"api.anthropic.com"}
		return nil
	}
}

// bindingRow scans one ListSandboxSecretBindings row (env_key, secret_name, revoked).
func bindingRow(envKey, secretName string) func(dest ...any) error {
	return func(dest ...any) error {
		*dest[0].(*string) = envKey
		*dest[1].(*string) = secretName
		*dest[2].(*bool) = false
		return nil
	}
}

func setupSecretRouter(h *Handlers, teamID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if teamID != "" {
			c.Set("team_id", teamID)
		}
		c.Next()
	})
	r.POST("/sandboxes/:sandbox_id/secrets", h.AttachSandboxSecret)
	r.DELETE("/sandboxes/:sandbox_id/secrets/:env_key", h.DetachSandboxSecret)
	return r
}

func attachReq(sandboxID, body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/secrets", strings.NewReader(body))
}

func detachReq(sandboxID, envKey string) *http.Request {
	return httptest.NewRequest(http.MethodDelete, "/sandboxes/"+sandboxID+"/secrets/"+envKey, nil)
}

func TestApplySecretBindings_InjectsJWTAndEnv(t *testing.T) {
	var gotEnv map[string]string
	var gotJWT string
	vmd := &stubVMD{injectEnvFn: func(_ context.Context, _ string, env map[string]string, jwt string) error {
		gotEnv, gotJWT = env, jwt
		return nil
	}}
	h := &Handlers{VMD: vmd, Signer: newTestSigner(t, "v1")}

	ip := netip.MustParseAddr("10.0.0.5")
	sb := db.Sandbox{ID: uuid.New(), TeamID: uuid.New(), HostID: "host-1", IpAddress: &ip}
	meta := []SecretBindingMeta{{
		SecretID:   uuid.New(),
		EnvKey:     "ANTHROPIC_API_KEY",
		AuthType:   "bearer",
		Hosts:      []string{"api.anthropic.com"},
		ProxyToken: "ssrv_proxy_abc",
	}}
	if err := h.applySecretBindings(context.Background(), sb, meta); err != nil {
		t.Fatalf("applySecretBindings: %v", err)
	}
	if gotJWT == "" {
		t.Error("expected a signed JWT for a non-empty binding set")
	}
	if gotEnv["ANTHROPIC_API_KEY"] != "ssrv_proxy_abc" {
		t.Errorf("env stand-in = %q, want the proxy token", gotEnv["ANTHROPIC_API_KEY"])
	}
}

func TestApplySecretBindings_EmptyMetaNoJWT(t *testing.T) {
	var called bool
	var gotJWT string
	vmd := &stubVMD{injectEnvFn: func(_ context.Context, _ string, _ map[string]string, jwt string) error {
		called, gotJWT = true, jwt
		return nil
	}}
	h := &Handlers{VMD: vmd, Signer: newTestSigner(t, "v1")}

	sb := db.Sandbox{ID: uuid.New(), TeamID: uuid.New(), HostID: "host-1"}
	if err := h.applySecretBindings(context.Background(), sb, nil); err != nil {
		t.Fatalf("applySecretBindings: %v", err)
	}
	if !called {
		t.Fatal("InjectSandboxEnv was not called")
	}
	if gotJWT != "" {
		t.Errorf("empty binding set should inject no JWT, got %q", gotJWT)
	}
}

func TestAttachSandboxSecret_Active_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	secretID := uuid.New()
	ip := netip.MustParseAddr("10.0.0.5")
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive, HostID: "host-1", IpAddress: &ip}

	var injected bool
	vmd := &stubVMD{injectEnvFn: func(_ context.Context, _ string, _ map[string]string, jwt string) error {
		injected = true
		if jwt == "" {
			t.Error("active attach should inject a signed JWT")
		}
		return nil
	}}

	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "GetSandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "GetSecretByName"):
				return secretRow(db.Secret{ID: secretID, TeamID: teamID, Name: "anthropic-prod", AuthType: "bearer"})
			default: // CreateActivity
				return activityRow()
			}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "ListSandboxSecretBindingMeta") {
				return &scanRows{rows: []func(...any) error{bindingMetaRow(secretID, "ANTHROPIC_API_KEY", "bearer", "ssrv_proxy_x")}}, nil
			}
			return &scanRows{}, nil // ListSandboxSecretBindings: no existing bindings
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, attachReq(sandboxID.String(), `{"env_key":"ANTHROPIC_API_KEY","secret_name":"anthropic-prod"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if !injected {
		t.Error("InjectSandboxEnv was not called for an active sandbox")
	}
}

func TestAttachSandboxSecret_Paused_NoInject(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusPaused, HostID: "host-1"}

	vmd := &stubVMD{injectEnvFn: func(context.Context, string, map[string]string, string) error {
		t.Error("a paused sandbox must not be injected on attach")
		return nil
	}}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "GetSandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "GetSecretByName"):
				return secretRow(db.Secret{ID: uuid.New(), TeamID: teamID, Name: "anthropic-prod", AuthType: "bearer"})
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, attachReq(sandboxID.String(), `{"env_key":"ANTHROPIC_API_KEY","secret_name":"anthropic-prod"}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
}

func TestAttachSandboxSecret_NotFound(t *testing.T) {
	teamID := uuid.New()
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, attachReq(uuid.New().String(), `{"env_key":"ANTHROPIC_API_KEY","secret_name":"anthropic-prod"}`))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func TestAttachSandboxSecret_BadStatus_Conflict(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusResuming, HostID: "host-1"}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, attachReq(sandboxID.String(), `{"env_key":"ANTHROPIC_API_KEY","secret_name":"anthropic-prod"}`))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
}

func TestAttachSandboxSecret_EnvKeyCollision_Conflict(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusActive, HostID: "host-1"}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "GetSecretByName") {
				return secretRow(db.Secret{ID: uuid.New(), TeamID: teamID, Name: "anthropic-prod", AuthType: "bearer"})
			}
			return sandboxRow(sb)
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			return &scanRows{rows: []func(...any) error{bindingRow("ANTHROPIC_API_KEY", "other")}}, nil
		},
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, attachReq(sandboxID.String(), `{"env_key":"ANTHROPIC_API_KEY","secret_name":"anthropic-prod"}`))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
}

func TestAttachSandboxSecret_SecretNotFound(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusActive, HostID: "host-1"}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "GetSecretByName") {
				return notFoundRow()
			}
			return sandboxRow(sb)
		},
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) { return &scanRows{}, nil },
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, attachReq(sandboxID.String(), `{"env_key":"ANTHROPIC_API_KEY","secret_name":"anthropic-prod"}`))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestDetachSandboxSecret_Active_Success(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	ip := netip.MustParseAddr("10.0.0.5")
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Name: "sb", Status: db.SandboxStatusActive, HostID: "host-1", IpAddress: &ip}

	var injected bool
	vmd := &stubVMD{injectEnvFn: func(context.Context, string, map[string]string, string) error {
		injected = true
		return nil
	}}
	tok := "ssrv_proxy_gone"
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "GetSandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "DeleteSandboxSecretBinding"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = uuid.New()
					*dest[1].(**string) = &tok
					return nil
				}}
			default:
				return activityRow()
			}
		},
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) { return &scanRows{}, nil },
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, detachReq(sandboxID.String(), "ANTHROPIC_API_KEY"))

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if !injected {
		t.Error("InjectSandboxEnv was not called to re-mint the reduced set")
	}
}

func TestDetachSandboxSecret_Paused_NoInject(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusPaused, HostID: "host-1"}

	vmd := &stubVMD{injectEnvFn: func(context.Context, string, map[string]string, string) error {
		t.Error("a paused sandbox must not be injected on detach")
		return nil
	}}
	tok := "ssrv_proxy_gone"
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "GetSandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "DeleteSandboxSecretBinding"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = uuid.New()
					*dest[1].(**string) = &tok
					return nil
				}}
			default:
				return activityRow()
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	h := &Handlers{VMD: vmd, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, detachReq(sandboxID.String(), "ANTHROPIC_API_KEY"))

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
}

func TestDetachSandboxSecret_NoEncryptor_Succeeds(t *testing.T) {
	// Revocation must work with neither encryptor nor signer configured.
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusPaused, HostID: "host-1"}

	tok := "ssrv_proxy_gone"
	var revoked bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "GetSandbox"):
				return sandboxRow(sb)
			case strings.Contains(sql, "DeleteSandboxSecretBinding"):
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = uuid.New()
					*dest[1].(**string) = &tok
					return nil
				}}
			default:
				return activityRow()
			}
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "InsertRevokedProxyToken") {
				revoked = true
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}

	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock), Encryptor: nil, Signer: nil}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, detachReq(sandboxID.String(), "ANTHROPIC_API_KEY"))

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body.String())
	}
	if !revoked {
		t.Error("detach must record the binding's token as revoked")
	}
}

func TestAttachSandboxSecret_NoSignerReturns500(t *testing.T) {
	// With an encryptor but no signer, a binding can never be minted into a JWT,
	// so attach must reject up front (active or paused) rather than bank it.
	teamID := uuid.New()
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(&mockDBTX{}), Encryptor: noopEncryptor{}, Signer: nil}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, attachReq(uuid.New().String(), `{"env_key":"ANTHROPIC_API_KEY","secret_name":"anthropic-prod"}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

func TestLoadSecretBindingMeta_PersistsMintedTokenForLegacyRow(t *testing.T) {
	sandboxID := uuid.New()
	secretID := uuid.New()
	var persisted bool
	mock := &mockDBTX{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &scanRows{rows: []func(...any) error{func(dest ...any) error {
				*dest[0].(*uuid.UUID) = secretID
				*dest[1].(*string) = "ANTHROPIC_API_KEY"
				*dest[2].(**string) = nil // legacy: NULL proxy_token
				*dest[3].(*string) = "api-key"
				*dest[4].(*[]byte) = nil
				sc := "anthropic"
				*dest[5].(**string) = &sc
				*dest[6].(*[]string) = []string{"api.anthropic.com"}
				return nil
			}}}, nil
		},
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "ClaimSandboxSecretProxyToken") {
				persisted = true
				tok, _ := args[2].(*string) // the minted token passed in; echo it back
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(**string) = tok
					return nil
				}}
			}
			return notFoundRow()
		},
	}
	h := &Handlers{DB: db.New(mock)}
	meta, err := h.loadSecretBindingMeta(context.Background(), sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != 1 || meta[0].ProxyToken == "" {
		t.Fatalf("expected one binding with a minted token, got %+v", meta)
	}
	if !persisted {
		t.Error("a token minted for a legacy NULL row must be persisted so detach can revoke it")
	}
}

func TestDetachSandboxSecret_BindingNotFound(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusActive, HostID: "host-1"}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "DeleteSandboxSecretBinding") {
				return notFoundRow()
			}
			return sandboxRow(sb)
		},
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, detachReq(sandboxID.String(), "ANTHROPIC_API_KEY"))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func TestDetachSandboxSecret_RevocationFailureReturns500(t *testing.T) {
	// Fail closed: a revocation-insert failure must surface as 500, not 204.
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusPaused, HostID: "host-1"}
	tok := "ssrv_proxy_gone"
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "DeleteSandboxSecretBinding") {
				return &mockRow{scanFn: func(dest ...any) error {
					*dest[0].(*uuid.UUID) = uuid.New()
					*dest[1].(**string) = &tok
					return nil
				}}
			}
			return sandboxRow(sb)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("insert revoked token failed")
		},
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, detachReq(sandboxID.String(), "ANTHROPIC_API_KEY"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

func TestDetachSandboxSecret_BadStatus_Conflict(t *testing.T) {
	sandboxID := uuid.New()
	teamID := uuid.New()
	sb := db.Sandbox{ID: sandboxID, TeamID: teamID, Status: db.SandboxStatusResuming, HostID: "host-1"}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
	}
	h := &Handlers{VMD: &stubVMD{}, DB: db.New(mock), Encryptor: noopEncryptor{}, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, detachReq(sandboxID.String(), "ANTHROPIC_API_KEY"))

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
}
