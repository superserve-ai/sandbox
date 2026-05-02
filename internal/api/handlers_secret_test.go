package api

import (
	"context"
	"errors"
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

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/secrets"
)

// ---------------------------------------------------------------------------
// fakeEnc — minimal Encryptor for tests. Round-trips opaquely; the bytes it
// returns aren't real ciphertext, just markers.
// ---------------------------------------------------------------------------

type fakeEnc struct {
	encErr  error
	calls   int
	lastVal []byte
}

func (f *fakeEnc) Encrypt(_ context.Context, plaintext []byte) (secrets.Encrypted, error) {
	f.calls++
	f.lastVal = append([]byte(nil), plaintext...)
	if f.encErr != nil {
		return secrets.Encrypted{}, f.encErr
	}
	return secrets.Encrypted{
		Ciphertext:   []byte("ct:" + string(plaintext)),
		EncryptedDEK: []byte("dek"),
		KEKID:        "kek/test",
	}, nil
}

func (f *fakeEnc) Decrypt(_ context.Context, enc secrets.Encrypted) ([]byte, error) {
	return enc.Ciphertext, nil
}

// ---------------------------------------------------------------------------
// Secret row helper — populates a Secret from a Scan call.
// Field order matches the secret table column order (sqlc-generated).
// ---------------------------------------------------------------------------

func secretRow(s db.Secret) *mockRow {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*uuid.UUID) = s.ID
		*dest[1].(*uuid.UUID) = s.TeamID
		*dest[2].(*string) = s.Name
		*dest[3].(*string) = s.Provider
		*dest[4].(*[]byte) = s.Ciphertext
		*dest[5].(*[]byte) = s.EncryptedDek
		*dest[6].(*string) = s.KekID
		*dest[7].(*time.Time) = s.CreatedAt
		*dest[8].(*time.Time) = s.UpdatedAt
		*dest[9].(*pgtype.Timestamptz) = s.LastUsedAt
		*dest[10].(*pgtype.Timestamptz) = s.DeletedAt
		return nil
	}}
}

// ---------------------------------------------------------------------------
// Router helper — wires the secret + audit routes for a Handlers under test.
// ---------------------------------------------------------------------------

func setupSecretRouter(h *Handlers, teamID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if teamID != "" {
			c.Set("team_id", teamID)
		}
		c.Next()
	})
	r.POST("/secrets", h.CreateSecret)
	r.GET("/secrets/:name", h.GetSecret)
	r.PATCH("/secrets/:name", h.PatchSecret)
	r.DELETE("/secrets/:name", h.DeleteSecret)
	r.GET("/sandboxes/:sandbox_id/audit", h.GetSandboxAudit)
	return r
}

func jsonReq(method, url, body string) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// ---------------------------------------------------------------------------
// CreateSecret
// ---------------------------------------------------------------------------

func TestCreateSecret_Success(t *testing.T) {
	teamID := uuid.New()
	created := db.Secret{
		ID: uuid.New(), TeamID: teamID, Name: "ANTHROPIC_PROD",
		Provider: "anthropic", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	enc := &fakeEnc{}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if !strings.Contains(sql, "INSERT INTO secret") {
				t.Fatalf("unexpected query: %s", sql)
			}
			return secretRow(created)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
	}
	h := &Handlers{DB: db.New(mock), Encryptor: enc}

	w := httptest.NewRecorder()
	body := `{"name":"ANTHROPIC_PROD","provider":"anthropic","value":"sk-ant-secret"}`
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, jsonReq(http.MethodPost, "/secrets", body))

	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	resp := parseJSON(t, w)
	if resp["name"] != "ANTHROPIC_PROD" {
		t.Errorf("name=%v", resp["name"])
	}
	if _, hasValue := resp["value"]; hasValue {
		t.Error("response leaked plaintext value")
	}
	if enc.calls != 1 {
		t.Errorf("encryptor called %d times, want 1", enc.calls)
	}
	if string(enc.lastVal) != "sk-ant-secret" {
		t.Errorf("encryptor saw %q", enc.lastVal)
	}
}

func TestCreateSecret_BadName(t *testing.T) {
	teamID := uuid.New()
	cases := []string{
		`{"name":"","provider":"anthropic","value":"x"}`,
		`{"name":"has space","provider":"anthropic","value":"x"}`,
		`{"name":"slashes/not/allowed","provider":"anthropic","value":"x"}`,
		`{"name":"-startsbad","provider":"anthropic","value":"x"}`,
		`{"name":"9digitfirst","provider":"anthropic","value":"x"}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			mock := &mockDBTX{
				queryRowFn: func(context.Context, string, ...any) pgx.Row {
					t.Fatal("DB should not be called for invalid name")
					return notFoundRow()
				},
				execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
					return pgconn.CommandTag{}, nil
				},
			}
			h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
			w := httptest.NewRecorder()
			setupSecretRouter(h, teamID.String()).ServeHTTP(w, jsonReq(http.MethodPost, "/secrets", body))
			if w.Code != http.StatusBadRequest {
				t.Errorf("status=%d", w.Code)
			}
		})
	}
}

func TestCreateSecret_BadProvider(t *testing.T) {
	teamID := uuid.New()
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			t.Fatal("DB should not be called")
			return notFoundRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	body := `{"name":"FOO","provider":"openai","value":"x"}`
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, jsonReq(http.MethodPost, "/secrets", body))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, body=%s", w.Code, w.Body.String())
	}
}

func TestCreateSecret_EmptyValue(t *testing.T) {
	teamID := uuid.New()
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	body := `{"name":"FOO","provider":"anthropic","value":""}`
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, jsonReq(http.MethodPost, "/secrets", body))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCreateSecret_DuplicateReturns409(t *testing.T) {
	teamID := uuid.New()
	pgErr := &pgconn.PgError{Code: "23505", ConstraintName: "secret_team_name_unique"}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return errorRow(pgErr)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	body := `{"name":"DUP","provider":"anthropic","value":"x"}`
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, jsonReq(http.MethodPost, "/secrets", body))
	if w.Code != http.StatusConflict {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCreateSecret_EncryptorMissing(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	// Encryptor: nil
	h := &Handlers{DB: db.New(mock)}
	w := httptest.NewRecorder()
	body := `{"name":"FOO","provider":"anthropic","value":"x"}`
	setupSecretRouter(h, uuid.New().String()).ServeHTTP(w, jsonReq(http.MethodPost, "/secrets", body))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCreateSecret_EncryptError(t *testing.T) {
	teamID := uuid.New()
	enc := &fakeEnc{encErr: errors.New("kms unreachable")}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			t.Fatal("DB should not be called when encrypt fails")
			return notFoundRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: enc}
	w := httptest.NewRecorder()
	body := `{"name":"FOO","provider":"anthropic","value":"x"}`
	setupSecretRouter(h, teamID.String()).ServeHTTP(w, jsonReq(http.MethodPost, "/secrets", body))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// GetSecret
// ---------------------------------------------------------------------------

func TestGetSecret_Success(t *testing.T) {
	teamID := uuid.New()
	row := db.Secret{
		ID: uuid.New(), TeamID: teamID, Name: "ANTHROPIC_PROD",
		Provider: "anthropic", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return secretRow(row) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/secrets/ANTHROPIC_PROD", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	resp := parseJSON(t, w)
	if _, hasCipher := resp["ciphertext"]; hasCipher {
		t.Error("response leaked ciphertext field")
	}
	if _, hasDEK := resp["encrypted_dek"]; hasDEK {
		t.Error("response leaked encrypted_dek field")
	}
	if _, hasValue := resp["value"]; hasValue {
		t.Error("response leaked plaintext value")
	}
}

func TestGetSecret_NotFound(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	setupSecretRouter(h, uuid.New().String()).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/secrets/MISSING", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// PatchSecret
// ---------------------------------------------------------------------------

func TestPatchSecret_Success(t *testing.T) {
	teamID := uuid.New()
	existing := db.Secret{
		ID: uuid.New(), TeamID: teamID, Name: "ANTHROPIC_PROD",
		Provider: "anthropic", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	updated := existing
	updated.UpdatedAt = time.Now().Add(time.Minute)

	enc := &fakeEnc{}
	calls := 0
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			calls++
			if calls == 1 {
				if !strings.Contains(sql, "SELECT") {
					t.Errorf("first call: expected SELECT, got %s", sql)
				}
				return secretRow(existing)
			}
			if !strings.Contains(sql, "UPDATE secret") {
				t.Errorf("second call: expected UPDATE, got %s", sql)
			}
			return secretRow(updated)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: enc}
	w := httptest.NewRecorder()
	body := `{"value":"sk-ant-NEW"}`
	setupSecretRouter(h, teamID.String()).ServeHTTP(w,
		jsonReq(http.MethodPatch, "/secrets/ANTHROPIC_PROD", body))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if enc.calls != 1 {
		t.Errorf("encryptor calls = %d, want 1", enc.calls)
	}
	if string(enc.lastVal) != "sk-ant-NEW" {
		t.Errorf("encryptor saw %q", enc.lastVal)
	}
}

func TestPatchSecret_NotFound(t *testing.T) {
	teamID := uuid.New()
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	body := `{"value":"sk-ant-x"}`
	setupSecretRouter(h, teamID.String()).ServeHTTP(w,
		jsonReq(http.MethodPatch, "/secrets/MISSING", body))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPatchSecret_EmptyValue(t *testing.T) {
	teamID := uuid.New()
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			t.Fatal("DB should not be called for empty value")
			return notFoundRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	body := `{"value":""}`
	setupSecretRouter(h, teamID.String()).ServeHTTP(w,
		jsonReq(http.MethodPatch, "/secrets/FOO", body))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeleteSecret
// ---------------------------------------------------------------------------

func TestDeleteSecret_Success(t *testing.T) {
	teamID := uuid.New()
	row := db.Secret{
		ID: uuid.New(), TeamID: teamID, Name: "FOO",
		Provider: "anthropic", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if !strings.Contains(sql, "UPDATE secret") {
				t.Errorf("unexpected query: %s", sql)
			}
			return secretRow(row)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w,
		httptest.NewRequest(http.MethodDelete, "/secrets/FOO", nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteSecret_NotFound(t *testing.T) {
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	setupSecretRouter(h, uuid.New().String()).ServeHTTP(w,
		httptest.NewRequest(http.MethodDelete, "/secrets/MISSING", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetSandboxAudit — basic auth + query-param tests. Listing rows requires
// pgx.Rows mocking which existing tests don't have, so we cover the
// gating behavior here and leave row-listing for integration tests.
// ---------------------------------------------------------------------------

func TestGetSandboxAudit_BadUUID(t *testing.T) {
	teamID := uuid.New()
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	setupSecretRouter(h, teamID.String()).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/sandboxes/not-a-uuid/audit", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d", w.Code)
	}
}

func TestGetSandboxAudit_SandboxNotFound(t *testing.T) {
	teamID := uuid.New()
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	w := httptest.NewRecorder()
	url := fmt.Sprintf("/sandboxes/%s/audit", uuid.New())
	setupSecretRouter(h, teamID.String()).ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestGetSandboxAudit_BadLimit(t *testing.T) {
	teamID := uuid.New()
	sb := db.Sandbox{ID: uuid.New(), TeamID: teamID, Status: db.SandboxStatusActive}
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return sandboxRow(sb) },
		execFn:     func(context.Context, string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, nil },
	}
	h := &Handlers{DB: db.New(mock), Encryptor: &fakeEnc{}}
	cases := []string{
		"?limit=0",
		"?limit=-1",
		"?limit=abc",
		"?limit=100000",
		"?before=-5",
		"?before=notanumber",
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/sandboxes/%s/audit%s", sb.ID, q)
			setupSecretRouter(h, teamID.String()).ServeHTTP(w,
				httptest.NewRequest(http.MethodGet, url, nil))
			if w.Code != http.StatusBadRequest {
				t.Errorf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
