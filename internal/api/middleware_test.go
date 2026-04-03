package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

// fakeRow implements pgx.Row for testing.
type fakeRow struct {
	values []any
	err    error
}

func (r *fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		switch v := d.(type) {
		case *uuid.UUID:
			*v = r.values[i].(uuid.UUID)
		case *string:
			*v = r.values[i].(string)
		case *time.Time:
			*v = r.values[i].(time.Time)
		case *pgtype.Timestamptz:
			if r.values[i] == nil {
				v.Valid = false
			} else {
				v.Time = r.values[i].(time.Time)
				v.Valid = true
			}
		case *bool:
			*v = r.values[i].(bool)
		case *[]string:
			*v = r.values[i].([]string)
		}
	}
	return nil
}

// fakeDBTX implements db.DBTX for testing.
type fakeDBTX struct {
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (f *fakeDBTX) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if f.execFn != nil {
		return f.execFn(ctx, sql, args...)
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (f *fakeDBTX) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, nil
}

func (f *fakeDBTX) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if f.queryRowFn != nil {
		return f.queryRowFn(ctx, sql, args...)
	}
	return &fakeRow{err: pgx.ErrNoRows}
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func setupTestRouter(queries *db.Queries) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(APIKeyAuth(queries))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"api_key_id": c.GetString("api_key_id"),
			"team_id":    c.GetString("team_id"),
		})
	})
	return r
}

func TestAPIKeyAuth_MissingHeader(t *testing.T) {
	fake := &fakeDBTX{}
	queries := db.New(fake)
	router := setupTestRouter(queries)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyAuth_InvalidKey(t *testing.T) {
	fake := &fakeDBTX{
		queryRowFn: func(_ context.Context, _ string, _ ...any) pgx.Row {
			return &fakeRow{err: pgx.ErrNoRows}
		},
	}
	queries := db.New(fake)
	router := setupTestRouter(queries)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "bad-key")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyAuth_ValidKey(t *testing.T) {
	keyID := uuid.New()
	teamID := uuid.New()
	now := time.Now()

	fake := &fakeDBTX{
		queryRowFn: func(_ context.Context, _ string, args ...any) pgx.Row {
			return &fakeRow{
				values: []any{
					keyID,                    // id
					args[0].(string),         // key_hash
					"test-key",               // name
					now,                      // created_at
					nil,                      // expires_at
					false,                    // revoked
					teamID,                   // team_id
					[]string{"instances:*"},  // scopes
					nil,                      // last_used_at
				},
			}
		},
		execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	queries := db.New(fake)
	router := setupTestRouter(queries)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "valid-key-123")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["api_key_id"] != keyID.String() {
		t.Errorf("api_key_id = %q, want %q", resp["api_key_id"], keyID.String())
	}
	if resp["team_id"] != teamID.String() {
		t.Errorf("team_id = %q, want %q", resp["team_id"], teamID.String())
	}
}

func TestAPIKeyAuth_HashesCorrectly(t *testing.T) {
	var receivedHash string
	keyID := uuid.New()
	teamID := uuid.New()
	now := time.Now()

	fake := &fakeDBTX{
		queryRowFn: func(_ context.Context, _ string, args ...any) pgx.Row {
			receivedHash = args[0].(string)
			return &fakeRow{
				values: []any{
					keyID, receivedHash, "test", now, nil, false,
					teamID, []string{}, nil,
				},
			}
		},
		execFn: func(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	queries := db.New(fake)
	router := setupTestRouter(queries)

	apiKey := "my-secret-key"
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", apiKey)
	router.ServeHTTP(w, req)

	expectedHash := hashKey(apiKey)
	if receivedHash != expectedHash {
		t.Errorf("hash mismatch: got %q, want %q", receivedHash, expectedHash)
	}
}

func TestRequireScope_Allowed(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		scope  string
	}{
		{"exact match", []string{"instances:read", "instances:write"}, "instances:read"},
		{"wildcard", []string{"*"}, "instances:read"},
		{"empty scopes allows all", []string{}, "anything"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("scopes", tt.scopes)
				c.Next()
			})
			r.Use(RequireScope(tt.scope))
			r.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"ok": true})
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", w.Code)
			}
		})
	}
}

func TestRequireScope_Denied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("scopes", []string{"instances:read"})
		c.Next()
	})
	r.Use(RequireScope("instances:write"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireScope_NoScopesInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequireScope("instances:read"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
