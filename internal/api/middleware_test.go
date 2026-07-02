package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// APIKeyAuth middleware tests
// ---------------------------------------------------------------------------

// We can't easily mock pgxpool.Pool (it's a concrete type), so we test the
// auth middleware through the full router using a real test DB in integration
// tests. Here we test the middleware's observable behavior via HTTP:
// missing header, empty header, etc.

func newAuthTestRouter(pool *pgxpool.Pool) *gin.Engine {
	r := gin.New()
	r.Use(APIKeyAuth(pool))
	r.GET("/test", func(c *gin.Context) {
		teamID, _ := c.Get("team_id")
		c.JSON(http.StatusOK, gin.H{"team_id": teamID})
	})
	return r
}

func TestAPIKeyAuth_MissingHeader(t *testing.T) {
	// Pass nil pool — middleware should reject before touching DB.
	r := newAuthTestRouter(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected error object, got %v", resp)
	}
	if errObj["code"] != "auth_failed" {
		t.Errorf("expected code=auth_failed, got %v", errObj["code"])
	}
}

func TestAPIKeyAuth_EmptyHeader(t *testing.T) {
	r := newAuthTestRouter(nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Wrong-cell 401 (region-tagged API keys)
// ---------------------------------------------------------------------------

// newUnreachablePool returns a pool whose every query errors: pgxpool
// connects lazily, so construction succeeds and the middleware's key lookup
// fails at Scan — the same branch a key-not-found takes.
func newUnreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// doAuthRequest sends a request with the given API key and returns the status
// code and decoded error object (nil if the body has none).
func doAuthRequest(t *testing.T, r *gin.Engine, key string) (int, map[string]interface{}) {
	t.Helper()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", key)
	r.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj, _ := resp["error"].(map[string]interface{})
	return w.Code, errObj
}

func TestAPIKeyAuth_WrongRegionKey(t *testing.T) {
	t.Setenv("SANDBOX_ID_REGION", "use")
	r := newAuthTestRouter(newUnreachablePool(t))

	code, errObj := doAuthRequest(t, r, "ss_live_usw_dGVzdHJhbmRvbQ")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
	if errObj["code"] != "wrong_region" {
		t.Errorf("expected code=wrong_region, got %v", errObj["code"])
	}
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "region 'usw'") || !strings.Contains(msg, "https://api-usw.superserve.ai") {
		t.Errorf("message should name the region and its endpoint, got %q", msg)
	}
}

func TestAPIKeyAuth_WrongRegionKey_DefaultCellRegion(t *testing.T) {
	// Unset SANDBOX_ID_REGION means the pre-multi-region primary cell,
	// region "use" — a usw-tagged key must still get the redirect hint.
	t.Setenv("SANDBOX_ID_REGION", "")
	r := newAuthTestRouter(newUnreachablePool(t))

	code, errObj := doAuthRequest(t, r, "ss_live_usw_dGVzdHJhbmRvbQ")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
	if errObj["code"] != "wrong_region" {
		t.Errorf("expected code=wrong_region, got %v", errObj["code"])
	}
}

func TestAPIKeyAuth_WrongRegionKey_UseKeyOnUswCell(t *testing.T) {
	// The primary cell predates the region scheme and lives at the bare api
	// hostname — a use-tagged key misrouted to the usw cell must be pointed
	// at https://api.superserve.ai, not a derived api-use that doesn't exist.
	t.Setenv("SANDBOX_ID_REGION", "usw")
	r := newAuthTestRouter(newUnreachablePool(t))

	code, errObj := doAuthRequest(t, r, "ss_live_use_dGVzdHJhbmRvbQ")
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
	if errObj["code"] != "wrong_region" {
		t.Errorf("expected code=wrong_region, got %v", errObj["code"])
	}
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "region 'use'") || !strings.Contains(msg, "(https://api.superserve.ai)") {
		t.Errorf("message should point at the bare canonical endpoint, got %q", msg)
	}
	if strings.Contains(msg, "api-use") {
		t.Errorf("message must not reference the nonexistent api-use host, got %q", msg)
	}
}

func TestAPIKeyAuth_LookupFailureStaysGeneric(t *testing.T) {
	t.Setenv("SANDBOX_ID_REGION", "use")
	r := newAuthTestRouter(newUnreachablePool(t))

	cases := []struct {
		name string
		key  string
	}{
		{"same-region key not in DB", "ss_live_use_dGVzdHJhbmRvbQ"},
		{"legacy key", "ss_live_dGVzdHJhbmRvbQ"},
		// Legacy randoms are base64url and may contain underscores; "abc"
		// parses as a region but is not in knownRegions, so no hint.
		{"legacy key with coincidental underscore segments", "ss_live_abc_ZGVm_NDU2"},
		// "euw" could be a real region one day, but until it lands in
		// knownRegions the hint is suppressed — the accepted tradeoff for
		// never pointing legacy-key users at endpoints that do not exist.
		{"unknown-region prefix", "ss_live_euw_dGVzdHJhbmRvbQ"},
		{"unparseable key", "not-a-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, errObj := doAuthRequest(t, r, tc.key)
			if code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", code)
			}
			if errObj["code"] != "auth_failed" {
				t.Errorf("expected code=auth_failed, got %v", errObj["code"])
			}
			if errObj["message"] != "Invalid or missing X-API-Key header." {
				t.Errorf("expected the generic 401 message, got %v", errObj["message"])
			}
		})
	}
}

func TestAPIKeyRegion(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{"ss_live_usw_dGVzdA", "usw"},
		{"ss_live_use_dGVzdA", "use"},
		{"ss_live_dGVzdA", ""},                    // legacy: no region segment
		{"ss_live_ABC_def", ""},                   // uppercase: not a region shape
		{"ss_live__abc", ""},                      // empty region segment
		{"ss_live_usw_", ""},                      // empty random
		{"ss_live_aaaaaaaaaaaaaaaaaa_dGVzdA", ""}, // 18 chars, over the cap
		{"sk-something", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := apiKeyRegion(tc.key); got != tc.want {
			t.Errorf("apiKeyRegion(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RequestLogger middleware tests
// ---------------------------------------------------------------------------

func TestRequestLogger_DoesNotBreakResponse(t *testing.T) {
	r := gin.New()
	r.Use(RequestLogger())
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ok", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequestLogger_LogsQueryParams(t *testing.T) {
	r := gin.New()
	r.Use(RequestLogger())
	r.GET("/search", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"q": c.Query("q")})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/search?q=test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ErrorHandler middleware tests
// ---------------------------------------------------------------------------

func TestErrorHandler_RecoversPanic(t *testing.T) {
	r := gin.New()
	r.Use(ErrorHandler())
	r.GET("/panic", func(c *gin.Context) {
		panic("test panic!")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected error object in response")
	}
	if errObj["code"] != "internal_error" {
		t.Errorf("expected code=internal_error, got %v", errObj["code"])
	}
}

func TestErrorHandler_PassesThrough(t *testing.T) {
	r := gin.New()
	r.Use(ErrorHandler())
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ok", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// SHA256 key hashing (unit test for the auth logic)
// ---------------------------------------------------------------------------

func TestAPIKeyHash(t *testing.T) {
	apiKey := "sk-test-" + uuid.New().String()
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:])

	if len(keyHash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars", len(keyHash))
	}

	// Same key produces same hash.
	hash2 := sha256.Sum256([]byte(apiKey))
	keyHash2 := hex.EncodeToString(hash2[:])
	if keyHash != keyHash2 {
		t.Error("same key should produce same hash")
	}

	// Different key produces different hash.
	hash3 := sha256.Sum256([]byte("sk-different"))
	keyHash3 := hex.EncodeToString(hash3[:])
	if keyHash == keyHash3 {
		t.Error("different keys should produce different hashes")
	}
}
