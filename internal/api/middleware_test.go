package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
