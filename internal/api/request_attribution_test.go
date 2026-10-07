package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func captureRequestLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = old })
	return &buf
}

func lastRequestLog(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var result map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) == nil && entry["event_type"] == "request" {
			result = entry
		}
	}
	if result == nil {
		t.Fatalf("no request log: %s", buf)
	}
	return result
}

func TestRequestAttributionKeyIsNotCreator(t *testing.T) {
	buf := captureRequestLogs(t)
	creator, team, key := uuid.New(), uuid.NewString(), uuid.NewString()
	entry := apiKeyCacheEntry{id: key, teamID: team, createdBy: pgtype.UUID{Bytes: creator, Valid: true}}
	for _, name := range []string{"example-key", consoleImpersonationKeyName} {
		t.Run(name, func(t *testing.T) {
			entry.name = name
			r := gin.New()
			r.Use(RequestLogger())
			r.GET("/sandboxes/:sandbox_id", func(c *gin.Context) {
				setAPIKeyContext(c, entry)
				// Business attribution is deliberately unchanged.
				_, hasActor := c.Get("actor_id")
				if hasActor != (name != consoleImpersonationKeyName) {
					t.Fatal("business actor changed")
				}
				c.Status(http.StatusForbidden)
			})
			req := httptest.NewRequest("GET", "/sandboxes/"+uuid.NewString(), nil)
			req.Header.Set("X-Actor-User-Id", creator.String())
			r.ServeHTTP(httptest.NewRecorder(), req)
			got := lastRequestLog(t, buf)
			for field, want := range map[string]any{"actor_type": "api_key", "actor_id": key, "credential_id": key, "api_key_id": key, "team_id": team, "status": float64(403), "auth_outcome": "authenticated", "attribution_status": "identified", "route": "/sandboxes/:sandbox_id"} {
				if got[field] != want {
					t.Errorf("%s = %v, want %v", field, got[field], want)
				}
			}
			if _, ok := got["user_id"]; ok {
				t.Fatal("key creator or public actor header became verified human")
			}
		})
	}
}

func TestRequestAttributionAuthOutcomes(t *testing.T) {
	buf := captureRequestLogs(t)
	t.Setenv("OPERATOR_API_TOKEN", "test-operator-secret")
	t.Setenv("INTERNAL_API_TOKEN", "test-internal-secret")
	human := uuid.NewString()
	for _, tc := range []struct {
		name, bearer, key, outcome, actor, attribution string
		middleware                                     []gin.HandlerFunc
	}{
		{"public", "", "", "not_evaluated", "unauthenticated", "unavailable", nil},
		{"missing key", "", "", "missing", "unauthenticated", "unavailable", []gin.HandlerFunc{APIKeyAuth(nil)}},
		{"key lookup failure", "", "test-synthetic-key", "error", "unknown", "error", []gin.HandlerFunc{APIKeyAuth(newUnreachablePool(t))}},
		{"missing operator", "", "", "missing", "unauthenticated", "unavailable", []gin.HandlerFunc{OperatorAuth()}},
		{"invalid operator", "Bearer test-wrong-secret", "", "invalid", "unauthenticated", "unavailable", []gin.HandlerFunc{OperatorAuth(), InternalActorFromHeader()}},
		{"operator", "Bearer test-operator-secret", "", "authenticated", "operator", "unavailable", []gin.HandlerFunc{OperatorAuth()}},
		{"delegated human", "Bearer test-internal-secret", "", "authenticated", "human", "identified", []gin.HandlerFunc{InternalAuth(), InternalActorFromHeader()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			r := gin.New()
			r.Use(RequestLogger())
			r.Use(tc.middleware...)
			r.GET("/test", func(c *gin.Context) { c.Status(http.StatusForbidden) })
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tc.bearer)
			req.Header.Set("X-API-Key", tc.key)
			req.Header.Set("X-Actor-User-Id", human)
			r.ServeHTTP(httptest.NewRecorder(), req)
			got := lastRequestLog(t, buf)
			if got["auth_outcome"] != tc.outcome || got["actor_type"] != tc.actor || got["attribution_status"] != tc.attribution {
				t.Fatalf("unexpected identity: %v", got)
			}
			if tc.actor == "human" {
				if got["actor_id"] != human || got["user_id"] != human {
					t.Fatal(got)
				}
			} else if _, ok := got["user_id"]; ok {
				t.Fatal("untrusted human assertion logged")
			}
			if strings.Contains(buf.String(), "test-operator-secret") || strings.Contains(buf.String(), "test-synthetic-key") {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestRequestAttributionRedactsTargetsAndPanics(t *testing.T) {
	buf := captureRequestLogs(t)
	const secret = "SYNTHETIC_PRIVATE_MARKER"
	const uuidSecretName = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	r := gin.New()
	r.Use(RequestLogger(), ErrorHandler())
	r.POST("/secrets/:name", func(c *gin.Context) { c.Status(204) })
	r.GET("/panic", func(c *gin.Context) { panic(secret) })
	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{"POST", "/secrets/" + secret + "?token=" + secret, 204},
		{"POST", "/secrets/" + uuidSecretName, 204},
		{"GET", "/unknown/" + secret + "?token=" + secret, 404},
		{"GET", "/panic?key=" + secret, 500},
	} {
		buf.Reset()
		req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(secret))
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Cookie", "session="+secret)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatal(w.Code)
		}
		if strings.Contains(buf.String(), secret) || strings.Contains(buf.String(), uuidSecretName) {
			t.Fatalf("secret in logs: %s", buf)
		}
		got := lastRequestLog(t, buf)
		if got["status"] != float64(tc.status) || got["body_size"] != float64(w.Body.Len()) && tc.status != 204 && tc.status != 404 {
			t.Fatal(got)
		}
		if _, ok := got["latency"]; !ok {
			t.Fatal("latency missing")
		}
	}
}

func TestRequestAttributionIncludesGlobalRateLimitRejection(t *testing.T) {
	buf := captureRequestLogs(t)
	r := SetupRouter(t.Context(), &Handlers{}, nil)
	for n := 0; n < 1000; n++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/unknown", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got := lastRequestLog(t, buf)
			if got["status"] != float64(429) || got["auth_outcome"] != "not_evaluated" {
				t.Fatal(got)
			}
			return
		}
	}
	t.Fatal("rate limit did not reject test burst")
}

func TestRequestAttributionPublicSandboxIDs(t *testing.T) {
	buf := captureRequestLogs(t)
	id := uuid.NewString()
	r := gin.New()
	r.Use(RequestLogger())
	r.POST("/sandboxes/:sandbox_id/pause", func(c *gin.Context) { c.Status(http.StatusForbidden) })
	for _, raw := range []string{id, "sb-use-" + id, "PRIVATE_MARKER"} {
		buf.Reset()
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/sandboxes/"+raw+"/pause", nil))
		event := lastRequestLog(t, buf)
		if raw == "PRIVATE_MARKER" {
			if event["sandbox_id"] != nil || strings.Contains(buf.String(), raw) {
				t.Fatal("unvalidated sandbox target leaked")
			}
		} else if event["sandbox_id"] != id || event["path"] != "/sandboxes/"+id+"/pause" {
			t.Fatalf("lost sandbox target: %v", event)
		}
		if event["route"] != "/sandboxes/:sandbox_id/pause" || event["auth_outcome"] != "not_evaluated" {
			t.Fatalf("target became identity or changed grouping: %v", event)
		}
	}
}
