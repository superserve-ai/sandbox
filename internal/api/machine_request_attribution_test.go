package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/auth"
)

type loggingMachineResolver func(context.Context, string) (auth.CallerContext, error)

func (f loggingMachineResolver) ResolveMachineCredential(ctx context.Context, raw string) (auth.CallerContext, error) {
	return f(ctx, raw)
}

func TestMachineRequestAttributionRotationAndDenials(t *testing.T) {
	buf := new(bytes.Buffer)
	logger := zerolog.New(buf)
	caller := auth.CallerContext{
		PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), HostedTenantID: uuid.New(),
		Permissions: []auth.MachineOperation{auth.MachineOperationRead}, Policy: auth.NewMachinePolicy(auth.MachineOperationRead),
		Audience: "sandbox-api", ExpiresAt: time.Now().Add(time.Hour), RevocationGeneration: 1,
	}
	for _, tc := range []struct {
		name, route string
		err         error
		status      int
		outcome     string
	}{
		{"initial", "/sandboxes/:sandbox_id", nil, 204, "authenticated"},
		{"rotated", "/sandboxes/:sandbox_id", nil, 204, "authenticated"},
		{"ownership denial", "/sandboxes/:sandbox_id", nil, 403, "authenticated"},
		{"permission denial", "/settings", nil, 403, "authenticated"},
		{"revoked", "/sandboxes/:sandbox_id", pgx.ErrNoRows, 401, "invalid"},
		{"authority unavailable", "/sandboxes/:sandbox_id", ErrMachineAuthorityUnavailable, 503, "error"},
		{"lookup failed", "/sandboxes/:sandbox_id", errors.New("SYNTHETIC_LOOKUP_SECRET"), 401, "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			if tc.name == "rotated" {
				caller.CredentialID = uuid.New()
			}
			calls, handled := 0, false
			r := gin.New()
			r.Use(requestLogger(&logger), MachineCredentialAuth(loggingMachineResolver(func(context.Context, string) (auth.CallerContext, error) {
				calls++
				return caller, tc.err
			})), APIKeyAuth(nil))
			r.GET(tc.route, func(c *gin.Context) {
				handled = true
				c.Status(tc.status)
			})
			target := strings.ReplaceAll(tc.route, ":sandbox_id", uuid.NewString())
			req := httptest.NewRequest(http.MethodGet, target+"?secret=SYNTHETIC_QUERY_SECRET", nil)
			req.Header.Set("X-QM-Machine-Credential", "SYNTHETIC_CREDENTIAL_SECRET")
			req.Header.Set("X-Actor-User-Id", "SYNTHETIC_ACTOR_SECRET")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.status || calls != 1 || (handled && (tc.err != nil || tc.name == "permission denial")) {
				t.Fatalf("status=%d calls=%d handled=%t", w.Code, calls, handled)
			}
			e := lastRequestLog(t, buf)
			if e["auth_outcome"] != tc.outcome || e["route"] != tc.route {
				t.Fatal(e)
			}
			if tc.outcome == "authenticated" {
				for k, v := range map[string]any{"actor_type": "machine", "actor_id": caller.PrincipalID.String(), "credential_id": caller.CredentialID.String(), "team_id": caller.TeamID.String(), "attribution_status": "identified"} {
					if e[k] != v {
						t.Errorf("%s=%v want %v", k, e[k], v)
					}
				}
			} else if e["actor_id"] != nil || e["credential_id"] != nil || e["team_id"] != nil {
				t.Fatalf("failed verification acquired caller metadata: %v", e)
			}
			if tc.outcome == "error" && (e["actor_type"] != "unknown" || e["attribution_status"] != "error") {
				t.Fatal(e)
			}
			if e["user_id"] != nil || strings.Contains(buf.String(), "SYNTHETIC") {
				t.Fatal("unverified human or sensitive content in logs")
			}
		})
	}
}
