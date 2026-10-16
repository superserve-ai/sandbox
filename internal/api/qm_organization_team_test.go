package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestQMTeamRequestDiagnostics(t *testing.T) {
	var output bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&output)
	t.Cleanup(func() { log.Logger = previous })
	const org = "20000000-0000-4000-8000-000000000001"
	const route = "/internal/qm/organizations/:qm_org_id/team"
	for _, tc := range []struct {
		method string
		status int
	}{
		{http.MethodGet, 200}, {http.MethodPost, 200},
		{http.MethodGet, 401}, {http.MethodPost, 401},
		{http.MethodGet, 500}, {http.MethodPost, 500},
		{http.MethodGet, 404},
	} {
		output.Reset()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(log.Logger.WithContext(c.Request.Context()))
		}, RequestLogger(), ErrorHandler())
		r.Handle(tc.method, route, TeamCreationPrivacy(), func(c *gin.Context) {
			if tc.status == 500 {
				panic("idempotency-key-marker")
			}
			c.AbortWithStatus(tc.status)
		})
		path := "/internal/qm/organizations/" + org + "/team"
		wantPath := route
		if tc.status == 404 {
			path += "/unknown"
			wantPath = "/internal/qm/organizations/[redacted]"
		}
		req := httptest.NewRequest(tc.method, path+"?idempotency_key=idempotency-key-marker-"+org, nil)
		response := httptest.NewRecorder()
		r.ServeHTTP(response, req)
		if response.Code != tc.status {
			t.Fatalf("%s: status %d, want %d", tc.method, response.Code, tc.status)
		}
		if strings.Contains(output.String(), org) || strings.Contains(output.String(), "idempotency-key-marker") {
			t.Fatal("request diagnostics exposed organization identity or idempotency key")
		}
		lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
		for _, line := range lines {
			var event map[string]any
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatal(err)
			}
			if event["path"] != wantPath {
				t.Fatalf("diagnostic path = %v, want %s", event["path"], wantPath)
			}
		}
	}
}

func TestQMTeamBodyDeadlinePrecedesAuthentication(t *testing.T) {
	cfg := qmTeamConfig{namespace: "qm-test", authority: "10000000-0000-4000-8000-000000000001", region: "use", token: strings.Repeat("t", 40)}
	for _, authenticated := range []bool{false, true} {
		w := &deadlineTeamWriter{ResponseRecorder: httptest.NewRecorder()}
		body := &deadlineTeamBody{writer: w}
		r := gin.New()
		r.Use(TeamCreationReadDeadline())
		r.POST("/internal/qm/organizations/:qm_org_id/team", qmOrganizationTeamHandler(nil, cfg))
		req := httptest.NewRequest("POST", "/internal/qm/organizations/20000000-0000-4000-8000-000000000001/team", body)
		if authenticated {
			req.Header.Set("X-QM-Team-Service-Token", cfg.token)
		}
		r.ServeHTTP(w, req)
		if len(w.deadlines) != 1 {
			t.Fatal("request body has no bounded read deadline")
		}
		if authenticated && (w.Code != 400 || body.reads != 1) {
			t.Fatal("stalled authenticated body was not rejected")
		}
		if !authenticated && (w.Code != 401 || body.reads != 0) {
			t.Fatal("unauthenticated body was read")
		}
	}
}

type qmTeamErrorQuery struct{ err error }

func (q qmTeamErrorQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	return qmTeamErrorRow{q.err}
}

type qmTeamErrorRow struct{ err error }

func (r qmTeamErrorRow) Scan(...any) error { return r.err }
func TestQMTeamAuthorityFailureIsNotConflictOrAbsence(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, errors.New("synthetic database unavailable")} {
		_, err := readQMTeam(context.Background(), qmTeamErrorQuery{failure}, qmTeamConfig{}, "org")
		if !errors.Is(err, failure) || errors.Is(err, errQMTeamConflict) || errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("transient failure misclassified", err)
		}
	}
	if _, err := readQMTeam(context.Background(), qmTeamErrorQuery{pgx.ErrNoRows}, qmTeamConfig{}, "org"); !errors.Is(err, errQMTeamConflict) {
		t.Fatal("missing authority must not authorize creation")
	}
}
