package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

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
