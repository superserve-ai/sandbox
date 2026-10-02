package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

func restrictedCompute(t *testing.T, team uuid.UUID) *abuse.ComputeEvaluator {
	t.Helper()
	return restrictedComputeInMode(t, team, "enforce")
}

func restrictedComputeInMode(t *testing.T, team uuid.UUID, mode string) *abuse.ComputeEvaluator {
	t.Helper()
	path := filepath.Join(t.TempDir(), "compute.json")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"mode":%q,"restrictions":[{"subject_type":"team","subject_id":%q,"actions":["create","resume"]}]}`, mode, team)), 0600); err != nil {
		t.Fatal(err)
	}
	source := abuse.NewConfigComputeSource(path, nil, nil)
	source.Refresh(context.Background())
	return &abuse.ComputeEvaluator{Source: source}
}

func TestComputeDenialBeforeLifecycleWork(t *testing.T) {
	for _, route := range []string{"create", "resume", "activate", "files"} {
		t.Run(route, func(t *testing.T) {
			team, id := uuid.New(), uuid.New()
			reads := 0
			mock := &mockDBTX{queryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
				reads++
				if route == "create" {
					t.Fatal("denied request reached database")
				}
				if !strings.Contains(query, "SELECT") {
					t.Fatal("denied request attempted mutation")
				}
				return sandboxRow(db.Sandbox{ID: id, TeamID: team, Status: db.SandboxStatusPaused})
			}}
			h := &Handlers{DB: db.New(mock), ComputeRestrictions: restrictedCompute(t, team), Config: &config.Config{}}
			var req *http.Request
			switch route {
			case "create":
				req = createSandboxReq(`{"name":"example"}`)
			case "resume":
				req = httptest.NewRequest("POST", "/sandboxes/"+id.String()+"/resume", nil)
			case "activate":
				req = activateRequest(id.String())
			case "files":
				req = httptest.NewRequest("GET", "/sandboxes/"+id.String()+"/files", nil)
			}
			w := httptest.NewRecorder()
			setupTestRouter(h, team.String()).ServeHTTP(w, req)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"code":"abuse_denied"`) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if strings.Contains(w.Body.String(), team.String()) {
				t.Fatal("response leaked subject")
			}
			if route != "create" && reads != 1 {
				t.Fatalf("reads=%d", reads)
			}
		})
	}
}

func TestComputeRestrictionExplicitResumeStateResponses(t *testing.T) {
	previousWindow := pausingSettleWindow
	t.Cleanup(func() { pausingSettleWindow = previousWindow })

	for _, tc := range []struct {
		name     string
		statuses []db.SandboxStatus
		want     int
		code     string
	}{
		{name: "active", statuses: []db.SandboxStatus{db.SandboxStatusActive}, want: http.StatusConflict, code: "conflict"},
		{name: "missing", want: http.StatusNotFound, code: "not_found"},
		{name: "pausing", statuses: []db.SandboxStatus{db.SandboxStatusPausing}, want: http.StatusConflict, code: "conflict"},
		{name: "pause reverted", statuses: []db.SandboxStatus{db.SandboxStatusPausing, db.SandboxStatusActive}, want: http.StatusConflict, code: "conflict"},
		{name: "pause completed", statuses: []db.SandboxStatus{db.SandboxStatusPausing, db.SandboxStatusPaused}, want: http.StatusForbidden, code: "abuse_denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pausingSettleWindow = time.Second
			if tc.name == "pausing" {
				pausingSettleWindow = 0
			}
			team, id := uuid.New(), uuid.New()
			reads := 0
			mock := &mockDBTX{queryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
				if !strings.Contains(query, "-- name: GetSandbox :one") {
					t.Fatalf("request attempted work before state response: %s", query)
				}
				reads++
				if len(tc.statuses) == 0 {
					return notFoundRow()
				}
				status := tc.statuses[min(reads-1, len(tc.statuses)-1)]
				return sandboxRow(db.Sandbox{ID: id, TeamID: team, Status: status})
			}}
			h := &Handlers{DB: db.New(mock), ComputeRestrictions: restrictedCompute(t, team)}
			w := httptest.NewRecorder()
			setupTestRouter(h, team.String()).ServeHTTP(w, resumeRequest(id.String()))
			if w.Code != tc.want || errorCode(parseJSON(t, w)) != tc.code {
				t.Fatalf("response = %d %s, want %d %s", w.Code, w.Body, tc.want, tc.code)
			}
			if reads == 0 || (len(tc.statuses) > 1 && reads < 2) {
				t.Fatalf("state reads = %d, want to observe the target state", reads)
			}
		})
	}
}

func TestComputeRestrictionAllowsAlreadyActive(t *testing.T) {
	team, id := uuid.New(), uuid.New()
	h := &Handlers{DB: db.New(&mockDBTX{queryRowFn: func(context.Context, string, ...any) pgx.Row {
		return sandboxRow(db.Sandbox{ID: id, TeamID: team, Status: db.SandboxStatusActive})
	}}), Config: &config.Config{}, ComputeRestrictions: restrictedCompute(t, team)}
	w := httptest.NewRecorder()
	setupTestRouter(h, team.String()).ServeHTTP(w, activateRequest(id.String()))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

type computeDecisionCapture struct {
	telemetry.Recorder
	decisions [][4]string
}

func (r *computeDecisionCapture) RecordComputeDecision(_ context.Context, action, mode, outcome, subject string) {
	r.decisions = append(r.decisions, [4]string{action, mode, outcome, subject})
}

func (*computeDecisionCapture) RecordComputeRefresh(context.Context, string) {}

func TestComputeObserveAllowsLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
		run    func(*testing.T, func(*Handlers, uuid.UUID))
	}{
		{name: "create", action: "create", run: testCreateSandboxSuccess},
		{name: "resume", action: "resume", run: testResumeSandboxLegacyPolicyToleratesOldVMD},
		{name: "activate paused", action: "resume", run: testActivateSandboxPausedResumesAndReturns200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &computeDecisionCapture{Recorder: telemetry.NewNoopRecorder()}
			previous := currentTelemetryRecorder()
			SetTelemetryRecorder(rec)
			t.Cleanup(func() { SetTelemetryRecorder(previous) })

			tc.run(t, func(h *Handlers, team uuid.UUID) {
				h.ComputeRestrictions = restrictedComputeInMode(t, team, "observe")
			})

			want := [4]string{tc.action, "observe", "would_deny", "team"}
			if len(rec.decisions) != 1 || rec.decisions[0] != want {
				t.Fatalf("compute decisions = %v, want exactly [%v]", rec.decisions, want)
			}
		})
	}
}
