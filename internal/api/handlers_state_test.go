package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/state"
)

// newStateHandlers wires a real LocalProvider (the reference state backend) with
// a mock DB that owns one sandbox, and pre-mounts its state so checkpoints have
// something to snapshot.
func newStateHandlers(t *testing.T) (*Handlers, uuid.UUID) {
	t.Helper()
	provider, err := state.NewLocalProvider(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sandboxID := uuid.New()
	// Create the sandbox's durable state (current dir) so it can be checkpointed.
	if _, err := provider.Mount(context.Background(), sandboxID.String(), "/state"); err != nil {
		t.Fatal(err)
	}
	mock := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		if strings.Contains(sql, "FROM sandbox") {
			return sandboxRow(db.Sandbox{ID: sandboxID, Status: db.SandboxStatusActive, CreatedAt: time.Now()})
		}
		return notFoundRow()
	}}
	return &Handlers{State: provider, DB: db.New(mock)}, sandboxID
}

func stateReq(method, path, body string) *http.Request {
	return httptest.NewRequest(method, path, strings.NewReader(body))
}

func TestCheckpointBranchRollbackLifecycle(t *testing.T) {
	h, sid := newStateHandlers(t)
	team := uuid.New().String()
	base := "/sandboxes/" + sid.String()

	// Checkpoint.
	w := httptest.NewRecorder()
	setupTestRouter(h, team).ServeHTTP(w, stateReq(http.MethodPost, base+"/checkpoints", `{"name":"cp1"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("checkpoint should 201, got %d: %s", w.Code, w.Body.String())
	}

	// List shows it.
	w = httptest.NewRecorder()
	setupTestRouter(h, team).ServeHTTP(w, stateReq(http.MethodGet, base+"/checkpoints", ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "cp1") {
		t.Fatalf("list should include cp1: %d %s", w.Code, w.Body.String())
	}

	// Branch from it (the Actor fork primitive).
	w = httptest.NewRecorder()
	setupTestRouter(h, team).ServeHTTP(w, stateReq(http.MethodPost, base+"/branches", `{"name":"b1","from_checkpoint":"cp1"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("branch should 201, got %d: %s", w.Code, w.Body.String())
	}

	// Rollback to it.
	w = httptest.NewRecorder()
	setupTestRouter(h, team).ServeHTTP(w, stateReq(http.MethodPost, base+"/rollback", `{"checkpoint":"cp1"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("rollback should 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCheckpointBranchMissingCheckpoint(t *testing.T) {
	h, sid := newStateHandlers(t)
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w,
		stateReq(http.MethodPost, "/sandboxes/"+sid.String()+"/branches", `{"name":"b","from_checkpoint":"nope"}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("branch from missing checkpoint should 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStateDisabledWhenNoProvider(t *testing.T) {
	h := &Handlers{DB: db.New(&mockDBTX{})} // State nil
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w,
		stateReq(http.MethodPost, "/sandboxes/"+uuid.New().String()+"/checkpoints", `{"name":"x"}`))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("nil state provider should 501, got %d", w.Code)
	}
}

func TestCheckpointForeignSandbox404(t *testing.T) {
	provider, _ := state.NewLocalProvider(t.TempDir())
	// DB owns no sandbox → GetSandbox returns no rows → 404.
	h := &Handlers{State: provider, DB: db.New(&mockDBTX{queryRowFn: func(context.Context, string, ...any) pgx.Row {
		return notFoundRow()
	}})}
	w := httptest.NewRecorder()
	setupTestRouter(h, uuid.New().String()).ServeHTTP(w,
		stateReq(http.MethodPost, "/sandboxes/"+uuid.New().String()+"/checkpoints", `{"name":"x"}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("checkpoint on unowned sandbox should 404, got %d", w.Code)
	}
}
