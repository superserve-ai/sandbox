package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

type hostDrainRows struct {
	items []db.ClaimHostDrainSandboxesRow
	idx   int
}

func newHostDrainRows(items []db.ClaimHostDrainSandboxesRow) *hostDrainRows {
	return &hostDrainRows{items: items, idx: -1}
}

func (r *hostDrainRows) Next() bool {
	r.idx++
	return r.idx < len(r.items)
}

func (r *hostDrainRows) Scan(dest ...any) error {
	row := r.items[r.idx]
	*dest[0].(*uuid.UUID) = row.ID
	*dest[1].(*uuid.UUID) = row.TeamID
	*dest[2].(*string) = row.Name
	*dest[3].(*pgtype.UUID) = row.SnapshotID
	*dest[4].(*string) = row.HostID
	return nil
}

func (r *hostDrainRows) Close()                                       {}
func (r *hostDrainRows) Err() error                                   { return nil }
func (r *hostDrainRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *hostDrainRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *hostDrainRows) Values() ([]any, error)                       { return nil, nil }
func (r *hostDrainRows) RawValues() [][]byte                          { return nil }
func (r *hostDrainRows) Conn() *pgx.Conn                              { return nil }

type hostListRows struct {
	items []db.Host
	idx   int
}

func newHostListRows(items []db.Host) *hostListRows {
	return &hostListRows{items: items, idx: -1}
}

func (r *hostListRows) Next() bool {
	r.idx++
	return r.idx < len(r.items)
}

func (r *hostListRows) Scan(dest ...any) error {
	row := r.items[r.idx]
	*dest[0].(*string) = row.ID
	*dest[1].(*string) = row.VmdAddr
	*dest[2].(*string) = row.ProxyAddr
	*dest[3].(*string) = row.Region
	*dest[4].(*string) = row.Status
	*dest[5].(*int32) = row.CapacityMemoryMib
	*dest[6].(*int32) = row.CapacityVcpus
	*dest[7].(*pgtype.Timestamptz) = row.LastHeartbeatAt
	*dest[8].(*time.Time) = row.CreatedAt
	*dest[9].(*time.Time) = row.UpdatedAt
	return nil
}

func (r *hostListRows) Close()                                       {}
func (r *hostListRows) Err() error                                   { return nil }
func (r *hostListRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *hostListRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *hostListRows) Values() ([]any, error)                       { return nil, nil }
func (r *hostListRows) RawValues() [][]byte                          { return nil }
func (r *hostListRows) Conn() *pgx.Conn                              { return nil }

func hostDrainStringRow(value string) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*string) = value
		return nil
	}}
}

func hostDrainCountRow(value int64) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*int64) = value
		return nil
	}}
}

func hostDrainHostRow(host db.Host) pgx.Row {
	return &mockRow{scanFn: func(dest ...any) error {
		*dest[0].(*string) = host.ID
		*dest[1].(*string) = host.VmdAddr
		*dest[2].(*string) = host.ProxyAddr
		*dest[3].(*string) = host.Region
		*dest[4].(*string) = host.Status
		*dest[5].(*int32) = host.CapacityMemoryMib
		*dest[6].(*int32) = host.CapacityVcpus
		*dest[7].(*pgtype.Timestamptz) = host.LastHeartbeatAt
		*dest[8].(*time.Time) = host.CreatedAt
		*dest[9].(*time.Time) = host.UpdatedAt
		return nil
	}}
}

func TestDrainHostPausesWithMaintenanceTrigger(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "test-internal-token")

	hostID := "staging-host"
	row := db.ClaimHostDrainSandboxesRow{
		ID:     uuid.New(),
		TeamID: uuid.New(),
		Name:   "running-sandbox",
		HostID: hostID,
	}
	var (
		pauseCalls       atomic.Int32
		finalizeTrigger  string
		finalizeSQL      string
		beginDrainSQL    string
		drainCountSQL    string
		claimSQL         string
		claimHost        string
		claimBatch       int32
		beginDrainCalls  atomic.Int32
		activateSQLCalls atomic.Int32
	)
	activityAction := make(chan string, 1)

	mock := &mockDBTX{
		queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
			if !strings.Contains(sql, "ClaimHostDrainSandboxes") {
				t.Errorf("unexpected Query SQL: %s", sql)
				return emptyRows{}, nil
			}
			claimSQL = sql
			claimHost = args[0].(string)
			claimBatch = args[1].(int32)
			return newHostDrainRows([]db.ClaimHostDrainSandboxesRow{row}), nil
		},
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "SET status = 'draining'"):
				beginDrainCalls.Add(1)
				beginDrainSQL = sql
				return hostDrainStringRow("draining")
			case strings.Contains(sql, "SET status = 'active', updated_at"):
				activateSQLCalls.Add(1)
				return hostDrainStringRow("active")
			case strings.Contains(sql, "upserted AS") && strings.Contains(sql, "runtime_checkpoint"):
				finalizeSQL = sql
				finalizeTrigger = args[5].(string)
				return finalizePauseRow(uuid.New())
			case strings.Contains(sql, "snapshot_operation_id IS NOT NULL"):
				drainCountSQL = sql
				return hostDrainCountRow(0)
			case strings.Contains(sql, "INSERT INTO activity"):
				activityAction <- args[8].(string)
				return activityRow()
			default:
				t.Errorf("unexpected QueryRow SQL: %s", sql)
				return errorRow(pgx.ErrNoRows)
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
	}
	vmd := &stubVMD{pauseFn: func(_ context.Context, id, _ string) (string, string, error) {
		pauseCalls.Add(1)
		if id != row.ID.String() {
			t.Errorf("PauseInstance id = %q, want %q", id, row.ID)
		}
		return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := SetupRouter(ctx, h, nil)
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/drain", nil)
	req.Header.Set("Authorization", "Bearer test-internal-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := parseJSON(t, w)
	if body["host_id"] != hostID || body["status"] != "draining" || body["paused_count"] != float64(1) {
		t.Fatalf("unexpected response: %#v", body)
	}
	if got := pauseCalls.Load(); got != 1 {
		t.Fatalf("PauseInstance calls = %d, want 1", got)
	}
	if got := beginDrainCalls.Load(); got != 1 {
		t.Fatalf("BeginHostDrain calls = %d, want 1", got)
	}
	if got := activateSQLCalls.Load(); got != 0 {
		t.Fatalf("drain must not reactivate host; activate calls = %d", got)
	}
	if claimHost != hostID || claimBatch != hostDrainBatchSize {
		t.Fatalf("claim args = (%q, %d), want (%q, %d)", claimHost, claimBatch, hostID, hostDrainBatchSize)
	}
	for _, required := range []string{
		"draining_host AS MATERIALIZED",
		"h.status = 'draining'",
		"FOR SHARE",
		"JOIN draining_host",
	} {
		if !strings.Contains(claimSQL, required) {
			t.Errorf("ClaimHostDrainSandboxes SQL missing %q:\n%s", required, claimSQL)
		}
	}
	if finalizeTrigger != "host_drain" {
		t.Fatalf("FinalizePause trigger = %q, want host_drain", finalizeTrigger)
	}
	for _, required := range []string{
		"locked_host AS MATERIALIZED",
		"FOR SHARE OF h",
		"target AS MATERIALIZED",
		"FOR UPDATE OF s",
		"upserted.snapshot_trigger = 'host_drain'",
		"target.host_status = 'draining'",
		"THEN NULL",
	} {
		if !strings.Contains(finalizeSQL, required) {
			t.Errorf("FinalizePause SQL missing %q:\n%s", required, finalizeSQL)
		}
	}
	if !strings.Contains(beginDrainSQL, "UPDATE sandbox") ||
		!strings.Contains(beginDrainSQL, "SET auto_delete_at = NULL") {
		t.Fatalf("BeginHostDrain must clear pre-existing auto-delete deadlines:\n%s", beginDrainSQL)
	}
	if !strings.Contains(drainCountSQL, "snapshot.status IN ('creating', 'deleting')") ||
		!strings.Contains(drainCountSQL, "template_build.status IN ('building', 'snapshotting')") {
		t.Fatalf("drain convergence must include host-local snapshot/build work:\n%s", drainCountSQL)
	}
	select {
	case action := <-activityAction:
		if action != "host_drained" {
			t.Fatalf("activity action = %q, want host_drained", action)
		}
	case <-time.After(time.Second):
		t.Fatal("host-drain activity was not recorded")
	}
}

func TestDrainHostPauseFailureLeavesHostDraining(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "test-internal-token")

	hostID := "staging-host"
	row := db.ClaimHostDrainSandboxesRow{
		ID:     uuid.New(),
		TeamID: uuid.New(),
		Name:   "unpausable-sandbox",
		HostID: hostID,
	}
	var (
		pauseCalls      atomic.Int32
		reactivatedHost atomic.Bool
	)
	mock := &mockDBTX{
		queryFn: func(context.Context, string, ...any) (pgx.Rows, error) {
			return newHostDrainRows([]db.ClaimHostDrainSandboxesRow{row}), nil
		},
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "SET status = 'draining'"):
				return hostDrainStringRow("draining")
			case strings.Contains(sql, "SET status = 'active', updated_at"):
				reactivatedHost.Store(true)
				return hostDrainStringRow("active")
			case strings.Contains(sql, "FROM sandbox_active_interval"):
				return notFoundRow()
			default:
				return errorRow(pgx.ErrNoRows)
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
	}
	vmd := &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
		pauseCalls.Add(1)
		return "", "", context.DeadlineExceeded
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := SetupRouter(ctx, h, nil)
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/drain", nil)
	req.Header.Set("Authorization", "Bearer test-internal-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504; body: %s", w.Code, w.Body.String())
	}
	if got := pauseCalls.Load(); got != 2 {
		t.Fatalf("PauseInstance calls = %d, want 2 (bounded retry)", got)
	}
	if reactivatedHost.Load() {
		t.Fatal("failed drain must leave the host draining")
	}
}

func TestActivateHostRequiresInternalAuth(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "test-internal-token")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := SetupRouter(ctx, &Handlers{}, nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/internal/hosts/staging-host/activate", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
}

func TestActivateHostRequiresDrainingHostWithNoLifecycleWork(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "test-internal-token")

	hostID := "staging-host"
	var activateSQL string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			if strings.Contains(sql, "ActivateDrainedHost") {
				activateSQL = sql
				return hostDrainStringRow("active")
			}
			t.Fatalf("unexpected QueryRow SQL: %s", sql)
			return errorRow(pgx.ErrNoRows)
		},
	}
	h := &Handlers{DB: db.New(mock)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := SetupRouter(ctx, h, nil)
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/activate", nil)
	req.Header.Set("Authorization", "Bearer test-internal-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	for _, required := range []string{
		"target_host AS MATERIALIZED",
		"h.status IN ('draining', 'active')",
		"FOR UPDATE",
		"target.status = 'draining'",
		"s.snapshot_operation_id IS NOT NULL",
		"saved.status IN ('creating', 'deleting')",
		"build.status IN ('building', 'snapshotting')",
		"SELECT status FROM target_host WHERE status = 'active'",
	} {
		if !strings.Contains(activateSQL, required) {
			t.Errorf("ActivateDrainedHost SQL missing %q:\n%s", required, activateSQL)
		}
	}
}

func TestActivateHostGuardFailureReturnsConflictForExistingHost(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "test-internal-token")

	hostID := "staging-host"
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "ActivateDrainedHost"):
				return errorRow(pgx.ErrNoRows)
			case strings.Contains(sql, "FROM host WHERE id"):
				now := time.Now()
				return hostDrainHostRow(db.Host{ID: hostID, Status: "draining", CreatedAt: now, UpdatedAt: now})
			default:
				t.Fatalf("unexpected QueryRow SQL: %s", sql)
				return errorRow(pgx.ErrNoRows)
			}
		},
	}
	h := &Handlers{DB: db.New(mock)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	router := SetupRouter(ctx, h, nil)
	req := httptest.NewRequest(http.MethodPost, "/internal/hosts/"+hostID+"/activate", nil)
	req.Header.Set("Authorization", "Bearer test-internal-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", w.Code, w.Body.String())
	}
	if body := parseJSON(t, w); body["error"].(map[string]any)["code"] != "host_not_drained" {
		t.Fatalf("unexpected response: %#v", body)
	}
}

func TestReaperDeclarativelyDrainsHostsWithWorkerDedupe(t *testing.T) {
	hostID := "declarative-drain-host"
	row := db.ClaimHostDrainSandboxesRow{
		ID:     uuid.New(),
		TeamID: uuid.New(),
		Name:   "running-sandbox",
		HostID: hostID,
	}
	pauseStarted := make(chan struct{}, 1)
	releasePause := make(chan struct{})
	var (
		listCalls  atomic.Int32
		claimCalls atomic.Int32
		pauseCalls atomic.Int32
	)
	mock := &mockDBTX{
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			switch {
			case strings.Contains(sql, "FROM host\nORDER BY created_at"):
				listCalls.Add(1)
				now := time.Now()
				return newHostListRows([]db.Host{{
					ID: hostID, Status: "draining", VmdAddr: "vmd", ProxyAddr: "proxy",
					Region: "test", CapacityMemoryMib: 1024, CapacityVcpus: 1,
					CreatedAt: now, UpdatedAt: now,
				}}), nil
			case strings.Contains(sql, "ClaimHostDrainSandboxes"):
				claimCalls.Add(1)
				return newHostDrainRows([]db.ClaimHostDrainSandboxesRow{row}), nil
			default:
				t.Errorf("unexpected Query SQL: %s", sql)
				return emptyRows{}, nil
			}
		},
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "upserted AS") && strings.Contains(sql, "runtime_checkpoint"):
				return finalizePauseRow(uuid.New())
			case strings.Contains(sql, "snapshot_operation_id IS NOT NULL"):
				return hostDrainCountRow(0)
			case strings.Contains(sql, "INSERT INTO activity"):
				return activityRow()
			default:
				t.Errorf("unexpected QueryRow SQL: %s", sql)
				return errorRow(pgx.ErrNoRows)
			}
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
	}
	vmd := &stubVMD{pauseFn: func(context.Context, string, string) (string, string, error) {
		pauseCalls.Add(1)
		pauseStarted <- struct{}{}
		<-releasePause
		return "/snapshots/vmstate.snap", "/snapshots/mem.snap", nil
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h.scheduleDrainingHostWorkers(ctx)
	select {
	case <-pauseStarted:
	case <-time.After(time.Second):
		t.Fatal("declarative drain worker did not start")
	}

	// Wait until the discovery scan itself has exited, then run another tick
	// while the slow host worker is still active. It must discover the host but
	// dedupe the worker instead of issuing a second claim/pause.
	deadline := time.Now().Add(time.Second)
	for {
		h.hostDrainMu.Lock()
		scanRunning := h.hostDrainScan
		h.hostDrainMu.Unlock()
		if !scanRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("host drain scan did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	h.scheduleDrainingHostWorkers(ctx)
	deadline = time.Now().Add(time.Second)
	for listCalls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(releasePause)

	deadline = time.Now().Add(time.Second)
	for {
		h.hostDrainMu.Lock()
		workers := len(h.hostDrainWorkers)
		h.hostDrainMu.Unlock()
		if workers == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("host drain worker did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if got := listCalls.Load(); got < 2 {
		t.Fatalf("ListHosts calls = %d, want at least 2 ticks", got)
	}
	if got := claimCalls.Load(); got != 1 {
		t.Fatalf("ClaimHostDrainSandboxes calls = %d, want 1", got)
	}
	if got := pauseCalls.Load(); got != 1 {
		t.Fatalf("PauseInstance calls = %d, want 1", got)
	}
}

func TestSandboxAdmissionSQLLocksActiveHostBeforeMutation(t *testing.T) {
	var statements []string
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			statements = append(statements, sql)
			return errorRow(pgx.ErrNoRows)
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
	}
	queries := db.New(mock)
	_, _ = queries.CreateSandbox(context.Background(), db.CreateSandboxParams{HostID: "host-a"})
	_, _ = queries.CreateSandboxFromTemplate(context.Background(), db.CreateSandboxFromTemplateParams{HostID: "host-a"})
	_, _ = queries.BeginResume(context.Background(), db.BeginResumeParams{ID: uuid.New(), TeamID: uuid.New()})

	if len(statements) != 3 {
		t.Fatalf("captured %d admission statements, want 3", len(statements))
	}
	for i, sql := range statements {
		if !strings.Contains(sql, "h.status = 'active'") {
			t.Errorf("statement %d does not require an active host:\n%s", i, sql)
		}
		if !strings.Contains(sql, "FOR SHARE") && !strings.Contains(sql, "FOR UPDATE OF h") {
			t.Errorf("statement %d does not take a drain-conflicting host lock:\n%s", i, sql)
		}
		if !strings.Contains(sql, "NOT EXISTS (SELECT 1 FROM host)") {
			t.Errorf("statement %d does not limit legacy fallback to an empty host table:\n%s", i, sql)
		}
		activeHostPos := strings.Index(sql, "active_host AS MATERIALIZED")
		mutationPos := strings.Index(sql, "INSERT INTO sandbox")
		if mutationPos < 0 {
			mutationPos = strings.Index(sql, "UPDATE sandbox")
		}
		if activeHostPos < 0 || mutationPos < 0 || activeHostPos > mutationPos {
			t.Errorf("statement %d does not order host admission before sandbox mutation:\n%s", i, sql)
		}
	}
}

func TestTemplateBuildDispatchSQLLocksActiveHost(t *testing.T) {
	var statement string
	mock := &mockDBTX{
		queryRowFn: func(context.Context, string, ...any) pgx.Row { return notFoundRow() },
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			statement = sql
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	hostID := "host-a"
	buildVMID := uuid.New().String()
	affected, err := db.New(mock).TryDispatchBuild(context.Background(), db.TryDispatchBuildParams{
		ID: uuid.New(), VmdHostID: &hostID, VmdBuildVmID: &buildVMID,
	})
	if err != nil || affected != 1 {
		t.Fatalf("TryDispatchBuild = (%d, %v), want (1, nil)", affected, err)
	}
	for _, required := range []string{
		"active_host AS MATERIALIZED",
		"h.status = 'active'",
		"FOR SHARE",
		"NOT EXISTS (SELECT 1 FROM host)",
		"FROM admitted_host",
	} {
		if !strings.Contains(statement, required) {
			t.Errorf("TryDispatchBuild SQL missing %q:\n%s", required, statement)
		}
	}
}

func TestUpdateSandboxAutoDeleteLocksHostAndPreservesDrainFence(t *testing.T) {
	var statement string
	mock := &mockDBTX{
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			statement = sql
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	seconds := int32(300)
	affected, err := db.New(mock).UpdateSandboxAutoDelete(context.Background(), db.UpdateSandboxAutoDeleteParams{
		ID: uuid.New(), TeamID: uuid.New(), AutoDeleteSeconds: &seconds,
	})
	if err != nil || affected != 1 {
		t.Fatalf("UpdateSandboxAutoDelete = (%d, %v), want (1, nil)", affected, err)
	}
	for _, required := range []string{
		"locked_host AS MATERIALIZED",
		"FOR SHARE OF h",
		"WHERE NOT EXISTS (SELECT 1 FROM host)",
		"host_state.status <> 'draining'",
		"ELSE NULL",
	} {
		if !strings.Contains(statement, required) {
			t.Errorf("UpdateSandboxAutoDelete SQL missing %q:\n%s", required, statement)
		}
	}
}

func TestAutoDeleteLifecycleSQLUsesHostFirstDrainFence(t *testing.T) {
	var (
		finalizeSQL string
		revertSQL   string
		claimSQL    string
	)
	mock := &mockDBTX{
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			claimSQL = sql
			return emptyRows{}, nil
		},
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			finalizeSQL = sql
			return finalizePauseRow(uuid.New())
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			revertSQL = sql
			return pgconn.CommandTag{}, nil
		},
	}
	queries := db.New(mock)
	id, teamID := uuid.New(), uuid.New()
	memPath := "/snapshots/mem.snap"
	if _, err := queries.FinalizePause(context.Background(), db.FinalizePauseParams{
		ID: id, TeamID: teamID, Path: "/snapshots/vmstate.snap", MemPath: &memPath,
		Trigger: "timeout",
	}); err != nil {
		t.Fatalf("FinalizePause: %v", err)
	}
	if err := queries.RevertResumeToPaused(context.Background(), db.RevertResumeToPausedParams{
		ID: id, TeamID: teamID,
	}); err != nil {
		t.Fatalf("RevertResumeToPaused: %v", err)
	}
	if _, err := queries.ClaimAutoDeleteSandboxes(context.Background(), db.ClaimAutoDeleteSandboxesParams{
		BatchSize: 10, RevocationExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("ClaimAutoDeleteSandboxes: %v", err)
	}

	for name, statement := range map[string]string{
		"FinalizePause":        finalizeSQL,
		"RevertResumeToPaused": revertSQL,
	} {
		for _, required := range []string{
			"locked_host AS MATERIALIZED",
			"FOR SHARE OF h",
			"target AS MATERIALIZED",
			"FOR UPDATE OF s",
			"target.host_status = 'draining'",
			"WHERE NOT EXISTS (SELECT 1 FROM host)",
		} {
			if !strings.Contains(statement, required) {
				t.Errorf("%s SQL missing %q:\n%s", name, required, statement)
			}
		}
		if hostLock, sandboxLock := strings.Index(statement, "FOR SHARE OF h"), strings.Index(statement, "FOR UPDATE OF s"); hostLock < 0 || sandboxLock < 0 || hostLock > sandboxLock {
			t.Errorf("%s must lock host before sandbox:\n%s", name, statement)
		}
	}

	for _, required := range []string{
		"candidate_hosts AS MATERIALIZED",
		"locked_hosts AS MATERIALIZED",
		"FOR SHARE OF h",
		"admitted_hosts AS MATERIALIZED",
		"status <> 'draining'",
		"WHERE NOT EXISTS (SELECT 1 FROM host)",
		"JOIN admitted_hosts",
		"FOR UPDATE OF s SKIP LOCKED",
	} {
		if !strings.Contains(claimSQL, required) {
			t.Errorf("ClaimAutoDeleteSandboxes SQL missing %q:\n%s", required, claimSQL)
		}
	}
	if hostLock, sandboxLock := strings.Index(claimSQL, "FOR SHARE OF h"), strings.Index(claimSQL, "FOR UPDATE OF s"); hostLock < 0 || sandboxLock < 0 || hostLock > sandboxLock {
		t.Errorf("ClaimAutoDeleteSandboxes must lock hosts before sandboxes:\n%s", claimSQL)
	}
}
