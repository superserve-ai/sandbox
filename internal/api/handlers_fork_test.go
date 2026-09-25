package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

// readySnapshotFixture is a ready mem+fs snapshot with everything a fork
// inherits: shape, paths, a timeout, egress rules and secret bindings.
func readySnapshotFixture(teamID uuid.UUID, secretIDs ...uuid.UUID) db.SandboxSnapshot {
	snap := snapshotFixture(teamID, uuid.New(), "ready")
	snap.HostID = "snap-host"
	snap.TemplateID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	snap.BasePath = "/templates/t/base.ext4"
	dir := "/saved/" + snap.ID.String()
	vmstate, mem, overlay := dir+"/vmstate.snap", dir+"/mem.diff", dir+"/overlay.ext4"
	snap.SnapshotPath, snap.MemPath, snap.OverlayPath = &vmstate, &mem, &overlay
	timeout := int32(600)
	snap.TimeoutSeconds = &timeout
	snap.NetworkConfig = []byte(`{"egress":{"allowed_cidrs":["10.0.0.0/8"],"denied_cidrs":[],"allowed_domains":["api.openai.com"]}}`)
	bindings := make([]string, 0, len(secretIDs))
	for i, id := range secretIDs {
		bindings = append(bindings, fmt.Sprintf(`{"env_key":"KEY_%d","secret_id":%q}`, i, id))
	}
	snap.SecretBindings = []byte("[" + strings.Join(bindings, ",") + "]")
	return snap
}

func TestCreateSandbox_FromSnapshotForksOnItsHost(t *testing.T) {
	teamID := uuid.New()
	live := db.Secret{ID: uuid.New(), TeamID: teamID, Name: "openai", AuthType: "bearer"}
	gone := uuid.New()
	snap := readySnapshotFixture(teamID, live.ID, gone)

	var capHost string
	var capStatuses, capRequired []string
	var insertArgs []any
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandboxSnapshot :one"):
				if args[0] != snap.ID || args[1] != teamID {
					t.Errorf("snapshot read for (%v, %v); want the request's id under the caller's team", args[0], args[1])
				}
				return sandboxSnapshotRow(snap)
			case strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one"):
				capRequired, _ = args[0].([]string)
				capHost, _ = args[1].(string)
				capStatuses, _ = args[2].([]string)
				return scalarBoolRow(true)
			case strings.Contains(sql, "-- name: CreateSandboxFromSnapshot :one"):
				insertArgs = args
				return sandboxRow(db.Sandbox{
					ID: args[2].(uuid.UUID), TeamID: teamID, Name: "fork", Status: db.SandboxStatusStarting,
					VcpuCount: 2, MemoryMib: 2048, HostID: snap.HostID, TimeoutSeconds: snap.TimeoutSeconds,
					SourceSnapshotID: pgtype.UUID{Bytes: snap.ID, Valid: true},
				})
			case strings.Contains(sql, "FROM template"):
				t.Error("a create from a snapshot must not read a template")
			}
			return activityRow()
		},
		queryFn: func(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
			if !strings.Contains(sql, "-- name: GetSecretsByIDs :many") {
				return &scanRows{}, nil
			}
			if ids := args[1].([]uuid.UUID); len(ids) != 2 || ids[0] != live.ID || ids[1] != gone {
				t.Errorf("secrets looked up by %v; want the snapshot's two bindings", ids)
			}
			return &scanRows{rows: []func(...any) error{secretRow(live).scanFn}}, nil
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	var restoredSnapshot, restoredMem string
	var pushedAllow, pushedDeny, pushedDomains []string
	var injected map[string]string
	var injectedJWT string
	vmd := &stubVMD{
		restoreFn: func(_ context.Context, _, snapshotPath, memPath string) (string, error) {
			restoredSnapshot, restoredMem = snapshotPath, memPath
			return "10.0.0.7", nil
		},
		updateNetworkFn: func(_ context.Context, _ string, allow, deny, domains []string) error {
			pushedAllow, pushedDeny, pushedDomains = allow, deny, domains
			return nil
		},
		injectEnvFn: func(_ context.Context, _ string, env map[string]string, jwt string) error {
			injected, injectedJWT = env, jwt
			return nil
		},
	}
	scheduler := &stubScheduler{hostID: "scheduled-host"}
	h := &Handlers{VMD: vmd, DB: db.New(mock), Scheduler: scheduler, Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(fmt.Sprintf(`{"name":"fork","from_snapshot":%q,"env_vars":{"KEY_9":"x"}}`, snap.ID)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}

	// Placed on the snapshot's host, which must fork and may be draining.
	if scheduler.selects != 0 {
		t.Errorf("scheduler consulted %d times; the snapshot's host is the only place", scheduler.selects)
	}
	if capHost != snap.HostID || !hasString(capRequired, preview.HostCapabilitySavedSnapshots) || !hasString(capRequired, preview.HostCapabilitySnapshotForks) || !hasString(capStatuses, "draining") {
		t.Errorf("host pre-flight = (%s, %v, %v); want the snapshot's host, saved snapshots required, draining allowed", capHost, capRequired, capStatuses)
	}
	// The daemon copies the snapshot's files; the request names none.
	if restoredSnapshot != "" || restoredMem != "" {
		t.Errorf("restore named files (%q, %q); a fork passes none", restoredSnapshot, restoredMem)
	}
	got := vmd.restoreLimits
	if got.VCPU != 2 || got.MemoryMiB != 2048 || got.SavedSnapshotID != snap.ID.String() {
		t.Errorf("restore limits = %+v; want the snapshot's shape and id", got)
	}
	// The inherited rules are installed by the restore, before the resumed
	// workload runs, not pushed after it.
	if got.Egress == nil || !hasString(got.Egress.AllowedCIDRs, "10.0.0.0/8") || !hasString(got.Egress.AllowedDomains, "api.openai.com") {
		t.Errorf("restore egress = %+v; want the snapshot's rules", got.Egress)
	}
	if pushedAllow != nil || pushedDomains != nil || pushedDeny != nil {
		t.Errorf("rules pushed again after the restore installed them: (%v, %v, %v)", pushedAllow, pushedDeny, pushedDomains)
	}
	// The row is the snapshot's, with its timeout and the re-bound secret.
	if insertArgs[0] != snap.ID || *insertArgs[5].(*int32) != 600 {
		t.Errorf("insert named snapshot %v with timeout %v; want the source and its 600s", insertArgs[0], insertArgs[5])
	}
	if ids := insertArgs[8].([]uuid.UUID); len(ids) != 1 || ids[0] != live.ID {
		t.Errorf("bound secrets = %v; want only the live one", ids)
	}
	if keys := insertArgs[10].([]string); len(keys) != 1 || keys[0] != "KEY_0" {
		t.Errorf("bound env keys = %v; want the live binding's", keys)
	}
	if tokens := insertArgs[11].([]string); len(tokens) != 1 || tokens[0] == "" || injected["KEY_0"] != tokens[0] {
		t.Errorf("fresh token %v not the one injected (%q)", tokens, injected["KEY_0"])
	}
	if injectedJWT == "" || injected["KEY_9"] != "x" {
		t.Errorf("injected env %v with jwt %q; want the request's env var and a JWT for the binding", injected, injectedJWT)
	}
	body := parseJSON(t, w)
	if body["source_snapshot_id"] != snap.ID.String() || body["timeout_seconds"].(float64) != 600 || body["status"] != "active" {
		t.Errorf("body = %v; want the source, its timeout and active", body)
	}
	if network, _ := body["network"].(map[string]any); network == nil || len(network["allow_out"].([]any)) != 2 {
		t.Errorf("network = %v; want the inherited rules echoed", body["network"])
	}
}

func TestCreateSandbox_FromSnapshotRequestOverridesInheritance(t *testing.T) {
	teamID := uuid.New()
	secret := db.Secret{ID: uuid.New(), TeamID: teamID, Name: "openai", AuthType: "bearer"}
	snap := readySnapshotFixture(teamID, secret.ID)

	var insertArgs []any
	var secretsLookedUp bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandboxSnapshot :one"):
				return sandboxSnapshotRow(snap)
			case strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one"):
				return scalarBoolRow(true)
			case strings.Contains(sql, "-- name: CreateSandboxFromSnapshot :one"):
				insertArgs = args
				return sandboxRow(db.Sandbox{ID: args[2].(uuid.UUID), TeamID: teamID, Name: "fork", Status: db.SandboxStatusStarting, VcpuCount: 2, MemoryMib: 2048})
			}
			return activityRow()
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "-- name: GetSecretsByIDs :many") {
				secretsLookedUp = true
				return &scanRows{rows: []func(...any) error{secretRow(secret).scanFn}}, nil
			}
			return &scanRows{}, nil
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	vmd := &stubVMD{}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"name":"fork","from_snapshot":%q,"timeout_seconds":60,"network":{"allow_out":["1.1.1.1"]},"env_vars":{"KEY_0":"mine"}}`, snap.ID)
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	if *insertArgs[5].(*int32) != 60 {
		t.Errorf("timeout = %v; want the request's 60s over the snapshot's", insertArgs[5])
	}
	if !secretsLookedUp || len(insertArgs[8].([]uuid.UUID)) != 0 {
		t.Errorf("bound secrets = %v; the request's KEY_0 env var wins over the inherited binding", insertArgs[8])
	}
	if e := vmd.restoreLimits.Egress; e == nil || len(e.AllowedCIDRs) != 1 || e.AllowedCIDRs[0] != "1.1.1.1/32" || len(e.AllowedDomains) != 0 {
		t.Errorf("restore egress = %+v; want the request's rules over the snapshot's", e)
	}
}

func TestCreateSandbox_FromSnapshotRefusals(t *testing.T) {
	teamID := uuid.New()
	snap := readySnapshotFixture(teamID)
	cases := []struct {
		name       string
		body       string
		snapshot   func() pgx.Row
		capable    bool
		insert     func() pgx.Row
		wantStatus int
		wantCode   string
	}{
		{name: "both sources", body: fmt.Sprintf(`{"name":"x","from_template":"t","from_snapshot":%q}`, snap.ID), wantStatus: 400, wantCode: "bad_request"},
		{name: "not an id", body: `{"name":"x","from_snapshot":"latest"}`, wantStatus: 400, wantCode: "bad_request"},
		{name: "the nil id", body: `{"name":"x","from_snapshot":"00000000-0000-0000-0000-000000000000"}`, wantStatus: 400, wantCode: "bad_request"},
		{name: "unknown or another team's", snapshot: func() pgx.Row { return notFoundRow() }, wantStatus: 404, wantCode: "not_found"},
		{name: "still creating", snapshot: func() pgx.Row {
			creating := snap
			creating.Status = "creating"
			return sandboxSnapshotRow(creating)
		}, wantStatus: 409, wantCode: "conflict"},
		{name: "host cannot fork", capable: false, wantStatus: 503, wantCode: "host_not_ready"},
		{name: "deleted mid-create", capable: true, insert: func() pgx.Row { return notFoundRow() }, wantStatus: 404, wantCode: "not_found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var destroyed bool
			vmd := &stubVMD{destroyFn: func(context.Context, string, bool) error {
				destroyed = true
				return nil
			}}
			mock := &mockDBTX{
				queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
					switch {
					case strings.Contains(sql, "-- name: GetSandboxSnapshot :one"):
						if tc.snapshot != nil {
							return tc.snapshot()
						}
						return sandboxSnapshotRow(snap)
					case strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one"):
						return scalarBoolRow(tc.capable)
					case strings.Contains(sql, "-- name: CreateSandboxFromSnapshot :one"):
						if tc.insert != nil {
							return tc.insert()
						}
						return sandboxRow(db.Sandbox{ID: args[2].(uuid.UUID), TeamID: teamID, Status: db.SandboxStatusStarting})
					case strings.Contains(sql, "INSERT INTO sandbox"), strings.Contains(sql, "FROM template"):
						t.Errorf("unexpected query: %s", sql)
					}
					return activityRow()
				},
				execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			}
			h := &Handlers{VMD: vmd, DB: db.New(mock), Scheduler: &stubScheduler{hostID: "scheduled-host"}}
			body := tc.body
			if body == "" {
				body = fmt.Sprintf(`{"name":"x","from_snapshot":%q}`, snap.ID)
			}
			w := httptest.NewRecorder()
			setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(body))
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if errObj, _ := parseJSON(t, w)["error"].(map[string]any); errObj["code"] != tc.wantCode {
				t.Errorf("error code = %v, want %s", errObj["code"], tc.wantCode)
			}
			if tc.insert != nil && !destroyed {
				t.Error("the VM booted for a snapshot deleted mid-create was not destroyed")
			}
		})
	}
}

func TestCreateSandbox_FromSnapshotRefusesTooManyBindingsBeforeBoot(t *testing.T) {
	teamID := uuid.New()
	extra := db.Secret{ID: uuid.New(), TeamID: teamID, Name: "extra", AuthType: "bearer"}
	inherited := make([]db.Secret, SecretsBindingsCap)
	ids := make([]uuid.UUID, SecretsBindingsCap)
	for i := range inherited {
		inherited[i] = db.Secret{ID: uuid.New(), TeamID: teamID, Name: fmt.Sprintf("s%d", i), AuthType: "bearer"}
		ids[i] = inherited[i].ID
	}
	snap := readySnapshotFixture(teamID, ids...)
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandboxSnapshot :one"):
				return sandboxSnapshotRow(snap)
			case strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one"):
				return scalarBoolRow(true)
			case strings.Contains(sql, "INSERT INTO sandbox"):
				t.Error("a create over the binding limit must not write a row")
			}
			return activityRow()
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			rows := &scanRows{}
			switch {
			case strings.Contains(sql, "-- name: GetSecretsByIDs :many"):
				for _, s := range inherited {
					rows.rows = append(rows.rows, secretRow(s).scanFn)
				}
			case strings.Contains(sql, "-- name: GetSecretsByNames :many"):
				rows.rows = []func(...any) error{secretRow(extra).scanFn}
			}
			return rows, nil
		},
	}
	var booted bool
	vmd := &stubVMD{restoreFn: func(context.Context, string, string, string) (string, error) {
		booted = true
		return "10.0.0.7", nil
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock), Signer: newTestSigner(t, "v1")}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(fmt.Sprintf(`{"name":"fork","from_snapshot":%q,"secrets":{"EXTRA":"extra"}}`, snap.ID)))
	if w.Code != http.StatusBadRequest || booted {
		t.Fatalf("status = %d booted = %v; want 400 before any boot: %s", w.Code, booted, w.Body.String())
	}
}

// A vmd that cannot install a fork's rules before its workload runs leaves
// nothing safe to hand over: the fork is torn down, not activated.
func TestCreateSandbox_FromSnapshotFailsWhenTheHostCannotInstallItsRules(t *testing.T) {
	teamID := uuid.New()
	snap := readySnapshotFixture(teamID)
	var failed bool
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandboxSnapshot :one"):
				return sandboxSnapshotRow(snap)
			case strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one"):
				return scalarBoolRow(true)
			case strings.Contains(sql, "-- name: CreateSandboxFromSnapshot :one"):
				return sandboxRow(db.Sandbox{ID: args[2].(uuid.UUID), TeamID: teamID, Name: "fork", Status: db.SandboxStatusStarting, VcpuCount: 2, MemoryMib: 2048})
			}
			return activityRow()
		},
		execFn: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "-- name: UpdateSandboxStatus") {
				failed = true
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	var destroyed bool
	vmd := &stubVMD{
		restoreIgnoresRules: true,
		destroyFn: func(context.Context, string, bool) error {
			destroyed = true
			return nil
		},
	}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(fmt.Sprintf(`{"name":"fork","from_snapshot":%q}`, snap.ID)))
	if w.Code != http.StatusServiceUnavailable || !destroyed || !failed {
		t.Fatalf("status = %d destroyed = %v failed = %v; want 503 with the fork torn down: %s", w.Code, destroyed, failed, w.Body.String())
	}
}

// A source's proxy settings stay in the guest's environment. A fork left
// with no secrets bound has them cleared, or every HTTPS request it makes
// would go to the proxy with credentials that are not its own.
func TestCreateSandbox_FromSnapshotClearsProxySettingsWhenNoSecretsRemain(t *testing.T) {
	teamID := uuid.New()
	snap := readySnapshotFixture(teamID, uuid.New())
	mock := &mockDBTX{
		queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "-- name: GetSandboxSnapshot :one"):
				return sandboxSnapshotRow(snap)
			case strings.Contains(sql, "-- name: HostHasCapabilitiesUnlocked :one"):
				return scalarBoolRow(true)
			case strings.Contains(sql, "-- name: CreateSandboxFromSnapshot :one"):
				return sandboxRow(db.Sandbox{ID: args[2].(uuid.UUID), TeamID: teamID, Name: "fork", Status: db.SandboxStatusStarting, VcpuCount: 2, MemoryMib: 2048})
			}
			return activityRow()
		},
		execFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	var injected map[string]string
	vmd := &stubVMD{injectEnvFn: func(_ context.Context, _ string, env map[string]string, _ string) error {
		injected = env
		return nil
	}}
	h := &Handlers{VMD: vmd, DB: db.New(mock)}
	w := httptest.NewRecorder()
	// The source's one secret has since been deleted.
	setupTestRouter(h, teamID.String()).ServeHTTP(w, createSandboxReq(fmt.Sprintf(`{"name":"fork","from_snapshot":%q}`, snap.ID)))
	h.WaitAsyncBookkeeping()
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
	}
	if v, ok := injected["HTTPS_PROXY"]; !ok || v != "" {
		t.Fatalf("injected env = %v; want HTTPS_PROXY cleared", injected)
	}
}

func hasString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
