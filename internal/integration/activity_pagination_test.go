//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// insertSandboxActivity inserts a resource_type='sandbox' audit row tied to an
// existing sandbox, with controlled category/action/status/name/created_at so
// filter + ordering assertions are deterministic.
func insertSandboxActivity(t *testing.T, teamID, sandboxID uuid.UUID, category, action, status, sandboxName string, createdAt time.Time) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO activity (id, sandbox_id, team_id, category, action, status, sandbox_name, resource_type, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'sandbox', $8)`,
		uuid.New(), sandboxID, teamID, category, action, status, sandboxName, createdAt,
	); err != nil {
		t.Fatalf("insert sandbox activity %q/%q: %v", category, action, err)
	}
}

// insertSecretActivity inserts a resource_type='secret' audit row. Secret rows
// carry no sandbox FK; secret_name is the denormalized snapshot the CHECK
// constraint requires.
func insertSecretActivity(t *testing.T, teamID uuid.UUID, action, secretName string, createdAt time.Time) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO activity (id, team_id, category, action, secret_name, resource_type, created_at)
		 VALUES ($1, $2, 'secret', $3, $4, 'secret', $5)`,
		uuid.New(), teamID, action, secretName, createdAt,
	); err != nil {
		t.Fatalf("insert secret activity %q: %v", action, err)
	}
}

func actions(rows []map[string]any) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i], _ = r["action"].(string)
	}
	return out
}

// TestIntegration_ListActivity_Pagination exercises the paged audit-log list
// end to end: default (unpaginated) created_at ordering, limit/offset
// windowing, X-Total-Count, sort direction, category + status filters, the
// multi-column substring search, the created_at window, and 400s on bad input.
func TestIntegration_ListActivity_Pagination(t *testing.T) {
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	sandboxID := insertSandboxAt(t, teamID, "audit-sbx", "active", time.Now().Add(-2*time.Hour))

	// Truncate to the second so RFC3339 date-window params compare exactly
	// against the stored timestamps (no fractional-second drift).
	base := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	// oldest → newest, mixed categories + statuses.
	insertSandboxActivity(t, teamID, sandboxID, "sandbox", "started", "success", "audit-sbx", base.Add(1*time.Minute))
	insertSandboxActivity(t, teamID, sandboxID, "sandbox", "paused", "success", "audit-sbx", base.Add(2*time.Minute))
	insertSandboxActivity(t, teamID, sandboxID, "network", "updated", "error", "audit-sbx", base.Add(3*time.Minute))
	insertSecretActivity(t, teamID, "rotated", "db-password", base.Add(4*time.Minute))
	insertSandboxActivity(t, teamID, sandboxID, "sandbox", "deleted", "error", "audit-sbx", base.Add(5*time.Minute))

	// Default: full list, created_at DESC, total = 5.
	w := do(r, "GET", "/activity", apiKey, "")
	rows := decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "5" {
		t.Errorf("X-Total-Count = %q, want 5", got)
	}
	if want := []string{"deleted", "rotated", "updated", "paused", "started"}; !eqStrings(actions(rows), want) {
		t.Errorf("default order = %v, want %v", actions(rows), want)
	}

	// First page of 2 (created desc).
	w = do(r, "GET", "/activity?limit=2&offset=0", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "5" {
		t.Errorf("page1 X-Total-Count = %q, want 5", got)
	}
	if want := []string{"deleted", "rotated"}; !eqStrings(actions(rows), want) {
		t.Errorf("page1 = %v, want %v", actions(rows), want)
	}

	// created_at ascending.
	w = do(r, "GET", "/activity?sort=created_at&order=asc&limit=50", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"started", "paused", "updated", "rotated", "deleted"}; !eqStrings(actions(rows), want) {
		t.Errorf("asc order = %v, want %v", actions(rows), want)
	}

	// Category filter narrows both rows and the count.
	w = do(r, "GET", "/activity?category=sandbox&sort=created_at&order=asc", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("category X-Total-Count = %q, want 3", got)
	}
	if want := []string{"started", "paused", "deleted"}; !eqStrings(actions(rows), want) {
		t.Errorf("category=sandbox = %v, want %v", actions(rows), want)
	}

	// Errors tab → status=error.
	w = do(r, "GET", "/activity?status=error&sort=created_at&order=asc", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "2" {
		t.Errorf("error X-Total-Count = %q, want 2", got)
	}
	if want := []string{"updated", "deleted"}; !eqStrings(actions(rows), want) {
		t.Errorf("status=error = %v, want %v", actions(rows), want)
	}

	// Case-insensitive substring across secret_name.
	w = do(r, "GET", "/activity?q=PASSWORD", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"rotated"}; !eqStrings(actions(rows), want) {
		t.Errorf("secret_name search = %v, want %v", actions(rows), want)
	}

	// Substring across action.
	w = do(r, "GET", "/activity?q=delet", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"deleted"}; !eqStrings(actions(rows), want) {
		t.Errorf("action search = %v, want %v", actions(rows), want)
	}

	// created_at window [t2, t4] inclusive → paused, updated, rotated.
	after := base.Add(2 * time.Minute).UTC().Format(time.RFC3339)
	before := base.Add(4 * time.Minute).UTC().Format(time.RFC3339)
	w = do(r, "GET", "/activity?start="+after+"&end="+before+"&sort=created_at&order=asc", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("date window X-Total-Count = %q, want 3", got)
	}
	if want := []string{"paused", "updated", "rotated"}; !eqStrings(actions(rows), want) {
		t.Errorf("date window = %v, want %v", actions(rows), want)
	}

	// Offset without limit still reports the unwindowed total.
	w = do(r, "GET", "/activity?offset=2", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "5" {
		t.Errorf("offset-only X-Total-Count = %q, want 5", got)
	}

	// Malformed pagination / filters → 400.
	if w := do(r, "GET", "/activity?limit=0", apiKey, ""); w.Code != 400 {
		t.Errorf("limit=0 status = %d, want 400", w.Code)
	}
	if w := do(r, "GET", "/activity?sort=nope", apiKey, ""); w.Code != 400 {
		t.Errorf("bad sort status = %d, want 400", w.Code)
	}
	if w := do(r, "GET", "/activity?start=notatime", apiKey, ""); w.Code != 400 {
		t.Errorf("bad start status = %d, want 400", w.Code)
	}
}

// TestIntegration_ListActivity_DefaultLimitCap proves a request that omits
// `limit` is capped at maxPageSize (200) rather than returning the whole
// unbounded history — while X-Total-Count still reports the true total so the
// caller knows to page. Guards the handler's omitted-limit default; without it
// the activity list would happily serialize an entire team's event history.
func TestIntegration_ListActivity_DefaultLimitCap(t *testing.T) {
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// 205 secret events (no sandbox FK needed), each with a distinct created_at.
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO activity (id, team_id, category, action, secret_name, resource_type, created_at)
		 SELECT gen_random_uuid(), $1, 'secret', 'bulk', 'db-password', 'secret',
		        now() - (g || ' seconds')::interval
		 FROM generate_series(1, 205) AS g`,
		teamID,
	); err != nil {
		t.Fatalf("bulk insert activity: %v", err)
	}

	// No `limit` → capped at maxPageSize (200), not all 205 rows.
	w := do(r, "GET", "/activity", apiKey, "")
	rows := decodeArray(t, w)
	if len(rows) != 200 {
		t.Errorf("no-limit page size = %d, want 200 (capped at maxPageSize)", len(rows))
	}
	if got := w.Header().Get("X-Total-Count"); got != "205" {
		t.Errorf("X-Total-Count = %q, want 205 (true total despite the cap)", got)
	}
}

// insertTemplateActivity inserts a resource_type='template' audit row tied to
// an existing template.
func insertTemplateActivity(t *testing.T, teamID, templateID uuid.UUID, action string, createdAt time.Time) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO activity (id, team_id, template_id, category, action, resource_type, created_at)
		 VALUES ($1, $2, $3, 'template', $4, 'template', $5)`,
		uuid.New(), teamID, templateID, action, createdAt,
	); err != nil {
		t.Fatalf("insert template activity %q: %v", action, err)
	}
}

// TestIntegration_ListActivity_ResourceFields verifies the response exposes
// every resource/actor FK — sandbox_id, template_id, secret_id, actor_id — and
// that metadata renders as an object, not null. template_id in particular was
// silently dropped before, leaving template events unidentifiable.
func TestIntegration_ListActivity_ResourceFields(t *testing.T) {
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	base := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	sandboxID := insertSandboxAt(t, teamID, "rf-sbx", "active", base)
	templateID := insertTemplateAt(t, teamID, "rf-tpl", base)

	insertSandboxActivity(t, teamID, sandboxID, "sandbox", "started", "success", "rf-sbx", base.Add(1*time.Minute))
	insertTemplateActivity(t, teamID, templateID, "created", base.Add(2*time.Minute))
	insertSecretActivity(t, teamID, "rotated", "db-password", base.Add(3*time.Minute))

	w := do(r, "GET", "/activity?sort=created_at&order=asc", apiKey, "")
	rows := decodeArray(t, w)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	sbx, tpl, sec := rows[0], rows[1], rows[2]

	// Every row serializes all four resource/actor keys plus metadata (present
	// even when null) — no silently-dropped columns.
	for _, row := range rows {
		for _, k := range []string{"sandbox_id", "template_id", "secret_id", "actor_id", "metadata"} {
			if _, ok := row[k]; !ok {
				t.Errorf("row %v missing key %q", row["action"], k)
			}
		}
	}

	// Sandbox event: sandbox_id set; template_id/secret_id null.
	if sbx["sandbox_id"] == nil {
		t.Error("sandbox event: sandbox_id is null, want set")
	}
	if sbx["template_id"] != nil {
		t.Errorf("sandbox event: template_id = %v, want null", sbx["template_id"])
	}
	// Template event: template_id set (previously dropped), sandbox_id null.
	if tpl["template_id"] != templateID.String() {
		t.Errorf("template event: template_id = %v, want %s", tpl["template_id"], templateID)
	}
	if tpl["sandbox_id"] != nil {
		t.Errorf("template event: sandbox_id = %v, want null", tpl["sandbox_id"])
	}
	// Secret event: metadata defaults to an empty object, never null.
	if m, ok := sec["metadata"].(map[string]any); !ok || len(m) != 0 {
		t.Errorf("secret event: metadata = %v, want empty object {}", sec["metadata"])
	}
	// actor_id is null for these system-inserted rows (no actor set).
	if sbx["actor_id"] != nil {
		t.Errorf("actor_id = %v, want null", sbx["actor_id"])
	}
}
