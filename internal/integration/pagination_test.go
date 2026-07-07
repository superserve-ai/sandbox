//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// insertSandboxAt inserts a sandbox with a controlled name, status, and
// created_at so pagination + sort ordering can be asserted deterministically.
func insertSandboxAt(t *testing.T, teamID uuid.UUID, name, status string, createdAt time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	// host_id is NOT NULL (migration 20260410000001); supply a placeholder like
	// the other integration sandbox inserts do. created_at is set explicitly so
	// the sort assertions are deterministic.
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO sandbox (id, team_id, name, status, host_id, created_at)
		 VALUES ($1, $2, $3, $4::sandbox_status, 'test-host', $5)`,
		id, teamID, name, status, createdAt,
	); err != nil {
		t.Fatalf("insert sandbox %q: %v", name, err)
	}
	return id
}

func decodeArray(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var arr []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &arr); err != nil {
		t.Fatalf("decode array: %v; body=%s", err, w.Body.String())
	}
	return arr
}

func names(rows []map[string]any) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i], _ = r["name"].(string)
	}
	return out
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestIntegration_ListSandboxes_Pagination exercises the paged sandbox list end
// to end: default (unpaginated) ordering, limit/offset windowing, the
// X-Total-Count header, sort, status filter, and name substring search.
func TestIntegration_ListSandboxes_Pagination(t *testing.T) {
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	// Five sandboxes, created oldest→newest a..e, mixed statuses.
	base := time.Now().Add(-1 * time.Hour)
	insertSandboxAt(t, teamID, "alpha", "active", base.Add(1*time.Minute))
	insertSandboxAt(t, teamID, "bravo", "paused", base.Add(2*time.Minute))
	insertSandboxAt(t, teamID, "charlie", "active", base.Add(3*time.Minute))
	insertSandboxAt(t, teamID, "delta", "paused", base.Add(4*time.Minute))
	insertSandboxAt(t, teamID, "echo", "active", base.Add(5*time.Minute))

	// Default: full list, created_at DESC, total = 5.
	w := do(r, "GET", "/sandboxes", apiKey, "")
	rows := decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "5" {
		t.Errorf("X-Total-Count = %q, want 5", got)
	}
	if want := []string{"echo", "delta", "charlie", "bravo", "alpha"}; !eqStrings(names(rows), want) {
		t.Errorf("default order = %v, want %v", names(rows), want)
	}

	// First page of 2 (created desc).
	w = do(r, "GET", "/sandboxes?limit=2&offset=0", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "5" {
		t.Errorf("page1 X-Total-Count = %q, want 5", got)
	}
	if want := []string{"echo", "delta"}; !eqStrings(names(rows), want) {
		t.Errorf("page1 = %v, want %v", names(rows), want)
	}

	// Third page of 2 → single trailing row.
	w = do(r, "GET", "/sandboxes?limit=2&offset=4", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"alpha"}; !eqStrings(names(rows), want) {
		t.Errorf("page3 = %v, want %v", names(rows), want)
	}

	// Sort by name ascending.
	w = do(r, "GET", "/sandboxes?sort=name&order=asc&limit=50", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"alpha", "bravo", "charlie", "delta", "echo"}; !eqStrings(names(rows), want) {
		t.Errorf("name asc = %v, want %v", names(rows), want)
	}

	// Status filter narrows both rows and the count.
	w = do(r, "GET", "/sandboxes?status=paused&sort=name&order=asc", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "2" {
		t.Errorf("paused X-Total-Count = %q, want 2", got)
	}
	if want := []string{"bravo", "delta"}; !eqStrings(names(rows), want) {
		t.Errorf("paused = %v, want %v", names(rows), want)
	}

	// Case-insensitive name substring.
	w = do(r, "GET", "/sandboxes?q=LPH", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"alpha"}; !eqStrings(names(rows), want) {
		t.Errorf("substring = %v, want %v", names(rows), want)
	}

	// Offset without limit still reports the unwindowed total.
	w = do(r, "GET", "/sandboxes?offset=2", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "5" {
		t.Errorf("offset-only X-Total-Count = %q, want 5", got)
	}
	if want := []string{"charlie", "bravo", "alpha"}; !eqStrings(names(rows), want) {
		t.Errorf("offset-only = %v, want %v", names(rows), want)
	}

	// LIKE metacharacters in q match literally, not as wildcards.
	insertSandboxAt(t, teamID, "x_ray", "active", base.Add(6*time.Minute))
	insertSandboxAt(t, teamID, "xtray", "active", base.Add(7*time.Minute))
	w = do(r, "GET", "/sandboxes?q=x_ray", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"x_ray"}; !eqStrings(names(rows), want) {
		t.Errorf("underscore search = %v, want %v (literal _, not wildcard)", names(rows), want)
	}
	w = do(r, "GET", "/sandboxes?q=%25", apiKey, "") // q=%
	rows = decodeArray(t, w)
	if len(rows) != 0 {
		t.Errorf("q=%%%% matched %v, want none (literal %%, not wildcard)", names(rows))
	}

	// Malformed pagination → 400.
	if w := do(r, "GET", "/sandboxes?limit=0", apiKey, ""); w.Code != 400 {
		t.Errorf("limit=0 status = %d, want 400", w.Code)
	}
	if w := do(r, "GET", "/sandboxes?sort=nope", apiKey, ""); w.Code != 400 {
		t.Errorf("bad sort status = %d, want 400", w.Code)
	}
	if w := do(r, "GET", "/sandboxes?status=activ", apiKey, ""); w.Code != 400 {
		t.Errorf("bad status filter = %d, want 400", w.Code)
	}
}

// insertTemplateAt inserts a team template with a controlled name + created_at.
func insertTemplateAt(t *testing.T, teamID uuid.UUID, name string, createdAt time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO template (id, team_id, name, status, build_spec, created_at)
		 VALUES ($1, $2, $3, 'ready'::template_status, '{}'::jsonb, $4)`,
		id, teamID, name, createdAt,
	); err != nil {
		t.Fatalf("insert template %q: %v", name, err)
	}
	return id
}

// TestIntegration_ListTemplates_Pagination covers the owner filter, pagination,
// and X-Total-Count for templates. The team shelf is asserted in isolation via
// owner=team so the count is independent of however many system templates the
// shared test schema happens to carry.
func TestIntegration_ListTemplates_Pagination(t *testing.T) {
	teamID, apiKey := seedTeamAndKey(t)
	r := newRouter(t)

	base := time.Now().Add(-1 * time.Hour)
	insertTemplateAt(t, teamID, "img-one", base.Add(1*time.Minute))
	insertTemplateAt(t, teamID, "img-two", base.Add(2*time.Minute))
	insertTemplateAt(t, teamID, "img-three", base.Add(3*time.Minute))

	// owner=team isolates this team's shelf: 3 rows, created_at DESC.
	w := do(r, "GET", "/templates?owner=team", apiKey, "")
	rows := decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("team X-Total-Count = %q, want 3", got)
	}
	if want := []string{"img-three", "img-two", "img-one"}; !eqStrings(names(rows), want) {
		t.Errorf("team order = %v, want %v", names(rows), want)
	}

	// Paginated team shelf.
	w = do(r, "GET", "/templates?owner=team&limit=2&offset=0&sort=name&order=asc", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("team page X-Total-Count = %q, want 3", got)
	}
	if want := []string{"img-one", "img-three"}; !eqStrings(names(rows), want) {
		t.Errorf("team page name asc = %v, want %v", names(rows), want)
	}

	// Substring search on the team shelf.
	w = do(r, "GET", "/templates?owner=team&q=two", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"img-two"}; !eqStrings(names(rows), want) {
		t.Errorf("template substring = %v, want %v", names(rows), want)
	}

	// Legacy name_prefix (prefix, not substring) still works for SDK/MCP.
	w = do(r, "GET", "/templates?owner=team&name_prefix=img-t&sort=name&order=asc", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"img-three", "img-two"}; !eqStrings(names(rows), want) {
		t.Errorf("name_prefix = %v, want %v", names(rows), want)
	}

	// Offset without limit still reports the unwindowed total.
	w = do(r, "GET", "/templates?owner=team&offset=1", apiKey, "")
	rows = decodeArray(t, w)
	if got := w.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("offset-only X-Total-Count = %q, want 3", got)
	}
	if want := []string{"img-two", "img-one"}; !eqStrings(names(rows), want) {
		t.Errorf("offset-only = %v, want %v", names(rows), want)
	}

	// built_at DESC ranks built templates newest-first and never-built
	// (built_at IS NULL) last, not first.
	for name, builtAt := range map[string]time.Time{
		"img-one": base.Add(10 * time.Minute),
		"img-two": base.Add(20 * time.Minute),
	} {
		if _, err := testPool.Exec(context.Background(),
			`UPDATE template SET built_at = $1 WHERE team_id = $2 AND name = $3`,
			builtAt, teamID, name,
		); err != nil {
			t.Fatalf("set built_at for %q: %v", name, err)
		}
	}
	w = do(r, "GET", "/templates?owner=team&sort=built_at&order=desc", apiKey, "")
	rows = decodeArray(t, w)
	if want := []string{"img-two", "img-one", "img-three"}; !eqStrings(names(rows), want) {
		t.Errorf("built_at desc = %v, want %v (NULLS LAST)", names(rows), want)
	}

	// Invalid owner → 400.
	if w := do(r, "GET", "/templates?owner=bogus", apiKey, ""); w.Code != 400 {
		t.Errorf("bad owner status = %d, want 400", w.Code)
	}
}
