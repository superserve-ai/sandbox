//go:build integration

package integration

import (
	"context"

	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

const vmstateSHA = "e0ab134d0ba6aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const diskSHA = "7fde53aea27abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const genKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// A verified-generation report records coverage idempotently and syncs
// snapshot.size_bytes only when the report's vmstate digest matches the
// pause-time manifest row, which pins the report to exactly that pause.
func TestIntegration_BackupReport_RecordsAndSyncsSize(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-report")
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"backup-report"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)
	if pw := do(r, "POST", "/sandboxes/"+sid+"/pause", apiKey, ""); pw.Code != http.StatusNoContent {
		t.Fatalf("pause: %d %s", pw.Code, pw.Body.String())
	}
	// The endpoint's bookkeeping already finalized; force back to
	// 'pausing' so the manual finalize below is the one that writes the
	// manifest this test controls.
	if _, err := testPool.Exec(ctx,
		`UPDATE sandbox SET status = 'pausing' WHERE id = $1`, sandboxID); err != nil {
		t.Fatalf("force pausing: %v", err)
	}
	// The pause-time finalize: vmstate-only manifest, zero size, exactly
	// what vmd records since hashing left the pause path.
	if _, err := testQueries.FinalizePause(ctx, db.FinalizePauseParams{
		ID: sandboxID, TeamID: teamID,
		Path:              "/snapshots/" + sid + "/vmstate.snap",
		Trigger:           "manual",
		ManifestFileNames: []string{"vmstate.snap"},
		ManifestPaths:     []string{"/snapshots/" + sid + "/vmstate.snap"},
		ManifestSizes:     []int64{128},
		ManifestDigests:   []string{vmstateSHA},
		ManifestBasePaths: []string{""},
	}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	report := `{"sandbox_id":"` + sid + `","generation":"` + genKey + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T10:00:00Z","files":[` +
		`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `"},` +
		`{"name":"vmstate.snap","size_bytes":128,"sha256":"` + vmstateSHA + `"}]}`
	req := httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(report))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-report")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("report: %d %s", w.Code, w.Body.String())
	}
	first := mustJSON(t, w)
	if first["recorded"] != true || first["size_synced"] != true {
		t.Fatalf("first report = %v, want recorded and size_synced", first)
	}

	var size int64
	if err := testPool.QueryRow(ctx,
		`SELECT size_bytes FROM snapshot WHERE sandbox_id = $1`, sandboxID).Scan(&size); err != nil {
		t.Fatal(err)
	}
	if size != 4096+128 {
		t.Fatalf("snapshot.size_bytes = %d, want the verified manifest total", size)
	}

	// Redelivery (the outbox is at-least-once) records nothing new.
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(report))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-report")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("redelivery: %d %s", w.Code, w.Body.String())
	}
	if again := mustJSON(t, w); again["recorded"] != false {
		t.Fatalf("redelivery = %v, want recorded=false", again)
	}
	var rows int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM backup_generation WHERE sandbox_id = $1`, sandboxID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("backup_generation rows = %d, want 1 after redelivery", rows)
	}

	// An unchanged re-pause re-verifies the same generation later: the
	// newer verification refreshes completed_at in place, so freshness
	// checks see the current pause as covered.
	refreshed := strings.Replace(report, "2026-08-11T10:00:00Z", "2026-08-11T11:30:00Z", 1)
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(refreshed))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-report")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
	if res := mustJSON(t, w); res["recorded"] != true {
		t.Fatalf("refresh = %v, want recorded=true for a newer verification", res)
	}
	var completed string
	if err := testPool.QueryRow(ctx,
		`SELECT count(*), max(completed_at)::text FROM backup_generation WHERE sandbox_id = $1`,
		sandboxID).Scan(&rows, &completed); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || !strings.HasPrefix(completed, "2026-08-11 11:30:00") {
		t.Fatalf("after refresh rows=%d completed_at=%q, want one row at the newer instant", rows, completed)
	}

	// A report whose vmstate digest does not match the current pause
	// records coverage but must not touch sizes: it describes an older
	// generation.
	stale := strings.Replace(report, genKey, strings.Repeat("ff", 32), 1)
	stale = strings.Replace(stale, vmstateSHA, strings.Repeat("aa", 32), 1)
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(stale))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-report")
	r.ServeHTTP(w, req)
	res := mustJSON(t, w)
	if w.Code != http.StatusOK || res["recorded"] != true || res["size_synced"] != false {
		t.Fatalf("stale-vmstate report = %d %v, want recorded without size sync", w.Code, res)
	}
	if err := testPool.QueryRow(ctx,
		`SELECT size_bytes FROM snapshot WHERE sandbox_id = $1`, sandboxID).Scan(&size); err != nil {
		t.Fatal(err)
	}
	if size != 4096+128 {
		t.Fatalf("size_bytes changed to %d by a non-matching report", size)
	}
}

// A report for a sandbox this control plane never knew must clear, not
// error: the host would otherwise redeliver it from the outbox forever.
func TestIntegration_BackupReport_UnknownOwnerAccepted(t *testing.T) {
	ctx := context.Background()
	seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-orphan")
	r := newRouter(t)

	orphan := uuid.NewString()
	report := `{"sandbox_id":"` + orphan + `","generation":"` + genKey + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T10:00:00Z","files":[` +
		`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `"}]}`
	req := httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(report))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-orphan")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("orphan report: %d %s, want 200 so the outbox clears", w.Code, w.Body.String())
	}
	if res := mustJSON(t, w); res["orphaned"] != true {
		t.Fatalf("orphan report = %v, want orphaned=true", res)
	}
	var rows int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM backup_generation WHERE sandbox_id = $1`, orphan).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("orphan report wrote %d rows", rows)
	}
}
