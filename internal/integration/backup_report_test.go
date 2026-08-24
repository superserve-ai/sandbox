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

// A coverage-only report (zero files) records coverage without touching
// snapshot sizes: hosts seed historical completions whose task rows and
// manifests are long gone, and rejecting them would poison the seed
// since the reporter treats a 400 as permanent.
func TestIntegration_BackupReport_CoverageOnlySeed(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-seed")
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"backup-seed"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)

	body := `{"sandbox_id":"` + sid + `","generation":"` + genKey + `","bucket":"seed-bucket","completed_at":"2026-08-01T00:00:00Z","files":[]}`
	req := httptest.NewRequest("POST", "/internal/hosts/test-host/backups", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-seed")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("seed report: %d %s", w.Code, w.Body.String())
	}

	var gen, bucket string
	if err := testPool.QueryRow(ctx,
		`SELECT generation, bucket FROM backup_generation WHERE sandbox_id = $1`, sandboxID).Scan(&gen, &bucket); err != nil {
		t.Fatalf("coverage row missing after seed: %v", err)
	}
	if gen != genKey || bucket != "seed-bucket" {
		t.Fatalf("coverage = %s %s, want the seeded generation and bucket", gen, bucket)
	}
	var size any
	if err := testPool.QueryRow(ctx,
		`SELECT size_bytes FROM snapshot WHERE sandbox_id = $1`, sandboxID).Scan(&size); err == nil {
		if n, ok := size.(int64); ok && n != 0 {
			t.Fatalf("size_bytes = %d after a file-less seed, want untouched", n)
		}
	}
}

// A coverage-only report (empty files, the outbox seed's shape) with a
// newer completion instant refreshes freshness but must never erase the
// recorded manifest, and must never touch snapshot sizes.
func TestIntegration_BackupReport_CoverageOnlyPreservesManifest(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-seed")
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"seed-guard"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	_ = teamID

	rich := `{"sandbox_id":"` + sid + `","generation":"` + genKey + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T10:00:00Z","files":[` +
		`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `"},` +
		`{"name":"vmstate.snap","size_bytes":128,"sha256":"` + vmstateSHA + `"}]}`
	req := httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(rich))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-seed")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rich report: %d %s", w.Code, w.Body.String())
	}

	// The seed's shape: same generation, newer instant, no files.
	seeded := `{"sandbox_id":"` + sid + `","generation":"` + genKey + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T11:00:00Z","files":[]}`
	req = httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(seeded))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer itok-seed")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("coverage-only report: %d %s", w.Code, w.Body.String())
	}

	var files string
	var completedAt string
	if err := testPool.QueryRow(ctx,
		`SELECT files::text, completed_at::text FROM backup_generation WHERE sandbox_id = $1`, sid).
		Scan(&files, &completedAt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files, "rootfs.ext4") {
		t.Fatalf("coverage-only refresh erased the manifest: files = %s", files)
	}
	if !strings.Contains(completedAt, "11:00:00") {
		t.Fatalf("completed_at = %s, want the newer instant kept", completedAt)
	}
}

// The files jsonb follows a strict enrichment order, because the paths
// are what a lifecycle GC reasons from: a pathless report (an older
// host re-verifying the same content-addressed generation) refreshes
// freshness without demoting recorded paths; a path-bearing report
// enriches a pathless row even at an identical pinned instant (a
// rollout-window fallback can land the pathless copy first) without
// regressing freshness; and once paths are recorded they are frozen,
// since the immutable bucket manifest they mirror can never change.
func TestIntegration_BackupReport_ObjectPathEnrichmentOrder(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-paths")
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"path-guard"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	diskObj := "sandboxes/" + sid + "/" + genKey + "/rootfs.ext4.pabc123"
	send := func(body string) {
		t.Helper()
		req := httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer itok-paths")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("report: %d %s", w.Code, w.Body.String())
		}
	}
	readFiles := func() string {
		t.Helper()
		var files string
		if err := testPool.QueryRow(ctx,
			`SELECT files::text FROM backup_generation WHERE sandbox_id = $1`, sid).Scan(&files); err != nil {
			t.Fatal(err)
		}
		return files
	}

	send(`{"sandbox_id":"` + sid + `","generation":"` + genKey + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T10:00:00Z","files":[` +
		`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `","object":"` + diskObj + `"}]}`)
	if files := readFiles(); !strings.Contains(files, "rootfs.ext4.pabc123") {
		t.Fatalf("path-bearing report not recorded: files = %s", files)
	}

	// The pathless redelivery: same generation, newer instant, no paths.
	send(`{"sandbox_id":"` + sid + `","generation":"` + genKey + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T11:00:00Z","files":[` +
		`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `"}]}`)
	if files := readFiles(); !strings.Contains(files, "rootfs.ext4.pabc123") {
		t.Fatalf("pathless redelivery erased the object paths: files = %s", files)
	}

	// Recorded paths are frozen: a newer report claiming different
	// (structurally valid) fingerprints refreshes freshness only, since
	// nothing conforming can rename an immutable generation's objects.
	send(`{"sandbox_id":"` + sid + `","generation":"` + genKey + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T12:00:00Z","files":[` +
		`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `","object":"` + diskObj + `2"}]}`)
	files := readFiles()
	if strings.Contains(files, "rootfs.ext4.pabc1232") || !strings.Contains(files, "rootfs.ext4.pabc123") {
		t.Fatalf("recorded paths were not frozen: files = %s", files)
	}
	var completedAt string
	if err := testPool.QueryRow(ctx,
		`SELECT completed_at::text FROM backup_generation WHERE sandbox_id = $1`, sid).Scan(&completedAt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(completedAt, "12:00:00") {
		t.Fatalf("completed_at = %s, want freshness refreshed past the frozen files", completedAt)
	}

	// Enrichment at an identical pinned instant: the rollout-window
	// fallback landed a pathless copy of this verification first, and
	// the rich redelivery carries the same completed_at. The paths must
	// land without moving completed_at.
	gen2 := strings.Repeat("f0", 32)
	disk2 := "sandboxes/" + sid + "/" + gen2 + "/rootfs.ext4.pdef456"
	send(`{"sandbox_id":"` + sid + `","generation":"` + gen2 + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T10:30:00Z","files":[` +
		`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `"}]}`)
	// Pin reported_at so the enrichment below provably leaves the
	// freshness cap where the first receipt set it.
	if _, err := testPool.Exec(ctx,
		`UPDATE backup_generation SET reported_at = '2026-08-11T09:00:00Z' WHERE sandbox_id = $1 AND generation = $2`,
		sid, gen2); err != nil {
		t.Fatal(err)
	}
	send(`{"sandbox_id":"` + sid + `","generation":"` + gen2 + `",` +
		`"bucket":"cell-bucket","completed_at":"2026-08-11T10:30:00Z","files":[` +
		`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `","object":"` + disk2 + `"}]}`)
	var reportedAt string
	if err := testPool.QueryRow(ctx,
		`SELECT files::text, completed_at::text, reported_at::text FROM backup_generation WHERE sandbox_id = $1 AND generation = $2`,
		sid, gen2).Scan(&files, &completedAt, &reportedAt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files, "rootfs.ext4.pdef456") {
		t.Fatalf("equal-instant rich redelivery did not enrich: files = %s", files)
	}
	if !strings.Contains(completedAt, "10:30:00") {
		t.Fatalf("completed_at = %s, want the pinned instant untouched by enrichment", completedAt)
	}
	if !strings.Contains(reportedAt, "09:00:00") {
		t.Fatalf("reported_at = %s, want the freshness cap untouched by enrichment", reportedAt)
	}
}

// A report landing while the sandbox is in a TRANSITIONAL status —
// 'pausing' on the normal path, 'resuming' while pauseAndRevert
// re-pauses a failed resume — must be deferred (503, entry stays
// outboxed): evaluated in that window it would match the PREVIOUS
// snapshot's identity, fail to link, and clear the outbox before the
// pause it covers exists. A stale transition proceeds so a stranded
// sandbox cannot wedge the outbox.
func TestIntegration_BackupReport_DefersDuringTransitionalStatus(t *testing.T) {
	ctx := context.Background()
	_, apiKey := seedTeamAndKey(t)
	t.Setenv("INTERNAL_API_TOKEN", "itok-report")
	r := newRouter(t)

	cw := do(r, "POST", "/sandboxes", apiKey, `{"name":"report-defer"}`)
	if cw.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", cw.Code, cw.Body.String())
	}
	sid := mustJSON(t, cw)["id"].(string)
	sandboxID, _ := uuid.Parse(sid)

	deliver := func() int {
		report := `{"sandbox_id":"` + sid + `","generation":"` + genKey + `",` +
			`"bucket":"cell-bucket","completed_at":"2026-08-11T10:00:00Z","files":[` +
			`{"name":"rootfs.ext4","size_bytes":4096,"sha256":"` + diskSHA + `"},` +
			`{"name":"vmstate.snap","size_bytes":128,"sha256":"` + vmstateSHA + `"}]}`
		req := httptest.NewRequest("POST", "/internal/hosts/host-1/backups", strings.NewReader(report))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer itok-report")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	for _, status := range []string{"pausing", "resuming"} {
		if _, err := testPool.Exec(ctx,
			`UPDATE sandbox SET status = $2, updated_at = now() WHERE id = $1`,
			sandboxID, status); err != nil {
			t.Fatalf("force %s: %v", status, err)
		}
		if code := deliver(); code != http.StatusServiceUnavailable {
			t.Fatalf("report during fresh %q = %d, want 503 (deferred)", status, code)
		}
		// Stale transition: the guard yields and the report proceeds.
		if _, err := testPool.Exec(ctx,
			`UPDATE sandbox SET updated_at = now() - interval '20 minutes' WHERE id = $1`,
			sandboxID); err != nil {
			t.Fatalf("age %s: %v", status, err)
		}
		if code := deliver(); code != http.StatusOK {
			t.Fatalf("report during stale %q = %d, want 200", status, code)
		}
	}
}
