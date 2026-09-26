//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

// newRouterWithSigner is newRouter with a secrets signer, for creates that
// bind secrets and so mint a JWT.
func newRouterWithSigner(t *testing.T) *gin.Engine {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := api.NewSecretsSigner(base64.StdEncoding.EncodeToString(priv.Seed()), "v1")
	if err != nil {
		t.Fatal(err)
	}
	h := api.NewHandlers(&stubVMD{}, testQueries, &config.Config{
		Port: "0", VMDAddress: "localhost:0", SystemTeamID: testSystemTeamID.String(), DefaultHostID: testDefaultHostID,
	})
	h.Pool = testPool
	h.Signer = signer
	h.Encryptor = stubEncryptor{}
	registerTestHandlers(h)
	return api.SetupRouter(t.Context(), h, testPool)
}

// A sandbox created from a snapshot takes the snapshot's shape, paths and
// host, inherits what the request leaves unset, binds the source's secrets
// again with fresh tokens, and names its source. A snapshot that is not
// ready, not the caller's, or deleted gives no sandbox.
func TestIntegration_CreateSandbox_FromSnapshot(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	hostID := seedActivePreviewHost(t, preview.HostCapabilityPorts, preview.HostCapabilitySavedSnapshots)
	secretID := seedSecret(t, teamID)
	sourceID, err := insertSandboxRow(ctx, teamID, "fork-source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active', host_id = $2, base_path = '/templates/t/base.ext4',
		disk_mib = 4096, vcpu_count = 2, memory_mib = 2048, timeout_seconds = 900,
		network_config = '{"egress":{"allowed_cidrs":["10.0.0.0/8"],"denied_cidrs":[],"allowed_domains":[]}}' WHERE id = $1`, sourceID, hostID); err != nil {
		t.Fatal(err)
	}
	token := "sp_source"
	if _, err := testQueries.AddSandboxSecret(ctx, db.AddSandboxSecretParams{SandboxID: sourceID, SecretID: secretID, EnvKey: "TOKEN", ProxyToken: &token}); err != nil {
		t.Fatal(err)
	}
	// Bound, but its secret deleted before the capture: recorded, so a fork
	// can clear the key.
	deleted := seedSecret(t, teamID)
	if _, err := testQueries.AddSandboxSecret(ctx, db.AddSandboxSecretParams{SandboxID: sourceID, SecretID: deleted, EnvKey: "DELETED"}); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE secret SET deleted_at = now() WHERE id = $1`, deleted); err != nil {
		t.Fatal(err)
	}
	// Detached before the capture: its key is still in the guest, so it is
	// recorded without a secret, for a fork to clear, never to re-bind.
	gone := seedSecret(t, teamID)
	if _, err := testQueries.AddSandboxSecret(ctx, db.AddSandboxSecretParams{SandboxID: sourceID, SecretID: gone, EnvKey: "DETACHED"}); err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.DeleteSandboxSecretBinding(ctx, db.DeleteSandboxSecretBindingParams{SandboxID: sourceID, EnvKey: "DETACHED"}); err != nil {
		t.Fatal(err)
	}
	if err := testQueries.RecordDetachedSecretKey(ctx, db.RecordDetachedSecretKeyParams{SandboxID: sourceID, EnvKey: "DETACHED"}); err != nil {
		t.Fatal(err)
	}
	snap, err := testQueries.CreateSandboxSnapshot(ctx, db.CreateSandboxSnapshotParams{
		ID: uuid.New(), TeamID: teamID, SandboxID: sourceID, Kind: "mem+fs",
		SweepAfter: time.Now().Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create snapshot row: %v", err)
	}
	r := newRouterWithSigner(t)
	body := fmt.Sprintf(`{"name":"fork","from_snapshot":%q}`, snap.ID)

	if w := do(r, "POST", "/sandboxes", apiKey, body); w.Code != http.StatusConflict {
		t.Fatalf("create from a snapshot still creating: %d %s", w.Code, w.Body.String())
	}
	var recorded []map[string]string
	if err := json.Unmarshal(snap.SecretBindings, &recorded); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, b := range recorded {
		keys[b["env_key"]] = b["secret_id"]
	}
	if len(keys) != 3 || keys["TOKEN"] != secretID.String() || keys["DELETED"] != deleted.String() || keys["DETACHED"] != "" {
		t.Fatalf("recorded bindings = %s; want the live and deleted secrets and the detached key without one", snap.SecretBindings)
	}
	vmstate, mem, overlay := "/saved/s/vmstate.snap", "/saved/s/mem.diff", "/saved/s/overlay.ext4"
	if _, err := testQueries.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: snap.ID, SnapshotPath: &vmstate, MemPath: &mem, OverlayPath: &overlay, SizeBytes: 1}); err != nil {
		t.Fatal(err)
	}
	_, otherKey := seedTeamAndKey(t)
	if w := do(r, "POST", "/sandboxes", otherKey, body); w.Code != http.StatusNotFound {
		t.Fatalf("another team's create: %d %s", w.Code, w.Body.String())
	}
	// A host whose daemon cannot install a fork's rules before its guest runs
	// is never asked to fork.
	if w := do(r, "POST", "/sandboxes", apiKey, body); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("fork on a host without snapshot forks: %d %s", w.Code, w.Body.String())
	}
	if err := testQueries.SyncHostCapabilities(ctx, db.SyncHostCapabilitiesParams{
		HostID: hostID, Capabilities: []string{preview.HostCapabilityPorts, preview.HostCapabilitySavedSnapshots, preview.HostCapabilitySnapshotForks},
	}); err != nil {
		t.Fatal(err)
	}

	w := do(r, "POST", "/sandboxes", apiKey, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create from snapshot: %d %s", w.Code, w.Body.String())
	}
	resp := mustJSON(t, w)
	if resp["source_snapshot_id"] != snap.ID.String() || resp["timeout_seconds"].(float64) != 900 || resp["status"] != "active" {
		t.Fatalf("response = %v; want the source, its timeout and active", resp)
	}
	forkID, _ := uuid.Parse(resp["id"].(string))
	sb, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: forkID, TeamID: teamID})
	if err != nil {
		t.Fatal(err)
	}
	if !sb.SourceSnapshotID.Valid || uuid.UUID(sb.SourceSnapshotID.Bytes) != snap.ID || sb.HostID != hostID {
		t.Errorf("row source=%v host=%s; want the snapshot on its host", sb.SourceSnapshotID, sb.HostID)
	}
	if sb.BasePath == nil || *sb.BasePath != "/templates/t/base.ext4" || sb.SnapshotPath == nil || *sb.SnapshotPath != vmstate || sb.MemPath == nil || *sb.MemPath != mem || sb.DiskMib != 4096 {
		t.Errorf("row paths = (%v, %v, %v) disk %v; want the snapshot's", sb.BasePath, sb.SnapshotPath, sb.MemPath, sb.DiskMib)
	}
	if !strings.Contains(string(sb.NetworkConfig), "10.0.0.0/8") {
		t.Errorf("row network_config = %s; want the inherited rules, which a resume reapplies", sb.NetworkConfig)
	}
	if sb.HadSecretBindings == nil || !*sb.HadSecretBindings {
		t.Errorf("had_secret_bindings = %v; want true for the re-bound secret", sb.HadSecretBindings)
	}
	bound, err := testQueries.ListSandboxSecretBindingMeta(ctx, forkID)
	if err != nil || len(bound) != 1 || bound[0].SecretID != secretID || bound[0].EnvKey != "TOKEN" || bound[0].ProxyToken == nil || *bound[0].ProxyToken == "" {
		t.Errorf("bindings = %+v (%v); want the source's secret under TOKEN with a fresh token", bound, err)
	}
	if got := mustJSON(t, do(r, "GET", "/sandboxes/"+resp["id"].(string), apiKey, "")); got["source_snapshot_id"] != snap.ID.String() {
		t.Errorf("GET source_snapshot_id = %v", got["source_snapshot_id"])
	}

	// Deleting the snapshot takes nothing from the sandbox made from it, and
	// gives no further ones.
	if _, err := testQueries.BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: snap.ID, TeamID: teamID, StaleBefore: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := testQueries.MarkSandboxSnapshotDeleted(ctx, snap.ID); err != nil {
		t.Fatal(err)
	}
	if w := do(r, "POST", "/sandboxes", apiKey, body); w.Code != http.StatusNotFound {
		t.Fatalf("create from a deleted snapshot: %d %s", w.Code, w.Body.String())
	}
	if got, err := testQueries.GetSandbox(ctx, db.GetSandboxParams{ID: forkID, TeamID: teamID}); err != nil || !got.SourceSnapshotID.Valid {
		t.Errorf("sandbox after its source's delete: %v %v", got.SourceSnapshotID, err)
	}
}

// A delete of a snapshot waits for a sandbox being created from it to
// commit, so the build both reference is never left unreferenced between
// the two.
func TestIntegration_SnapshotDeleteWaitsForAForkInsert(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	sourceID, err := insertSandboxRow(ctx, teamID, "lock-source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active', base_path = '/templates/t/base.ext4', disk_mib = 4096 WHERE id = $1`, sourceID); err != nil {
		t.Fatal(err)
	}
	snap, err := testQueries.CreateSandboxSnapshot(ctx, db.CreateSandboxSnapshotParams{
		ID: uuid.New(), TeamID: teamID, SandboxID: sourceID, Kind: "mem+fs",
		SweepAfter: time.Now().Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	vmstate, mem, overlay := "/saved/l/vmstate.snap", "/saved/l/mem.diff", "/saved/l/overlay.ext4"
	if _, err := testQueries.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: snap.ID, SnapshotPath: &vmstate, MemPath: &mem, OverlayPath: &overlay, SizeBytes: 1}); err != nil {
		t.Fatal(err)
	}

	fork, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fork.Rollback(ctx) //nolint:errcheck
	if _, err := db.New(fork).CreateSandboxFromSnapshot(ctx, db.CreateSandboxFromSnapshotParams{
		SnapshotID: snap.ID, TeamID: teamID, ID: uuid.New(), Name: "fork", Status: db.SandboxStatusStarting,
		Metadata: []byte(`{}`), PreviewAccess: preview.AccessPublic,
		SecretIds: []uuid.UUID{}, EnvKeys: []string{}, ProxyTokens: []string{},
	}); err != nil {
		t.Fatalf("fork insert: %v", err)
	}

	del, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer del.Rollback(ctx) //nolint:errcheck
	if _, err := del.Exec(ctx, `SET LOCAL lock_timeout = '200ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = db.New(del).BeginSandboxSnapshotDelete(ctx, db.BeginSandboxSnapshotDeleteParams{ID: snap.ID, TeamID: teamID, StaleBefore: time.Now()})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("delete during an uncommitted fork insert: %v; want it to wait on the snapshot's lock", err)
	}
}

// A snapshot records the source's bindings at one moment: a detach waits
// for the capture's row, and one that committed first is not in it.
func TestIntegration_SnapshotRecordsBindingsUnderTheSecretWriteLock(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	sourceID, err := insertSandboxRow(ctx, teamID, "bind-source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active', base_path = '/templates/t/base.ext4', disk_mib = 4096 WHERE id = $1`, sourceID); err != nil {
		t.Fatal(err)
	}
	secretID := seedSecret(t, teamID)
	if _, err := testQueries.AddSandboxSecret(ctx, db.AddSandboxSecretParams{SandboxID: sourceID, SecretID: secretID, EnvKey: "TOKEN"}); err != nil {
		t.Fatal(err)
	}

	// A detach holds the lock and has deleted the binding, uncommitted.
	detach, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dq := db.New(detach)
	if err := dq.LockSandboxForSecretWrites(ctx, sourceID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := dq.DeleteSandboxSecretBinding(ctx, db.DeleteSandboxSecretBindingParams{SandboxID: sourceID, EnvKey: "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	type result struct {
		row db.SandboxSnapshot
		err error
	}
	done := make(chan result, 1)
	go func() {
		tx, err := testPool.Begin(ctx)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		q := db.New(tx)
		if err := q.LockSandboxForSecretWrites(ctx, sourceID.String()); err != nil {
			done <- result{err: err}
			return
		}
		row, err := q.CreateSandboxSnapshot(ctx, db.CreateSandboxSnapshotParams{
			ID: uuid.New(), TeamID: teamID, SandboxID: sourceID, Kind: "mem+fs", SweepAfter: time.Now().Add(15 * time.Minute),
		})
		if err == nil {
			err = tx.Commit(ctx)
		}
		done <- result{row, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("the capture did not wait for the detach: %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
	if err := detach.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.row.SecretBindings) != "[]" {
		t.Fatalf("snapshot bindings = %s; a detach that committed first is not the snapshot's", r.row.SecretBindings)
	}
}

// No secret changes while a capture may still be imaging the guest, so the
// image holds the bindings the snapshot records; once it settles, they may.
func TestIntegration_SecretAttachWaitsOutASnapshotCapture(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	sourceID, err := insertSandboxRow(ctx, teamID, "attach-source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active', ip_address = '192.0.2.10', base_path = '/templates/t/base.ext4', disk_mib = 4096 WHERE id = $1`, sourceID); err != nil {
		t.Fatal(err)
	}
	secretID := seedSecret(t, teamID)
	var secretName string
	if err := testPool.QueryRow(ctx, `SELECT name FROM secret WHERE id = $1`, secretID).Scan(&secretName); err != nil {
		t.Fatal(err)
	}
	snap, err := testQueries.CreateSandboxSnapshot(ctx, db.CreateSandboxSnapshotParams{
		ID: uuid.New(), TeamID: teamID, SandboxID: sourceID, Kind: "mem+fs", SweepAfter: time.Now().Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := newRouterWithSigner(t)
	body := fmt.Sprintf(`{"env_key":"TOKEN","secret_name":%q}`, secretName)
	w := do(r, "POST", "/sandboxes/"+sourceID.String()+"/secrets", apiKey, body)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "snapshot_in_progress") {
		t.Fatalf("attach during a capture: %d %s; want snapshot_in_progress", w.Code, w.Body.String())
	}
	if bound, err := testQueries.ListSandboxSecretBindingMeta(ctx, sourceID); err != nil || len(bound) != 0 {
		t.Fatalf("bindings after a refused attach: %+v %v", bound, err)
	}
	// However old: the sweep captures a creating row again until it settles.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET created_at = now() - interval '3 hours' WHERE id = $1`, snap.ID); err != nil {
		t.Fatal(err)
	}
	if w := do(r, "POST", "/sandboxes/"+sourceID.String()+"/secrets", apiKey, body); w.Code != http.StatusConflict {
		t.Fatalf("attach during an old capture: %d %s; want snapshot_in_progress", w.Code, w.Body.String())
	}
	overlay := "/saved/a/overlay.ext4"
	vmstate, mem := "/saved/a/vmstate.snap", "/saved/a/mem.diff"
	if _, err := testQueries.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: snap.ID, OverlayPath: &overlay, SnapshotPath: &vmstate, MemPath: &mem, SizeBytes: 1}); err != nil {
		t.Fatal(err)
	}
	if w := do(r, "POST", "/sandboxes/"+sourceID.String()+"/secrets", apiKey, body); w.Code >= 300 {
		t.Fatalf("attach once the capture settled: %d %s", w.Code, w.Body.String())
	}
}

// An attach undone after snapshots recorded it has the binding withdrawn
// from each taken since it began, settled or not, its key kept without the
// secret; an older snapshot's binding of the same key and secret stays.
func TestIntegration_UndoneAttachIsWithdrawnFromSnapshotsSinceItBegan(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	sourceID, err := insertSandboxRow(ctx, teamID, "undo-source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active', base_path = '/templates/t/base.ext4', disk_mib = 4096 WHERE id = $1`, sourceID); err != nil {
		t.Fatal(err)
	}
	secretID := seedSecret(t, teamID)
	if _, err := testQueries.AddSandboxSecret(ctx, db.AddSandboxSecretParams{SandboxID: sourceID, SecretID: secretID, EnvKey: "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	create := func() db.SandboxSnapshot {
		t.Helper()
		row, err := testQueries.CreateSandboxSnapshot(ctx, db.CreateSandboxSnapshotParams{
			ID: uuid.New(), TeamID: teamID, SandboxID: sourceID, Kind: "mem+fs", SweepAfter: time.Now().Add(15 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	ready := func(id uuid.UUID) {
		t.Helper()
		overlay, vmstate, mem := "/saved/u/overlay.ext4", "/saved/u/vmstate.snap", "/saved/u/mem.diff"
		if _, err := testQueries.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: id, OverlayPath: &overlay, SnapshotPath: &vmstate, MemPath: &mem, SizeBytes: 1}); err != nil {
			t.Fatal(err)
		}
	}
	// An earlier, legitimate binding of the same key and secret.
	older := create()
	ready(older.ID)
	if _, err := testPool.Exec(ctx, `UPDATE sandbox_snapshot SET created_at = now() - interval '1 hour' WHERE id = $1`, older.ID); err != nil {
		t.Fatal(err)
	}
	var since time.Time
	if err := testPool.QueryRow(ctx, `SELECT now()`).Scan(&since); err != nil {
		t.Fatal(err)
	}
	settled := create()
	ready(settled.ID)
	inFlight := create()

	// The undo, as the attach handler runs it.
	if _, err := testQueries.DeleteSandboxSecretBinding(ctx, db.DeleteSandboxSecretBindingParams{SandboxID: sourceID, EnvKey: "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	if err := testQueries.RecordDetachedSecretKey(ctx, db.RecordDetachedSecretKeyParams{SandboxID: sourceID, EnvKey: "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	if err := testQueries.WithdrawBindingFromSnapshots(ctx, db.WithdrawBindingFromSnapshotsParams{SandboxID: sourceID, EnvKey: "TOKEN", SecretID: secretID, Since: since}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{settled.ID, inFlight.ID} {
		got, err := testQueries.GetSandboxSnapshotUnscoped(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(got.SecretBindings), secretID.String()) || !strings.Contains(string(got.SecretBindings), `"TOKEN"`) {
			t.Fatalf("%s record after the undo = %s; want the key without its secret", got.Status, got.SecretBindings)
		}
	}
	if kept, err := testQueries.GetSandboxSnapshotUnscoped(ctx, older.ID); err != nil || !strings.Contains(string(kept.SecretBindings), secretID.String()) {
		t.Fatalf("older record = %s (%v); want it untouched", kept.SecretBindings, err)
	}
	// A re-attach of the key forgets it was detached.
	if _, err := testQueries.AddSandboxSecret(ctx, db.AddSandboxSecretParams{SandboxID: sourceID, SecretID: secretID, EnvKey: "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	if err := testQueries.ForgetDetachedSecretKey(ctx, db.ForgetDetachedSecretKeyParams{SandboxID: sourceID, EnvKey: "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM sandbox_secret_detached WHERE sandbox_id = $1`, sourceID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tombstones after a re-attach: %d %v", n, err)
	}
}

// A key detached from a running sandbox is cleared in its guest and not
// remembered; one detached while it is paused is remembered until then,
// and only the most recent are.
func TestIntegration_DetachedKeysAreBounded(t *testing.T) {
	ctx := context.Background()
	teamID, apiKey := seedTeamAndKey(t)
	sourceID, err := insertSandboxRow(ctx, teamID, "detach-source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'active', ip_address = '192.0.2.11' WHERE id = $1`, sourceID); err != nil {
		t.Fatal(err)
	}
	secretID := seedSecret(t, teamID)
	var secretName string
	if err := testPool.QueryRow(ctx, `SELECT name FROM secret WHERE id = $1`, secretID).Scan(&secretName); err != nil {
		t.Fatal(err)
	}
	r := newRouterWithSigner(t)
	tombstones := func() int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM sandbox_secret_detached WHERE sandbox_id = $1`, sourceID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	attachDetach := func(key string) {
		t.Helper()
		if w := do(r, "POST", "/sandboxes/"+sourceID.String()+"/secrets", apiKey, fmt.Sprintf(`{"env_key":%q,"secret_name":%q}`, key, secretName)); w.Code >= 300 {
			t.Fatalf("attach %s: %d %s", key, w.Code, w.Body.String())
		}
		if w := do(r, "DELETE", "/sandboxes/"+sourceID.String()+"/secrets/"+key, apiKey, ""); w.Code != http.StatusNoContent {
			t.Fatalf("detach %s: %d %s", key, w.Code, w.Body.String())
		}
	}
	attachDetach("RUNNING_KEY")
	if n := tombstones(); n != 0 {
		t.Fatalf("tombstones after a detach the guest applied: %d; want none", n)
	}
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET status = 'paused' WHERE id = $1`, sourceID); err != nil {
		t.Fatal(err)
	}
	attachDetach("PAUSED_KEY")
	if n := tombstones(); n != 1 {
		t.Fatalf("tombstones after a detach from a paused sandbox: %d; want 1", n)
	}
	for i := 0; i < 70; i++ {
		if err := testQueries.RecordDetachedSecretKey(ctx, db.RecordDetachedSecretKeyParams{SandboxID: sourceID, EnvKey: fmt.Sprintf("CHURN_%02d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := testQueries.PruneDetachedSecretKeys(ctx, db.PruneDetachedSecretKeysParams{SandboxID: sourceID, Keep: 64}); err != nil {
		t.Fatal(err)
	}
	if n := tombstones(); n != 64 {
		t.Fatalf("tombstones after churn: %d; want the 64 most recent", n)
	}
}
