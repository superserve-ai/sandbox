//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
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
	snap, err := testQueries.CreateSandboxSnapshot(ctx, db.CreateSandboxSnapshotParams{
		ID: uuid.New(), TeamID: teamID, SandboxID: sourceID, Kind: "mem+fs",
		SecretBindings: []byte(fmt.Sprintf(`[{"env_key":"TOKEN","secret_id":%q}]`, secretID)),
		SweepAfter:     time.Now().Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create snapshot row: %v", err)
	}
	r := newRouterWithSigner(t)
	body := fmt.Sprintf(`{"name":"fork","from_snapshot":%q}`, snap.ID)

	if w := do(r, "POST", "/sandboxes", apiKey, body); w.Code != http.StatusConflict {
		t.Fatalf("create from a snapshot still creating: %d %s", w.Code, w.Body.String())
	}
	vmstate, mem, overlay := "/saved/s/vmstate.snap", "/saved/s/mem.diff", "/saved/s/overlay.ext4"
	if _, err := testQueries.MarkSandboxSnapshotReady(ctx, db.MarkSandboxSnapshotReadyParams{ID: snap.ID, SnapshotPath: &vmstate, MemPath: &mem, OverlayPath: &overlay, SizeBytes: 1}); err != nil {
		t.Fatal(err)
	}
	_, otherKey := seedTeamAndKey(t)
	if w := do(r, "POST", "/sandboxes", otherKey, body); w.Code != http.StatusNotFound {
		t.Fatalf("another team's create: %d %s", w.Code, w.Body.String())
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
		SecretBindings: []byte("[]"), SweepAfter: time.Now().Add(15 * time.Minute),
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
