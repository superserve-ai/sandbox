//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
)

func TestIntegration_DrainSeparatesPlacementFromOwnerAndOrdersTransitions(t *testing.T) {
	ctx := context.Background()
	id := seedActivePreviewHost(t, preview.HostCapabilityPorts)
	var revision int64
	for _, target := range []string{"draining", "active", "draining"} {
		host, err := testQueries.PrepareHostAdmission(ctx, db.PrepareHostAdmissionParams{ID: id, Status: target, HeartbeatAfter: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}})
		if err != nil {
			t.Fatal(err)
		}
		if host.AdmissionRevision <= revision {
			t.Fatal("revision did not advance")
		}
		revision = host.AdmissionRevision
		placed, err := testQueries.HostHasCapabilities(ctx, db.HostHasCapabilitiesParams{HostID: id, RequiredCapabilities: []string{preview.HostCapabilityPorts}})
		if err != nil || placed != (target == "active") {
			t.Fatal("placement status", target, placed, err)
		}
		owner, err := testQueries.OwnerHostHasCapabilities(ctx, db.OwnerHostHasCapabilitiesParams{HostID: id, RequiredCapabilities: []string{preview.HostCapabilityPorts}})
		if err != nil || !owner {
			t.Fatal("owner rejected during drain", err)
		}
	}
	for _, target := range []string{"unhealthy", "provisioning"} {
		if _, err := testPool.Exec(ctx, "UPDATE host SET status=$2 WHERE id=$1", id, target); err != nil {
			t.Fatal(err)
		}
		owner, err := testQueries.OwnerHostHasCapabilities(ctx, db.OwnerHostHasCapabilitiesParams{HostID: id, RequiredCapabilities: []string{preview.HostCapabilityPorts}})
		if err != nil || owner {
			t.Fatal("unusable owner accepted", target, owner, err)
		}
	}
}

func TestIntegration_DrainCountsPausedAndFailedOwnership(t *testing.T) {
	ctx := context.Background()
	id := seedActivePreviewHost(t, preview.HostCapabilityPorts)
	for _, state := range []string{"active", "paused", "failed"} {
		sandbox := seedPrivatePreviewSandbox(t, testSystemTeamID, id, "drain-"+state)
		if _, err := testPool.Exec(ctx, "UPDATE sandbox SET status=$2 WHERE id=$1", sandbox, state); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := testQueries.HostOwnershipCounts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]int64{}
	for _, row := range counts {
		found[row.Status] = row.Count
	}
	for _, state := range []string{"active", "paused", "failed"} {
		if found[state] != 1 {
			t.Fatal("ownership disappeared", found)
		}
	}
}

func TestIntegration_OnlyUnactivatedCreateCanBeReassigned(t *testing.T) {
	ctx := context.Background()
	source := seedActivePreviewHost(t, preview.HostCapabilityPorts)
	destination := seedActivePreviewHost(t, preview.HostCapabilityPorts)
	sandbox := seedPrivatePreviewSandbox(t, testSystemTeamID, source, "refused-create")
	args := db.ReassignRejectedCreateHostParams{ID: sandbox, TeamID: testSystemTeamID, OldHostID: source, NewHostID: destination}
	for _, state := range []string{"paused", "active", "failed"} {
		if _, err := testPool.Exec(ctx, "UPDATE sandbox SET status=$2 WHERE id=$1", sandbox, state); err != nil {
			t.Fatal(err)
		}
		if n, err := testQueries.ReassignRejectedCreateHost(ctx, args); err != nil || n != 0 {
			t.Fatal("existing owner reassigned", state, n, err)
		}
	}
	if _, err := testPool.Exec(ctx, "UPDATE sandbox SET status='starting',ip_address=NULL,pid=NULL,snapshot_id=NULL WHERE id=$1", sandbox); err != nil {
		t.Fatal(err)
	}
	if n, err := testQueries.ReassignRejectedCreateHost(ctx, args); err != nil || n != 1 {
		t.Fatal("refused create not reassigned", n, err)
	}
	if n, err := testQueries.ReassignRejectedCreateHost(ctx, args); err != nil || n != 0 {
		t.Fatal("source CAS did not fence retry", n, err)
	}
}
