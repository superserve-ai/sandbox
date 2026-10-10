//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/db"
)

// A create reads the template's paths, then boots the VM from them in parallel
// with inserting its row. Between those two there is a live user of that
// generation that nothing records, so a rebuild landing in the window would
// leave a row pinning paths the collector may delete — and unlinking them does
// not disturb the running VM, so the sandbox commits and breaks later instead
// of failing now. The insert therefore has to refuse paths the template has
// moved off.
func TestIntegration_CreateRefusesAGenerationTheTemplateHasMovedOff(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	tpl, err := testQueries.CreateTemplate(ctx, db.CreateTemplateParams{
		TeamID: teamID, Name: "pin-" + uuid.NewString(),
		BuildSpec: []byte(`{"from":"example/image:stable"}`), Vcpu: 2, MemoryMib: 2048, DiskMib: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	generation := func(id string) (snapshot, mem, base string) {
		root := "/snapshots/templates/" + tpl.ID.String() + "/" + id + "/"
		return root + "vmstate.snap", root + "mem.snap", root + "base.ext4"
	}
	oldSnapshot, oldMem, oldBase := generation("build-old")
	if _, err := testPool.Exec(ctx, `
		UPDATE template SET status='ready', snapshot_path=$2, mem_path=$3, base_path=$4
		WHERE id=$1`, tpl.ID, oldSnapshot, oldMem, oldBase); err != nil {
		t.Fatal(err)
	}

	create := func(snapshot, mem, base string) error {
		_, err := testQueries.CreateSandboxFromTemplate(ctx, db.CreateSandboxFromTemplateParams{
			ID: uuid.New(), TeamID: teamID, Name: "s-" + uuid.NewString(),
			Status: db.SandboxStatusStarting, VcpuCount: 2, MemoryMib: 2048,
			HostID: testDefaultHostID, ID_2: tpl.ID,
			TeamID_2: teamID, TeamID_3: testSystemTeamID,
			SnapshotPath: &snapshot, MemPath: &mem, BasePath: &base,
			PreviewAccess: "public",
		})
		return err
	}

	// The generation the caller read is still current: the row lands, and from
	// then on it is what keeps that generation from being collected.
	if err := create(oldSnapshot, oldMem, oldBase); err != nil {
		t.Fatalf("create on the current generation was refused: %v", err)
	}

	// A rebuild promotes a new generation while another create is mid-flight.
	newSnapshot, newMem, newBase := generation("build-new")
	if _, err := testPool.Exec(ctx, `
		UPDATE template SET snapshot_path=$2, mem_path=$3, base_path=$4 WHERE id=$1`,
		tpl.ID, newSnapshot, newMem, newBase); err != nil {
		t.Fatal(err)
	}

	err = create(oldSnapshot, oldMem, oldBase)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a create pinned a generation the template had moved off: %v", err)
	}

	// The template is still servable, which is what separates this from a
	// deleted template and makes it worth retrying.
	servable, err := testQueries.TemplateStillServable(ctx, db.TemplateStillServableParams{
		TemplateID: tpl.ID, TeamID: teamID, SystemTeamID: testSystemTeamID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !servable {
		t.Fatal("the template reads as gone, so the race would be reported as a 404")
	}

	// Reading the template again yields the new generation, which inserts.
	if err := create(newSnapshot, newMem, newBase); err != nil {
		t.Fatalf("create on the promoted generation was refused: %v", err)
	}
}
