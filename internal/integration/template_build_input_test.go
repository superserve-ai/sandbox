//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_TemplateBuildCapturesImmutableInputs(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	tpl, err := testQueries.CreateTemplate(ctx, db.CreateTemplateParams{
		TeamID: teamID, Name: "input-" + uuid.NewString(),
		BuildSpec: []byte(`{"from":"example/image:original"}`), Vcpu: 1, MemoryMib: 1024, DiskMib: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	build, err := testQueries.CreateTemplateBuild(ctx, db.CreateTemplateBuildParams{
		TemplateID: tpl.ID, TeamID: teamID, BuildSpecHash: "original-input",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE template SET build_spec='{"from":"example/image:new"}',
		vcpu=2, memory_mib=2048, disk_mib=8192 WHERE id=$1`, tpl.ID); err != nil {
		t.Fatal(err)
	}
	input, err := testQueries.GetTemplateBuildInput(ctx, build.ID)
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		From string `json:"from"`
	}
	if err := json.Unmarshal(input.BuildSpec, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.From != "example/image:original" || input.Vcpu != 1 || input.MemoryMib != 1024 || input.DiskMib != 4096 {
		t.Fatalf("submission inputs changed: %+v, %s", input, input.BuildSpec)
	}
	if _, err := testPool.Exec(ctx, `UPDATE template_build_input SET vcpu=8 WHERE build_id=$1`, build.ID); err == nil {
		t.Fatal("persisted input snapshot accepted a mutation")
	}
}

func TestIntegration_TemplateWithBuildCapturesInputsAtomically(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	row, err := testQueries.CreateTemplateWithBuild(ctx, db.CreateTemplateWithBuildParams{
		TeamID: teamID, Name: "input-" + uuid.NewString(),
		BuildSpec: []byte(`{"from":"example/image:latest"}`), Vcpu: 8, MemoryMib: 8192, DiskMib: 16384,
		BuildSpecHash: "initial-input",
	})
	if err != nil {
		t.Fatal(err)
	}
	input, err := testQueries.GetTemplateBuildInput(ctx, row.BuildID)
	if err != nil {
		t.Fatal(err)
	}
	if input.Vcpu != 8 || input.MemoryMib != 8192 || input.DiskMib != 16384 {
		t.Fatalf("initial input capture: %+v", input)
	}
}

func TestIntegration_TemplateBuildInputRollsBackWithSubmission(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q := testQueries.WithTx(tx)
	row, err := q.CreateTemplateWithBuild(ctx, db.CreateTemplateWithBuildParams{
		TeamID: teamID, Name: "input-" + uuid.NewString(),
		BuildSpec: []byte(`{"from":"example/image:latest"}`), Vcpu: 1, MemoryMib: 1024, DiskMib: 4096,
		BuildSpecHash: "rolled-back-input",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetTemplateBuildInput(ctx, row.BuildID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM template_build_input WHERE build_id=$1`, row.BuildID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("rolled-back submission left input state behind")
	}
}

func TestIntegration_TemplateBuildInputSerializesWithEdit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	teamID, _ := seedTeamAndKey(t)
	tpl, err := testQueries.CreateTemplate(ctx, db.CreateTemplateParams{
		TeamID: teamID, Name: "input-" + uuid.NewString(),
		BuildSpec: []byte(`{"from":"example/image:original"}`), Vcpu: 1, MemoryMib: 1024, DiskMib: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(context.Background())
	if _, err := writer.Exec(ctx, `UPDATE template SET build_spec='{"from":"example/image:updated"}',
		vcpu=2, memory_mib=2048, disk_mib=8192 WHERE id=$1`, tpl.ID); err != nil {
		t.Fatal(err)
	}
	reader, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Release()
	type result struct {
		build db.TemplateBuild
		err   error
	}
	done := make(chan result, 1)
	go func() {
		build, err := db.New(reader).CreateTemplateBuild(ctx, db.CreateTemplateBuildParams{
			TemplateID: tpl.ID, TeamID: teamID, BuildSpecHash: "concurrent-input",
		})
		done <- result{build, err}
	}()
	waitForHostBlocker(t, ctx, reader.Conn().PgConn().PID(), writer.Conn().PgConn().PID())
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		input, err := testQueries.GetTemplateBuildInput(ctx, r.build.ID)
		if err != nil {
			t.Fatal(err)
		}
		var spec struct {
			From string `json:"from"`
		}
		if err := json.Unmarshal(input.BuildSpec, &spec); err != nil {
			t.Fatal(err)
		}
		if spec.From != "example/image:updated" || input.Vcpu != 2 || input.MemoryMib != 2048 || input.DiskMib != 8192 {
			t.Fatalf("captured a stale or mixed input after waiting for edit: %+v", input)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
