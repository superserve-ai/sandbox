//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func insertHostAdmissionHost(t *testing.T, tx pgx.Tx, status string) string {
	t.Helper()

	hostID := "admission-" + status + "-" + uuid.NewString()
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO host (
		    id, vmd_addr, proxy_addr, region, status,
		    capacity_memory_mib, capacity_vcpus
		)
		VALUES ($1, '127.0.0.1:1', '127.0.0.1:2', 'test', $2, 1024, 1)
	`, hostID, status); err != nil {
		t.Fatalf("insert %s host: %v", status, err)
	}
	return hostID
}

func insertHostAdmissionSandbox(
	t *testing.T,
	tx pgx.Tx,
	hostID string,
	status string,
) uuid.UUID {
	t.Helper()

	sandboxID := uuid.New()
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO sandbox (id, team_id, name, status, host_id)
		VALUES ($1, $2, $3, $4::sandbox_status, $5)
	`, sandboxID, testSystemTeamID, "host-admission-"+uuid.NewString(), status, hostID); err != nil {
		t.Fatalf("insert %s sandbox: %v", status, err)
	}
	return sandboxID
}

func requireHostAdmissionRejection(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("host admission unexpectedly succeeded")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("host admission error = %T %v, want PostgreSQL error", err, err)
	}
	if pgErr.Code != "SS006" {
		t.Fatalf("host admission SQLSTATE = %s, want SS006: %v", pgErr.Code, err)
	}
	if !strings.Contains(pgErr.Message, "host admission denied") {
		t.Fatalf("host admission message = %q, want admission denial", pgErr.Message)
	}
}

func TestHostAdmissionAllowsActiveHostAndLifecycleCompletion(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	hostID := insertHostAdmissionHost(t, tx, "active")
	startingID := insertHostAdmissionSandbox(t, tx, hostID, "starting")
	resumingID := insertHostAdmissionSandbox(t, tx, hostID, "paused")

	if _, err := tx.Exec(ctx, `
		UPDATE sandbox
		SET status = 'resuming'
		WHERE id = $1
	`, resumingID); err != nil {
		t.Fatalf("admit resume on active host: %v", err)
	}

	var templateID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id
		FROM template
		WHERE team_id = $1
		ORDER BY created_at
		LIMIT 1
	`, testSystemTeamID).Scan(&templateID); err != nil {
		t.Fatalf("find template: %v", err)
	}
	var buildID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO template_build (
		    template_id, team_id, build_spec_hash
		)
		VALUES ($1, $2, $3)
		RETURNING id
	`, templateID, testSystemTeamID, uuid.NewString()).Scan(&buildID); err != nil {
		t.Fatalf("insert pending template build: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE template_build
		SET status = 'building',
		    vmd_host_id = $2,
		    vmd_build_vm_id = $3
		WHERE id = $1 AND status = 'pending'
	`, buildID, hostID, "build-"+uuid.NewString()); err != nil {
		t.Fatalf("dispatch template build on active host: %v", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE host SET status = 'draining' WHERE id = $1
	`, hostID); err != nil {
		t.Fatalf("drain admitted host: %v", err)
	}

	// These are bookkeeping completions for launches admitted while the host
	// was active. A later drain must not strand either row in a transitional
	// state.
	for _, sandboxID := range []uuid.UUID{startingID, resumingID} {
		if _, err := tx.Exec(ctx, `
			UPDATE sandbox SET status = 'active' WHERE id = $1
		`, sandboxID); err != nil {
			t.Fatalf("complete admitted sandbox %s after drain: %v", sandboxID, err)
		}
	}
}

func TestHostAdmissionSerializesWithHostDrain(t *testing.T) {
	ctx := context.Background()
	hostID := "admission-lock-" + uuid.NewString()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO host (
		    id, vmd_addr, proxy_addr, region, status,
		    capacity_memory_mib, capacity_vcpus
		)
		VALUES ($1, '127.0.0.1:1', '127.0.0.1:2', 'test', 'active', 1024, 1)
	`, hostID); err != nil {
		t.Fatalf("insert active host: %v", err)
	}

	sandboxID := uuid.New()
	defer func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM sandbox WHERE id = $1`, sandboxID)
		_, _ = testPool.Exec(context.Background(), `DELETE FROM host WHERE id = $1`, hostID)
	}()

	admissionTx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin admission: %v", err)
	}
	defer admissionTx.Rollback(ctx)
	if _, err := admissionTx.Exec(ctx, `
		INSERT INTO sandbox (id, team_id, name, status, host_id)
		VALUES ($1, $2, $3, 'starting', $4)
	`, sandboxID, testSystemTeamID, "serialized-"+uuid.NewString(), hostID); err != nil {
		t.Fatalf("admit sandbox: %v", err)
	}

	drainTx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin drain: %v", err)
	}
	defer drainTx.Rollback(ctx)
	if _, err := drainTx.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
		t.Fatalf("set drain lock timeout: %v", err)
	}
	_, err = drainTx.Exec(ctx, `
		UPDATE host SET status = 'draining' WHERE id = $1
	`, hostID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("concurrent drain error = %v, want lock timeout 55P03", err)
	}
	if err := drainTx.Rollback(ctx); err != nil {
		t.Fatalf("rollback blocked drain: %v", err)
	}

	if err := admissionTx.Commit(ctx); err != nil {
		t.Fatalf("commit admission: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE host SET status = 'draining' WHERE id = $1
	`, hostID); err != nil {
		t.Fatalf("drain after admission commit: %v", err)
	}
}

func TestHostAdmissionRejectsUnavailableSandboxInsert(t *testing.T) {
	for _, status := range []string{"draining", "unhealthy"} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback(ctx)

			hostID := insertHostAdmissionHost(t, tx, status)
			_, err = tx.Exec(ctx, `
				INSERT INTO sandbox (id, team_id, name, status, host_id)
				VALUES ($1, $2, $3, 'starting', $4)
			`, uuid.New(), testSystemTeamID, "rejected-"+uuid.NewString(), hostID)
			requireHostAdmissionRejection(t, err)
		})
	}
}

func TestHostAdmissionTriggerRunsForNonOwnerWithoutFunctionExecute(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	role := "host_admission_app_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedRole := pgx.Identifier{role}.Sanitize()
	if _, err := tx.Exec(ctx, "CREATE ROLE "+quotedRole+" NOLOGIN BYPASSRLS"); err != nil {
		t.Fatalf("create app role: %v", err)
	}
	if _, err := tx.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+quotedRole); err != nil {
		t.Fatalf("grant schema usage: %v", err)
	}
	if _, err := tx.Exec(ctx, "GRANT INSERT ON sandbox TO "+quotedRole); err != nil {
		t.Fatalf("grant sandbox insert: %v", err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+quotedRole); err != nil {
		t.Fatalf("assume app role: %v", err)
	}

	// Trigger functions are intentionally not executable by PUBLIC. PostgreSQL
	// invokes them through the trigger, and their SECURITY DEFINER owner can
	// still call the private admission helper.
	_, err = tx.Exec(ctx, `
		INSERT INTO sandbox (id, team_id, name, status, host_id)
		VALUES ($1, $2, $3, 'starting', $4)
	`, uuid.New(), testSystemTeamID, "non-owner-"+uuid.NewString(), "missing-host")
	requireHostAdmissionRejection(t, err)
}

func TestHostAdmissionAllowsLegacyFallbackOnlyWithEmptyHostTable(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	// Isolate the compatibility condition from the suite's seeded default
	// host. The rollback restores every host and capability row.
	if _, err := tx.Exec(ctx, `LOCK TABLE host IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock host registry: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM host`); err != nil {
		t.Fatalf("empty host registry: %v", err)
	}
	insertHostAdmissionSandbox(t, tx, "legacy-default", "starting")
}

func TestHostAdmissionRejectsResumeOnDrainingHost(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	hostID := insertHostAdmissionHost(t, tx, "draining")
	sandboxID := insertHostAdmissionSandbox(t, tx, hostID, "paused")
	_, err = tx.Exec(ctx, `
		UPDATE sandbox SET status = 'resuming' WHERE id = $1
	`, sandboxID)
	requireHostAdmissionRejection(t, err)
}

func TestHostAdmissionRejectsLiveSandboxHostChange(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	activeHostID := insertHostAdmissionHost(t, tx, "active")
	drainingHostID := insertHostAdmissionHost(t, tx, "draining")
	sandboxID := insertHostAdmissionSandbox(t, tx, activeHostID, "active")

	_, err = tx.Exec(ctx, `
		UPDATE sandbox SET host_id = $2 WHERE id = $1
	`, sandboxID, drainingHostID)
	requireHostAdmissionRejection(t, err)
}

func TestHostAdmissionRejectsTemplateDispatchOnDrainingHost(t *testing.T) {
	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	hostID := insertHostAdmissionHost(t, tx, "draining")
	var templateID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id
		FROM template
		WHERE team_id = $1
		ORDER BY created_at
		LIMIT 1
	`, testSystemTeamID).Scan(&templateID); err != nil {
		t.Fatalf("find template: %v", err)
	}

	var buildID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO template_build (
		    template_id, team_id, build_spec_hash
		)
		VALUES ($1, $2, $3)
		RETURNING id
	`, templateID, testSystemTeamID, uuid.NewString()).Scan(&buildID); err != nil {
		t.Fatalf("insert pending template build: %v", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE template_build
		SET status = 'building',
		    vmd_host_id = $2,
		    vmd_build_vm_id = $3
		WHERE id = $1 AND status = 'pending'
	`, buildID, hostID, "build-"+uuid.NewString())
	requireHostAdmissionRejection(t, err)
}
