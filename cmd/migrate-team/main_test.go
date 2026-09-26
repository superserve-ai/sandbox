//go:build integration

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/promotiontest"
)

// The tests drive all four phases against two real databases created in the
// same Postgres instance CI already provides (postgres:16 via DATABASE_URL),
// with the full migration set applied to both — so cell-seeded rows (roles,
// feature flags, pricing plans) genuinely differ by id between the two, the
// way they do between prod cells.

var (
	srcURL, dstURL string
	srcPool        *pgxpool.Pool
	dstPool        *pgxpool.Pool
)

const (
	sourceHostID = "use1"
	destHostID   = "usw2"
	destRegion   = "usw"
)

func TestMain(m *testing.M) {
	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@localhost:5432/sandbox_test?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot connect to test database: %v\n", err)
		os.Exit(1)
	}
	for _, name := range []string{"migrate_team_use", "migrate_team_usw"} {
		if _, err := admin.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, name)); err != nil {
			fmt.Fprintf(os.Stderr, "drop %s: %v\n", name, err)
			os.Exit(1)
		}
		if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, name)); err != nil {
			fmt.Fprintf(os.Stderr, "create %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	admin.Close(ctx)

	srcURL, err = rewriteDBName(adminURL, "migrate_team_use")
	if err == nil {
		dstURL, err = rewriteDBName(adminURL, "migrate_team_usw")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "rewrite database url: %v\n", err)
		os.Exit(1)
	}

	srcPool, err = pgxpool.New(ctx, srcURL)
	if err == nil {
		dstPool, err = pgxpool.New(ctx, dstURL)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "open pools: %v\n", err)
		os.Exit(1)
	}
	defer srcPool.Close()
	defer dstPool.Close()

	for _, pool := range []*pgxpool.Pool{srcPool, dstPool} {
		if err := applyMigrations(ctx, pool); err != nil {
			fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
			os.Exit(1)
		}
		if err := promotiontest.Install(ctx, pool); err != nil {
			fmt.Fprintf(os.Stderr, "install trusted identity fixture: %v\n", err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}

func rewriteDBName(raw, name string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}

// applyMigrations mirrors internal/integration: run every SQL file under
// supabase/migrations in name order.
func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "supabase", "migrations")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("could not find supabase/migrations from %s", dir)
		}
		dir = parent
	}

	entries, err := os.ReadDir(filepath.Join(dir, "supabase", "migrations"))
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, "supabase", "migrations", e.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("exec %s: %w", e.Name(), err)
		}
	}
	return nil
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func countScoped(t *testing.T, pool *pgxpool.Pool, spec tableSpec, teamID uuid.UUID) int64 {
	t.Helper()
	var n int64
	q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s`, spec.name, spec.scope)
	if err := pool.QueryRow(context.Background(), q, teamID).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", spec.name, err)
	}
	return n
}

func scanString(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return s
}

// fixture is the synthetic team seeded into the source cell.
type fixture struct {
	team, teamB, teamC      uuid.UUID
	owner, member           uuid.UUID
	tpl, build              uuid.UUID
	sb1, sb2, sb3, sbActive uuid.UUID
	sb4                     uuid.UUID
	sysTplSrc, sysTplDst    uuid.UUID
	snap1, snap2            uuid.UUID
	secret                  uuid.UUID
	expectedCounts          map[string]int64
	expectedDirs            []string
}

func seedFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		team:      uuid.New(),
		teamB:     uuid.New(),
		teamC:     uuid.New(),
		owner:     uuid.New(),
		member:    uuid.New(),
		tpl:       uuid.New(),
		build:     uuid.New(),
		sb1:       uuid.New(),
		sb2:       uuid.New(),
		sb3:       uuid.New(),
		sb4:       uuid.New(),
		sbActive:  uuid.New(),
		sysTplSrc: uuid.New(),
		sysTplDst: uuid.New(),
		snap1:     uuid.New(),
		snap2:     uuid.New(),
		secret:    uuid.New(),
	}
	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)

	// Dest cell: the host sandboxes will be re-pointed at, plus one member
	// profile that already exists there (signed in against the dest cell
	// before the migration) — copy must not clobber it.
	mustExec(t, dstPool, `
		INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
		VALUES ($1, '10.1.0.1:50051', '10.1.0.1:8080', $2, 65536, 32)
		ON CONFLICT (id) DO NOTHING`, destHostID, destRegion)
	mustExec(t, dstPool, `
		INSERT INTO profile (id, email, provider, provider_id)
		VALUES ($1, 'pre-existing@example.com', 'google', 'google-pre')
		ON CONFLICT (id) DO NOTHING`, f.member)

	// Source cell: the team under migration.
	mustExec(t, srcPool, `INSERT INTO team (id, name) VALUES ($1, 'migration-drill')`, f.team)
	// This fixture supplies its own credit ledger below; suppress automatic
	// signup redemption before the owner chain is inserted.
	mustExec(t, srcPool, `DELETE FROM team_signup_trial_provenance WHERE team_id = $1 AND completed_at IS NULL`, f.team)
	mustExec(t, srcPool, `DELETE FROM team_credit_grant WHERE team_id = $1 AND reason = 'signup trial credit'`, f.team)
	mustExec(t, srcPool, `DELETE FROM team_trial_eligibility_cache WHERE team_id = $1`, f.team)
	mustExec(t, srcPool, `INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, 'owner@example.com', 'google', 'google-owner')`, f.owner)
	mustExec(t, srcPool, `INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, 'member@example.com', 'google', 'google-member')`, f.member)
	mustExec(t, srcPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner'), ($1, $3, 'member')`, f.team, f.owner, f.member)
	mustExec(t, srcPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active'), ($1, $3, 'active')`, f.team, f.owner, f.member)
	mustExec(t, srcPool, `
		INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id, granted_by)
		SELECT $2, r.id, 'team', $1, $2 FROM roles r WHERE r.name = 'team_owner'`, f.team, f.owner)
	mustExec(t, srcPool, `
		INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id, granted_by)
		SELECT $2, r.id, 'team', $1, $3 FROM roles r WHERE r.name = 'viewer'`, f.team, f.member, f.owner)

	// Keys are revoked: the fixture models post-freeze state (the freeze
	// rotates keys before copy; live keys block).
	mustExec(t, srcPool, `INSERT INTO api_key (team_id, key_hash, name, created_by, revoked_at) VALUES ($1, 'hash-'||$2::text, 'ci', $3, now())`, f.team, uuid.New(), f.owner)
	mustExec(t, srcPool, `INSERT INTO api_key (team_id, key_hash, name, revoked_at) VALUES ($1, 'hash-'||$2::text, 'agent', now())`, f.team, uuid.New())

	mustExec(t, srcPool, `
		INSERT INTO secret (id, team_id, name, auth_type, hosts, ciphertext, encrypted_dek, kek_id)
		VALUES ($1, $2, 'example-provider', 'bearer', ARRAY['api.example.com'], '\x0102aabb'::bytea, '\x0304ccdd'::bytea,
		        'projects/ss/locations/global/keyRings/secrets/cryptoKeys/kek')`, f.secret, f.team)

	tplDir := "/srv/templates/" + f.tpl.String()
	mustExec(t, srcPool, `
		INSERT INTO template (id, team_id, name, status, build_spec, vcpu, memory_mib, disk_mib,
		                      rootfs_path, snapshot_path, mem_path, base_path, delta_path, size_bytes, built_at)
		VALUES ($1, $2, 'drill-base', 'ready', '{"from":"drill"}', 1, 1024, 4096,
		        $3||'/rootfs.ext4', $3||'/vmstate.snap', $3||'/mem.snap', $3||'/base.ext4', $3||'/delta.ext4', 0, $4)`,
		f.tpl, f.team, tplDir, base)
	mustExec(t, srcPool, `
		INSERT INTO template_build (id, template_id, team_id, status, build_spec_hash, vmd_host_id, started_at, finalized_at)
		VALUES ($1, $2, $3, 'ready', 'drill-hash', $4, $5, $5)`, f.build, f.tpl, f.team, sourceHostID, base)

	// Two paused sandboxes with the circular snapshot link, one destroyed.
	for i, sb := range []uuid.UUID{f.sb1, f.sb2} {
		dir := "/srv/sandboxes/" + sb.String()
		mustExec(t, srcPool, `
			INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, template_id,
			                     snapshot_path, mem_path, base_path, delta_path)
			VALUES ($1, $2, $3, 'paused', 1, 1024, $4, $5,
			        $6||'/vmstate.snap', $6||'/mem.snap', $6||'/base.ext4', $6||'/delta.ext4')`,
			sb, f.team, fmt.Sprintf("drill-sb-%d", i+1), sourceHostID, f.tpl, dir)
	}
	for _, pair := range []struct{ snap, sb uuid.UUID }{{f.snap1, f.sb1}, {f.snap2, f.sb2}} {
		snapDir := "/srv/snapshots/" + pair.sb.String()
		mustExec(t, srcPool, `
			INSERT INTO snapshot (id, sandbox_id, team_id, path, mem_path, size_bytes, trigger)
			VALUES ($1, $2, $3, $4||'/disk.snap', $4||'/mem.snap', 0, 'pause')`,
			pair.snap, pair.sb, f.team, snapDir)
		mustExec(t, srcPool, `UPDATE sandbox SET snapshot_id = $2 WHERE id = $1`, pair.sb, pair.snap)
	}
	// Integrity manifest rows: one through each parent kind, so the copy
	// scope's snapshot and template branches are both exercised.
	mustExec(t, srcPool, `
		INSERT INTO artifact_manifest (snapshot_id, file_name, path, size_bytes, sha256)
		VALUES ($1, 'rootfs.ext4', '/srv/sandboxes/'||$2::text||'/rootfs.ext4', 4096,
		        repeat('ab', 32))`, f.snap1, f.sb1)
	mustExec(t, srcPool, `
		INSERT INTO artifact_manifest (template_id, file_name, path, size_bytes, sha256)
		VALUES ($1, 'base.ext4', '/srv/templates/'||$2::text||'/base.ext4', 8192,
		        repeat('cd', 32))`, f.tpl, f.tpl)
	// Backup coverage rows: one through each parent kind, so the copy
	// scope's sandbox and template branches are both exercised.
	mustExec(t, srcPool, `
		INSERT INTO backup_generation (sandbox_id, generation, bucket, completed_at, files)
		VALUES ($1, repeat('ef', 32), 'superserve-artifact-backup-test', now(),
		        jsonb_build_array(jsonb_build_object(
		            'name', 'rootfs.ext4', 'size_bytes', 4096, 'sha256', repeat('ab', 32))))`, f.sb1)
	mustExec(t, srcPool, `
		INSERT INTO backup_generation (template_id, build_id, generation, bucket, completed_at, files)
		VALUES ($1, 'build-1', repeat('01', 32), 'superserve-artifact-backup-test', now(),
		        jsonb_build_array(jsonb_build_object(
		            'name', 'base.ext4', 'size_bytes', 8192, 'sha256', repeat('cd', 32))))`, f.tpl)
	// Destroyed sandbox: copied for history, excluded from artifact dirs.
	mustExec(t, srcPool, `
		INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id,
		                     snapshot_path, mem_path, base_path, delta_path, destroyed_at)
		VALUES ($1, $2, 'drill-sb-gone', 'deleted', 1, 1024, $3,
		        '/srv/sandboxes/gone/vmstate.snap', '/srv/sandboxes/gone/mem.snap',
		        '/srv/sandboxes/gone/base.ext4', '/srv/sandboxes/gone/delta.ext4', $4)`,
		f.sb3, f.team, sourceHostID, base)

	mustExec(t, srcPool, `INSERT INTO sandbox_secret (sandbox_id, secret_id, env_key) VALUES ($1, $2, 'EXAMPLE_API_KEY')`, f.sb1, f.secret)

	for _, sb := range []uuid.UUID{f.sb1, f.sb2} {
		mustExec(t, srcPool, `
			INSERT INTO sandbox_active_interval (sandbox_id, team_id, actor_id, started_at, ended_at, end_reason)
			VALUES ($1, $2, $3, $4, $5, 'paused')`, sb, f.team, f.owner, base, base.Add(30*time.Minute))
		mustExec(t, srcPool, `
			INSERT INTO sandbox_compute_billing_interval (sandbox_id, team_id, vcpu_count, memory_mib, started_at, ended_at, end_reason)
			VALUES ($1, $2, 1, 1024, $3, $4, 'paused')`, sb, f.team, base, base.Add(30*time.Minute))
		mustExec(t, srcPool, `
			INSERT INTO sandbox_storage_interval (sandbox_id, team_id, disk_mib, started_at)
			VALUES ($1, $2, 4096, $3)`, sb, f.team, base)
	}

	// Billing rows with awkward numerics — the copy must not round them.
	mustExec(t, srcPool, `
		INSERT INTO team_billing_usage (team_id, period_start, period_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds)
		VALUES ($1, $2, $3, 123456789.123456, 987654321987.654321, 42.000001)`,
		f.team, base, base.Add(24*time.Hour))
	for i := 0; i < 2; i++ {
		hour := base.Add(time.Duration(i) * time.Hour)
		mustExec(t, srcPool, `
			INSERT INTO team_billing_usage_hourly (team_id, hour_start, hour_end, vcpu_seconds, memory_mib_seconds, storage_mib_seconds)
			VALUES ($1, $2, $3, 1800.5, 1843712.25, 7372800.125)`, f.team, hour, hour.Add(time.Hour))
	}
	mustExec(t, srcPool, `
		INSERT INTO team_billing_period (team_id, period_start, period_end, status, approved_by, approved_at)
		VALUES ($1, $2, $3, 'approved', $4, $5)`, f.team, base, base.Add(24*time.Hour), f.owner, base.Add(25*time.Hour))
	mustExec(t, srcPool, `
		INSERT INTO billing_period_anomaly (team_id, period_start, period_end, severity, kind, sandbox_id)
		VALUES ($1, $2, $3, 'warning', 'drill', $4)`, f.team, base, base.Add(24*time.Hour), f.sb1)
	mustExec(t, srcPool, `
		INSERT INTO billing_rollup_job (team_id, hour_start, hour_end, status, completed_at)
		VALUES ($1, $2, $3, 'completed', $4)`, f.team, base, base.Add(time.Hour), base.Add(2*time.Hour))
	mustExec(t, srcPool, `
		INSERT INTO billing_rollup_team_backfill_state (team_id, next_hour_start) VALUES ($1, $2)`, f.team, base.Add(2*time.Hour))

	mustExec(t, srcPool, `INSERT INTO team_feature_flag (team_id, key, enabled) VALUES ($1, 'tenant_usage_dashboard', true)`, f.team)
	// Explicit TRUE rollup flag: the copy must hold dest rollups FALSE for
	// the whole run anyway, then restore this value at the end.
	mustExec(t, srcPool, `INSERT INTO team_feature_flag (team_id, key, enabled) VALUES ($1, 'billing_hourly_rollups', true)`, f.team)
	mustExec(t, srcPool, `INSERT INTO team_pricing_plan (team_id, plan_key, assigned_by) VALUES ($1, 'payg', $2)`, f.team, f.owner)

	grantID := uuid.New()
	mustExec(t, srcPool, `
		INSERT INTO team_credit_grant (id, team_id, amount_usd, remaining_usd, reason, created_by)
		VALUES ($1, $2, 100.000000, 40.000000, 'pilot credits', $3)`, grantID, f.team, f.owner)
	mustExec(t, srcPool, `
		INSERT INTO team_credit_ledger (team_id, grant_id, amount_usd, reason, created_by)
		VALUES ($1, $2, -60.000000, 'usage draw-down', $3)`, f.team, grantID, f.owner)

	mustExec(t, srcPool, `INSERT INTO quota_alert_state (team_id, quota_type) VALUES ($1, 'sandbox')`, f.team)
	mustExec(t, srcPool, `
		INSERT INTO trial_credit_warning_state (team_id, lifecycle_key, status, sent_at)
		VALUES ($1, trial_credit_warning_lifecycle($1), 'sent', $2)`, f.team, base)
	mustExec(t, srcPool, `
		INSERT INTO trial_credit_warning_delivery (team_id, lifecycle_key, recipient, sent_at, rejected_at)
		VALUES ($1, trial_credit_warning_lifecycle($1), 'owner@example.com', $2, NULL),
		       ($1, trial_credit_warning_lifecycle($1), 'rejected@example.com', NULL, $2)`, f.team, base)

	mustExec(t, srcPool, `
		INSERT INTO activity (sandbox_id, team_id, actor_id, category, action, resource_type, sandbox_name)
		VALUES ($1, $2, $3, 'sandbox', 'create', 'sandbox', 'drill-sb-1')`, f.sb1, f.team, f.owner)
	mustExec(t, srcPool, `
		INSERT INTO activity (template_id, team_id, actor_id, category, action, resource_type)
		VALUES ($1, $2, $3, 'template', 'build', 'template')`, f.tpl, f.team, f.owner)
	mustExec(t, srcPool, `
		INSERT INTO activity (team_id, actor_id, category, action, resource_type, secret_id, secret_name)
		VALUES ($1, $2, 'secret', 'create', 'secret', $3, 'example-provider')`, f.team, f.owner, f.secret)

	mustExec(t, srcPool, `INSERT INTO sandbox_revocation (sandbox_id, expires_at) VALUES ($1, $2)`, f.sb1, base.Add(48*time.Hour))
	mustExec(t, srcPool, `INSERT INTO revoked_proxy_token (sandbox_id, proxy_token, expires_at) VALUES ($1, 'tok-1', $2)`, f.sb1, base.Add(48*time.Hour))

	// Rows that must NOT move: audit history, login flow.
	mustExec(t, srcPool, `
		INSERT INTO device_code (device_code, user_code, user_id, status, expires_at)
		VALUES ('dev-'||$1::text, 'usr-'||$1::text, $2, 'approved', $3)`, uuid.New(), f.owner, base.Add(time.Hour))
	mustExec(t, srcPool, `
		INSERT INTO proxy_audit (team_id, sandbox_id, secret_id, method, host, path, status)
		VALUES ($1, $2, $3, 'POST', 'api.example.com', '/v1/messages', 200)`, f.team, f.sb1, f.secret)
	mustExec(t, srcPool, `
		INSERT INTO net_flow (team_id, sandbox_id, protocol, host, dst_ip, dst_port, verdict)
		VALUES ($1, $2, 'tls', 'api.example.com', '192.0.2.10', 443, 'allowed')`, f.team, f.sb1)
	mustExec(t, srcPool, `
		INSERT INTO audit_logs (actor_user_id, team_id, event_type) VALUES ($1, $2, 'role_granted')`, f.owner, f.team)

	// A neighbor team that must survive detach and purge untouched. It
	// shares the owner, so detach's membership deletes must scope by team.
	mustExec(t, srcPool, `INSERT INTO team (id, name) VALUES ($1, 'bystander-team')`, f.teamB)
	mustExec(t, srcPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, f.teamB, f.owner)
	mustExec(t, srcPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, f.teamB, f.owner)
	mustExec(t, srcPool, `
		INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id, granted_by)
		SELECT $2, r.id, 'team', $1, $2 FROM roles r WHERE r.name = 'team_owner'`, f.teamB, f.owner)

	// System template: owned by another team in source; the dest cell has
	// its own seeded copy under a different id. sb4 boots from it, so the
	// copy must remap sandbox.template_id by name.
	mustExec(t, srcPool, `
		INSERT INTO template (id, team_id, name, status, build_spec, vcpu, memory_mib, disk_mib, snapshot_path, built_at)
		VALUES ($1, $2, 'superserve/base', 'ready', '{}', 1, 1024, 4096, '/srv/templates/sys/vmstate.snap', $3)`,
		f.sysTplSrc, f.teamB, base)
	sysTeamDst := uuid.New()
	mustExec(t, dstPool, `INSERT INTO team (id, name) VALUES ($1, 'bystander-team') ON CONFLICT DO NOTHING`, sysTeamDst)
	mustExec(t, dstPool, `
		INSERT INTO template (id, team_id, name, status, build_spec, vcpu, memory_mib, disk_mib, snapshot_path, built_at)
		VALUES ($1, $2, 'superserve/base', 'ready', '{}', 1, 1024, 4096, '/dstsrv/templates/sys/vmstate.snap', $3)`,
		f.sysTplDst, sysTeamDst, base)
	// Decoy: another dest team shadowing the system template's name with a
	// NEWER ready template. The remap must resolve through the owning
	// team's name and never pick this one.
	decoyTeam := uuid.New()
	mustExec(t, dstPool, `INSERT INTO team (id, name) VALUES ($1, 'decoy-team') ON CONFLICT DO NOTHING`, decoyTeam)
	mustExec(t, dstPool, `
		INSERT INTO template (id, team_id, name, status, build_spec, vcpu, memory_mib, disk_mib, snapshot_path, built_at)
		VALUES ($1, $2, 'superserve/base', 'ready', '{}', 1, 1024, 4096, '/dstsrv/templates/decoy/vmstate.snap', now())`,
		uuid.New(), decoyTeam)
	mustExec(t, srcPool, `
		INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, template_id,
		                     snapshot_path, mem_path, base_path, delta_path)
		VALUES ($1, $2, 'drill-sb-sys', 'paused', 1, 1024, $3, $4,
		        '/srv/sandboxes/sys/vmstate.snap', '/srv/sandboxes/sys/mem.snap', '/srv/sandboxes/sys/base.ext4', '/srv/sandboxes/sys/delta.ext4')`,
		f.sb4, f.team, sourceHostID, f.sysTplSrc)
	mustExec(t, srcPool, `
		INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id)
		VALUES ($1, $2, 'bystander-sb', 'paused', 1, 1024, $3)`, uuid.New(), f.teamB, sourceHostID)

	// A team with a still-running sandbox, to prove copy refuses.
	mustExec(t, srcPool, `INSERT INTO team (id, name) VALUES ($1, 'still-running-team')`, f.teamC)
	mustExec(t, srcPool, `
		INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id, ip_address)
		VALUES ($1, $2, 'still-running', 'active', 1, 1024, $3, '10.0.0.9')`, f.sbActive, f.teamC, sourceHostID)

	f.expectedCounts = map[string]int64{
		"profile":                            2,
		"team":                               1,
		"team_member":                        2,
		"team_memberships":                   2,
		"user_role_assignments":              2,
		"api_key":                            2,
		"secret":                             1,
		"template":                           1,
		"template_build":                     1,
		"sandbox":                            4,
		"snapshot":                           2,
		"artifact_manifest":                  2,
		"backup_generation":                  2,
		"sandbox_secret":                     1,
		"sandbox_active_interval":            2,
		"sandbox_compute_billing_interval":   2,
		"sandbox_storage_interval":           2,
		"team_billing_usage":                 1,
		"team_billing_usage_hourly":          2,
		"team_billing_period":                1,
		"billing_period_anomaly":             1,
		"billing_rollup_job":                 1,
		"billing_rollup_team_backfill_state": 1,
		"team_feature_flag":                  2,
		"team_billing_account":               0,
		"team_trial_eligibility_cache":       0,
		"team_pricing_plan":                  1,
		"team_credit_grant":                  1,
		"team_credit_ledger":                 1,
		"quota_alert_state":                  1,
		"trial_credit_warning_state":         1,
		"trial_credit_warning_delivery":      2,
		"activity":                           3,
		"sandbox_revocation":                 1,
		"revoked_proxy_token":                1,
	}

	f.expectedDirs = []string{
		tplDir,
		"/srv/sandboxes/" + f.sb1.String(),
		"/srv/sandboxes/" + f.sb2.String(),
		"/srv/sandboxes/sys",
		"/srv/snapshots/" + f.sb1.String(),
		"/srv/snapshots/" + f.sb2.String(),
	}
	sort.Strings(f.expectedDirs)
	return f
}

func (f *fixture) cfg(phase string) config {
	return config{
		teamID:     f.team,
		sourceURL:  srcURL,
		destURL:    dstURL,
		destHostID: destHostID,
		destRegion: destRegion,
		phase:      phase,
	}
}

func TestTeamMigration(t *testing.T) {
	ctx := context.Background()
	f := seedFixture(t)

	// Sanity: the fixture's expected-count map covers exactly the migrated set.
	if len(f.expectedCounts) != len(migratedTables) {
		t.Fatalf("fixture covers %d tables, migratedTables has %d", len(f.expectedCounts), len(migratedTables))
	}
	for _, spec := range migratedTables {
		want, ok := f.expectedCounts[spec.name]
		if !ok {
			t.Fatalf("fixture has no expected count for %s", spec.name)
		}
		if got := countScoped(t, srcPool, spec, f.team); got != want {
			t.Fatalf("fixture: source %s has %d rows, expected %d", spec.name, got, want)
		}
	}

	t.Run("plan writes paths-out", func(t *testing.T) {
		pathsFile := filepath.Join(t.TempDir(), "dirs.txt")
		cfg := f.cfg(phasePlan)
		cfg.pathsOut = pathsFile
		if err := run(ctx, cfg); err != nil {
			t.Fatalf("plan: %v", err)
		}
		raw, err := os.ReadFile(pathsFile)
		if err != nil {
			t.Fatalf("read paths-out: %v", err)
		}
		got := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if strings.Join(got, ",") != strings.Join(f.expectedDirs, ",") {
			t.Fatalf("paths-out mismatch:\n got  %v\n want %v", got, f.expectedDirs)
		}
	})

	t.Run("copy refuses active sandboxes", func(t *testing.T) {
		cfg := f.cfg(phaseCopy)
		cfg.teamID = f.teamC
		err := run(ctx, cfg)
		if err == nil {
			t.Fatal("copy of a team with an active sandbox must fail")
		}
		if !strings.Contains(err.Error(), f.sbActive.String()) {
			t.Fatalf("refusal error must list the offending sandbox, got: %v", err)
		}
		var n int64
		if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM team WHERE id = $1`, f.teamC).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatal("refused copy must write nothing to dest")
		}
	})

	t.Run("copy refuses a pausing sandbox", func(t *testing.T) {
		mustExec(t, srcPool, `UPDATE sandbox SET status = 'pausing' WHERE id = $1`, f.sb1)
		defer mustExec(t, srcPool, `UPDATE sandbox SET status = 'paused' WHERE id = $1`, f.sb1)

		err := run(ctx, f.cfg(phaseCopy))
		if err == nil || !strings.Contains(err.Error(), f.sb1.String()) {
			t.Fatalf("mid-pause sandbox must block the copy, got: %v", err)
		}
	})

	t.Run("copy refuses in-flight template builds", func(t *testing.T) {
		buildID := uuid.New()
		mustExec(t, srcPool, `
			INSERT INTO template_build (id, template_id, team_id, status, build_spec_hash, vmd_host_id)
			VALUES ($1, $2, $3, 'building', 'inflight-hash', $4)`, buildID, f.tpl, f.team, sourceHostID)
		defer mustExec(t, srcPool, `DELETE FROM template_build WHERE id = $1`, buildID)

		err := run(ctx, f.cfg(phaseCopy))
		if err == nil || !strings.Contains(err.Error(), buildID.String()) {
			t.Fatalf("in-flight build must block the copy, got: %v", err)
		}
	})

	t.Run("copy refuses unrevoked API keys", func(t *testing.T) {
		liveKey := uuid.New()
		mustExec(t, srcPool, `INSERT INTO api_key (id, team_id, key_hash, name) VALUES ($1, $2, 'hash-live', 'still-live')`, liveKey, f.team)
		defer mustExec(t, srcPool, `DELETE FROM api_key WHERE id = $1`, liveKey)

		err := run(ctx, f.cfg(phaseCopy))
		if err == nil || !strings.Contains(err.Error(), liveKey.String()) {
			t.Fatalf("live key must block the copy (freeze rotates keys), got: %v", err)
		}
	})

	t.Run("refuses when source and dest are the same database", func(t *testing.T) {
		cfg := f.cfg(phaseCopy)
		cfg.destURL = cfg.sourceURL
		err := run(ctx, cfg)
		if err == nil || !strings.Contains(err.Error(), "same database") {
			t.Fatalf("same-DB DSNs must refuse every dest-touching phase, got: %v", err)
		}
	})

	t.Run("copy refuses a failed sandbox", func(t *testing.T) {
		failedID := uuid.New()
		mustExec(t, srcPool, `
			INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id)
			VALUES ($1, $2, 'crashed', 'failed', 1, 1024, $3)`, failedID, f.team, sourceHostID)
		defer mustExec(t, srcPool, `DELETE FROM sandbox WHERE id = $1`, failedID)

		err := run(ctx, f.cfg(phaseCopy))
		if err == nil || !strings.Contains(err.Error(), failedID.String()) {
			t.Fatalf("failed sandbox must block the copy (destroy it first), got: %v", err)
		}
	})

	t.Run("copy round-trip", func(t *testing.T) {
		if err := run(ctx, f.cfg(phaseCopy)); err != nil {
			t.Fatalf("copy: %v", err)
		}

		for _, spec := range migratedTables {
			if got, want := countScoped(t, dstPool, spec, f.team), f.expectedCounts[spec.name]; got != want {
				t.Errorf("dest %s: got %d rows, want %d", spec.name, got, want)
			}
		}

		// The pre-existing dest profile is not clobbered; the source stays as-is.
		if got := scanString(t, dstPool, `SELECT email FROM profile WHERE id = $1`, f.member); got != "pre-existing@example.com" {
			t.Errorf("dest member profile clobbered: %s", got)
		}
		if got := scanString(t, srcPool, `SELECT email FROM profile WHERE id = $1`, f.member); got != "member@example.com" {
			t.Errorf("source member profile changed: %s", got)
		}

		// Role ids differ per cell and the assignment must follow the name.
		srcRole := scanString(t, srcPool, `SELECT id::text FROM roles WHERE name = 'team_owner'`)
		dstRole := scanString(t, dstPool, `SELECT id::text FROM roles WHERE name = 'team_owner'`)
		if srcRole == dstRole {
			t.Fatal("test premise broken: role ids should differ between cells")
		}
		got := scanString(t, dstPool, `
			SELECT r.name FROM user_role_assignments ura JOIN roles r ON r.id = ura.role_id
			WHERE ura.team_id = $1 AND ura.user_id = $2`, f.team, f.owner)
		if got != "team_owner" {
			t.Errorf("owner's dest role = %s, want team_owner", got)
		}
		var pending, claimed, entitled, granted bool
		if err := dstPool.QueryRow(ctx, `SELECT
			EXISTS(SELECT 1 FROM team_signup_trial_provenance WHERE team_id=$1 AND completed_at IS NULL),
			EXISTS(SELECT 1 FROM user_signup_trial_claim WHERE user_id IN ($2,$3)),
			EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id IN ($2,$3) AND signup_trial_claimed_at IS NOT NULL),
			EXISTS(SELECT 1 FROM team_credit_grant WHERE team_id=$1 AND reason='signup trial credit')`,
			f.team, f.owner, f.member).Scan(&pending, &claimed, &entitled, &granted); err != nil {
			t.Fatal(err)
		}
		var sourceClaimed, sourceEntitled bool
		if err := srcPool.QueryRow(ctx, `SELECT
			EXISTS(SELECT 1 FROM user_signup_trial_claim WHERE user_id IN ($1,$2)),
			EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id IN ($1,$2) AND signup_trial_claimed_at IS NOT NULL)`,
			f.owner, f.member).Scan(&sourceClaimed, &sourceEntitled); err != nil {
			t.Fatal(err)
		}
		if pending || granted || claimed != sourceClaimed || entitled != sourceEntitled {
			t.Fatalf("copied promotion state: pending=%v granted=%v claimed=%v/%v entitled=%v/%v", pending, granted, claimed, sourceClaimed, entitled, sourceEntitled)
		}

		// Host remap, home_region rehoming, quota counter.
		var n int64
		if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM sandbox WHERE team_id = $1 AND host_id <> $2`, f.team, destHostID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%d dest sandboxes not remapped to %s", n, destHostID)
		}
		if got := scanString(t, dstPool, `SELECT home_region || '|' || active_sandbox_count::text FROM team WHERE id = $1`, f.team); got != "usw|0" {
			t.Errorf("dest team home_region|count = %s, want usw|0", got)
		}

		// Circular FK relinked.
		if got := scanString(t, dstPool, `SELECT snapshot_id::text FROM sandbox WHERE id = $1`, f.sb1); got != f.snap1.String() {
			t.Errorf("dest sb1.snapshot_id = %s, want %s", got, f.snap1)
		}

		// System-template references remap to the dest cell's seeded copy.
		gotTpl := scanString(t, dstPool, `SELECT template_id::text FROM sandbox WHERE id = $1`, f.sb4)
		if gotTpl != f.sysTplDst.String() {
			t.Fatalf("sb4 template_id: got %s, want dest system template %s", gotTpl, f.sysTplDst)
		}
		// The team's own template keeps its id.
		if got := scanString(t, dstPool, `SELECT template_id::text FROM sandbox WHERE id = $1`, f.sb1); got != f.tpl.String() {
			t.Fatalf("sb1 template_id: got %s, want preserved %s", got, f.tpl)
		}

		// Secret ciphertext copies byte-for-byte; numerics keep every digit.
		srcSec := scanString(t, srcPool, `SELECT encode(ciphertext, 'hex') || '|' || encode(encrypted_dek, 'hex') || '|' || kek_id FROM secret WHERE id = $1`, f.secret)
		dstSec := scanString(t, dstPool, `SELECT encode(ciphertext, 'hex') || '|' || encode(encrypted_dek, 'hex') || '|' || kek_id FROM secret WHERE id = $1`, f.secret)
		if srcSec != dstSec {
			t.Errorf("secret bytes differ: %s vs %s", srcSec, dstSec)
		}
		srcUsage := scanString(t, srcPool, `SELECT vcpu_seconds::text || '|' || memory_mib_seconds::text FROM team_billing_usage WHERE team_id = $1`, f.team)
		dstUsage := scanString(t, dstPool, `SELECT vcpu_seconds::text || '|' || memory_mib_seconds::text FROM team_billing_usage WHERE team_id = $1`, f.team)
		if srcUsage != dstUsage {
			t.Errorf("billing numerics differ: %s vs %s", srcUsage, dstUsage)
		}

		// Audit/login tables stay behind.
		for _, table := range []string{"proxy_audit", "net_flow", "audit_logs"} {
			var n int64
			if err := dstPool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE team_id = $1`, table), f.team).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("dest %s has %d rows, want 0", table, n)
			}
		}
		if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM device_code WHERE user_id = $1`, f.owner).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("dest device_code has %d rows, want 0", n)
		}
	})

	t.Run("rollup hold persists through copy and releases at cutover", func(t *testing.T) {
		// The fixture's source flag is an explicit TRUE, but the dest must
		// stay HELD (false) through copy and validate — releasing early
		// lets the dest scheduler mint rollup state that wedges validate.
		var enabled bool
		if err := dstPool.QueryRow(ctx, `
			SELECT enabled FROM team_feature_flag
			WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, f.team).Scan(&enabled); err != nil {
			t.Fatalf("hold row missing after copy: %v", err)
		}
		if enabled {
			t.Fatal("dest rollup flag TRUE after copy — the hold leaked before cutover")
		}

		// Cutover: release restores the source's value.
		if err := run(ctx, f.cfg(phaseReleaseRollups)); err != nil {
			t.Fatalf("release-rollups: %v", err)
		}
		if err := dstPool.QueryRow(ctx, `
			SELECT enabled FROM team_feature_flag
			WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, f.team).Scan(&enabled); err != nil {
			t.Fatalf("flag row missing after release: %v", err)
		}
		if !enabled {
			t.Fatal("release did not restore the source's TRUE flag")
		}

		// With no source row at all, release removes the hold entirely.
		mustExec(t, srcPool, `DELETE FROM team_feature_flag WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, f.team)
		defer mustExec(t, srcPool, `INSERT INTO team_feature_flag (team_id, key, enabled) VALUES ($1, 'billing_hourly_rollups', true)`, f.team)
		if err := run(ctx, f.cfg(phaseReleaseRollups)); err != nil {
			t.Fatalf("release-rollups (absent source row): %v", err)
		}
		var n int
		if err := dstPool.QueryRow(ctx, `
			SELECT count(*) FROM team_feature_flag
			WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, f.team).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("hold not removed: %d override row(s) remain in dest", n)
		}
		// Leave dest matching the restored source state for later subtests.
		if err := run(ctx, f.cfg(phaseReleaseRollups)); err != nil {
			t.Fatalf("re-release: %v", err)
		}
	})

	t.Run("copy is idempotent", func(t *testing.T) {
		if err := run(ctx, f.cfg(phaseCopy)); err != nil {
			t.Fatalf("re-copy: %v", err)
		}
		for _, spec := range migratedTables {
			if got, want := countScoped(t, dstPool, spec, f.team), f.expectedCounts[spec.name]; got != want {
				t.Errorf("after re-copy, dest %s: got %d rows, want %d", spec.name, got, want)
			}
		}
		if got := scanString(t, dstPool, `SELECT snapshot_id::text FROM sandbox WHERE id = $1`, f.sb1); got != f.snap1.String() {
			t.Errorf("re-copy broke sb1.snapshot_id: %s", got)
		}
	})

	t.Run("validate passes", func(t *testing.T) {
		if err := run(ctx, f.cfg(phaseValidate)); err != nil {
			t.Fatalf("validate: %v", err)
		}
	})

	t.Run("retry converges after the source changed mid-window", func(t *testing.T) {
		// A background writer (or an aborted first attempt) mutates a source
		// row after it landed in dest. The re-run must overwrite the stale
		// dest row, not skip it.
		mustExec(t, srcPool, `UPDATE secret SET name = 'example-provider-rotated' WHERE id = $1`, f.secret)
		defer mustExec(t, srcPool, `UPDATE secret SET name = 'example-provider' WHERE id = $1`, f.secret)

		if err := run(ctx, f.cfg(phaseCopy)); err != nil {
			t.Fatalf("re-copy: %v", err)
		}
		got := scanString(t, dstPool, `SELECT name FROM secret WHERE id = $1`, f.secret)
		if got != "example-provider-rotated" {
			t.Fatalf("dest kept the stale row: name=%q, want the re-copied value", got)
		}
		if err := run(ctx, f.cfg(phaseValidate)); err != nil {
			t.Fatalf("validate after converging re-copy: %v", err)
		}
	})

	t.Run("copy preserves unknown warning state", func(t *testing.T) {
		var sentAt time.Time
		if err := srcPool.QueryRow(ctx, `SELECT sent_at FROM trial_credit_warning_state WHERE team_id = $1`, f.team).Scan(&sentAt); err != nil {
			t.Fatal(err)
		}
		mustExec(t, srcPool, `UPDATE trial_credit_warning_state SET status = 'unknown', sent_at = NULL WHERE team_id = $1`, f.team)
		defer mustExec(t, srcPool, `UPDATE trial_credit_warning_state SET status = 'sent', sent_at = $2 WHERE team_id = $1`, f.team, sentAt)
		defer mustExec(t, dstPool, `UPDATE trial_credit_warning_state SET status = 'sent', sent_at = $2 WHERE team_id = $1`, f.team, sentAt)

		if err := run(ctx, f.cfg(phaseValidate)); err == nil || !strings.Contains(err.Error(), "trial_credit_warning_state") {
			t.Fatalf("validate must detect changed warning state: %v", err)
		}
		if err := run(ctx, f.cfg(phaseCopy)); err != nil {
			t.Fatalf("copy unknown warning state: %v", err)
		}
		if got := scanString(t, dstPool, `SELECT status FROM trial_credit_warning_state WHERE team_id = $1`, f.team); got != "unknown" {
			t.Fatalf("dest warning status = %q, want unknown", got)
		}
		if err := run(ctx, f.cfg(phaseValidate)); err != nil {
			t.Fatalf("validate unknown warning state: %v", err)
		}
	})

	t.Run("validate catches content drift behind equal counts", func(t *testing.T) {
		// Same row count on both sides, different content — count parity
		// passes, the checksum pass must not.
		mustExec(t, srcPool, `UPDATE secret SET hosts = ARRAY['drift.example.org'] WHERE id = $1`, f.secret)
		defer func() {
			mustExec(t, srcPool, `UPDATE secret SET hosts = ARRAY['drift.example.org'] WHERE id = $1`, f.secret)
			if err := run(ctx, f.cfg(phaseCopy)); err != nil {
				t.Fatalf("restore copy: %v", err)
			}
		}()

		err := run(ctx, f.cfg(phaseValidate))
		if err == nil || !strings.Contains(err.Error(), "content drift") {
			t.Fatalf("checksums must flag drift the counts cannot see, got: %v", err)
		}
	})

	t.Run("validate catches a mismatch", func(t *testing.T) {
		mustExec(t, dstPool, `DELETE FROM activity WHERE team_id = $1 AND resource_type = 'secret'`, f.team)
		if err := run(ctx, f.cfg(phaseValidate)); err == nil {
			t.Fatal("validate must fail after a dest row is removed")
		}
		// Re-copy heals the hole; validate goes green again.
		if err := run(ctx, f.cfg(phaseCopy)); err != nil {
			t.Fatalf("healing copy: %v", err)
		}
		if err := run(ctx, f.cfg(phaseValidate)); err != nil {
			t.Fatalf("validate after heal: %v", err)
		}
	})

	t.Run("purge requires the exact team name", func(t *testing.T) {
		cfg := f.cfg(phasePurge)
		cfg.confirmTeamName = "migration-dril" // one letter off
		if err := run(ctx, cfg); err == nil {
			t.Fatal("purge with a wrong --confirm-team-name must fail")
		}
		if got := countScoped(t, srcPool, tableSpec{"team", "id = $1"}, f.team); got != 1 {
			t.Fatal("refused purge must not delete anything")
		}
	})

	t.Run("copy converges over a scheduler-created rollup job", func(t *testing.T) {
		// The dest cell's rollup scheduler can enqueue (team_id, hour_start)
		// the moment the copied team becomes visible — under a fresh id.
		// The natural-key upsert must overwrite it instead of wedging on
		// the unique constraint.
		var hourStart, hourEnd time.Time
		if err := srcPool.QueryRow(ctx, `SELECT hour_start, hour_end FROM billing_rollup_job WHERE team_id = $1`, f.team).Scan(&hourStart, &hourEnd); err != nil {
			t.Fatalf("read fixture rollup hour: %v", err)
		}
		mustExec(t, dstPool, `DELETE FROM billing_rollup_job WHERE team_id = $1`, f.team)
		mustExec(t, dstPool, `
			INSERT INTO billing_rollup_job (team_id, hour_start, hour_end, status)
			VALUES ($1, $2, $3, 'pending')`, f.team, hourStart, hourEnd)

		if err := run(ctx, f.cfg(phaseCopy)); err != nil {
			t.Fatalf("copy must converge over the scheduler's row: %v", err)
		}
		got := scanString(t, dstPool, `SELECT status FROM billing_rollup_job WHERE team_id = $1 AND hour_start = $2`, f.team, hourStart)
		if got != "completed" {
			t.Fatalf("scheduler row not overwritten: status=%q", got)
		}
		if err := run(ctx, f.cfg(phaseValidate)); err != nil {
			t.Fatalf("validate after convergence: %v", err)
		}
	})

	t.Run("validate tolerates source-side expiry of revocation rows", func(t *testing.T) {
		// The source reaper prunes expired revocation rows on its own
		// schedule; the dest keeps its copy. Parity must not gate on it.
		var n int
		if err := srcPool.QueryRow(ctx, `SELECT count(*) FROM sandbox_revocation WHERE sandbox_id = $1`, f.sb1).Scan(&n); err != nil || n == 0 {
			t.Fatalf("fixture should seed a revocation row (n=%d, err=%v)", n, err)
		}
		mustExec(t, srcPool, `DELETE FROM sandbox_revocation WHERE sandbox_id = $1`, f.sb1)

		if err := run(ctx, f.cfg(phaseValidate)); err != nil {
			t.Fatalf("validate must not gate on self-expiring rows: %v", err)
		}
	})

	t.Run("straggler sweep copies the transaction's own view", func(t *testing.T) {
		// The purge sweep runs copyTable off the locked transaction
		// so rows that landed after validate — invisible to any earlier
		// pass — still reach the dest before the deletes. Simulate by
		// sweeping from a transaction that holds an uncommitted straggler.
		tx, err := srcPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		strag := uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO activity (id, sandbox_id, team_id, actor_id, category, action, resource_type, sandbox_name)
			VALUES ($1, $2, $3, $4, 'sandbox', 'pause', 'sandbox', 'drill-sb-1')`, strag, f.sb1, f.team, f.owner); err != nil {
			t.Fatalf("straggler insert: %v", err)
		}
		defer mustExec(t, dstPool, `DELETE FROM activity WHERE id = $1`, strag)

		spec, ok := tableByName("activity")
		if !ok {
			t.Fatal("activity spec missing")
		}
		if _, _, err := copyTable(ctx, tx, dstPool, spec, f.team, nil); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		var n int
		if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM activity WHERE id = $1`, strag).Scan(&n); err != nil || n != 1 {
			t.Fatalf("straggler not swept to dest (n=%d, err=%v)", n, err)
		}
	})

	t.Run("purge refuses when a build starts during validate", func(t *testing.T) {
		buildID := uuid.New()
		mustExec(t, srcPool, `
			INSERT INTO template_build (id, template_id, team_id, status, build_spec_hash, vmd_host_id)
			VALUES ($1, $2, $3, 'pending', 'race-hash', $4)`, buildID, f.tpl, f.team, sourceHostID)
		defer func() {
			mustExec(t, srcPool, `UPDATE template_build SET status = 'cancelled' WHERE id = $1`, buildID)
			mustExec(t, srcPool, `DELETE FROM template_build_execution WHERE build_id = $1`, buildID)
			mustExec(t, srcPool, `DELETE FROM template_build WHERE id = $1`, buildID)
		}()

		cfg := f.cfg(phasePurge)
		cfg.confirmTeamName = "migration-drill"
		err := run(ctx, cfg)
		if err == nil || !strings.Contains(err.Error(), buildID.String()) {
			t.Fatalf("in-flight build must block purge, got: %v", err)
		}
	})

	t.Run("purge refuses when the source is no longer quiescent", func(t *testing.T) {
		mustExec(t, srcPool, `UPDATE sandbox SET status = 'active' WHERE id = $1`, f.sb1)
		defer mustExec(t, srcPool, `UPDATE sandbox SET status = 'paused' WHERE id = $1`, f.sb1)

		cfg := f.cfg(phasePurge)
		cfg.confirmTeamName = "migration-drill"
		err := run(ctx, cfg)
		if err == nil || !strings.Contains(err.Error(), f.sb1.String()) {
			t.Fatalf("post-copy resume must block purge, got: %v", err)
		}
	})

	t.Run("purge refuses while a destroyed sandbox still owes its host reclaim", func(t *testing.T) {
		mustExec(t, srcPool, `INSERT INTO sandbox_teardown (sandbox_id, host_id) VALUES ($1, $2)`, f.sb3, sourceHostID)
		defer mustExec(t, srcPool, `DELETE FROM sandbox_teardown WHERE sandbox_id = $1`, f.sb3)

		cfg := f.cfg(phasePurge)
		cfg.confirmTeamName = "migration-drill"
		err := run(ctx, cfg)
		if err == nil || !strings.Contains(err.Error(), f.sb3.String()) {
			t.Fatalf("pending teardown must block purge, got: %v", err)
		}
	})

	t.Run("detach refuses when the source is no longer quiescent", func(t *testing.T) {
		mustExec(t, srcPool, `UPDATE sandbox SET status = 'active' WHERE id = $1`, f.sb1)
		defer mustExec(t, srcPool, `UPDATE sandbox SET status = 'paused' WHERE id = $1`, f.sb1)

		cfg := f.cfg(phaseDetach)
		cfg.confirmTeamName = "migration-drill"
		err := run(ctx, cfg)
		if err == nil || !strings.Contains(err.Error(), f.sb1.String()) {
			t.Fatalf("post-copy resume must block detach, got: %v", err)
		}
	})

	t.Run("detach refuses when a build is in flight", func(t *testing.T) {
		buildID := uuid.New()
		mustExec(t, srcPool, `
			INSERT INTO template_build (id, template_id, team_id, status, build_spec_hash, vmd_host_id)
			VALUES ($1, $2, $3, 'building', 'race-hash', $4)`, buildID, f.tpl, f.team, sourceHostID)
		defer mustExec(t, srcPool, `DELETE FROM template_build WHERE id = $1`, buildID)

		cfg := f.cfg(phaseDetach)
		cfg.confirmTeamName = "migration-drill"
		err := run(ctx, cfg)
		if err == nil || !strings.Contains(err.Error(), buildID.String()) {
			t.Fatalf("in-flight build must block detach, got: %v", err)
		}
		if got := countScoped(t, srcPool, tableSpec{"team_memberships", "team_id = $1"}, f.team); got != 2 {
			t.Fatal("refused detach must not delete anything")
		}
	})

	t.Run("detach requires the exact team name", func(t *testing.T) {
		cfg := f.cfg(phaseDetach)
		cfg.confirmTeamName = "migration-dril" // one letter off
		if err := run(ctx, cfg); err == nil {
			t.Fatal("detach with a wrong --confirm-team-name must fail")
		}
		if got := countScoped(t, srcPool, tableSpec{"team_memberships", "team_id = $1"}, f.team); got != 2 {
			t.Fatal("refused detach must not delete anything")
		}
	})

	t.Run("detach removes only the membership rows", func(t *testing.T) {
		// Re-impose the copy's rollup hold on the dest (an earlier subtest
		// released it via the standalone phase): detach is the cutover
		// moment and must lift the hold itself, or the migrated team's
		// hourly rollups stay suppressed for the whole soak.
		mustExec(t, dstPool, `UPDATE team_feature_flag SET enabled = false WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, f.team)

		cfg := f.cfg(phaseDetach)
		cfg.confirmTeamName = "migration-drill"
		if err := run(ctx, cfg); err != nil {
			t.Fatalf("detach: %v", err)
		}

		var rollups bool
		if err := dstPool.QueryRow(ctx, `SELECT enabled FROM team_feature_flag
			WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, f.team).Scan(&rollups); err != nil {
			t.Fatal(err)
		}
		if !rollups {
			t.Fatal("detach must restore the source rollup flag in the dest at cutover")
		}

		// The RBAC chain is gone from the source; every other table keeps
		// its rows as the cold fallback. profile is asserted by id below —
		// its scope is derived from the deleted membership rows — and the
		// self-expiring exempt tables were pruned by an earlier subtest.
		for _, spec := range migratedTables {
			if spec.name == "profile" || validationExemptTables[spec.name] {
				continue
			}
			want := f.expectedCounts[spec.name]
			if membershipTables[spec.name] {
				want = 0
			}
			if got := countScoped(t, srcPool, spec, f.team); got != want {
				t.Errorf("after detach, source %s: got %d rows, want %d", spec.name, got, want)
			}
		}
		for _, id := range []uuid.UUID{f.owner, f.member} {
			var exists bool
			if err := srcPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM profile WHERE id = $1)`, id).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if !exists {
				t.Errorf("profile %s deleted from source; detach must not touch profiles", id)
			}
		}

		// The bystander team's memberships (same owner) survive.
		for _, table := range []string{"team_member", "team_memberships", "user_role_assignments"} {
			var n int64
			if err := srcPool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE team_id = $1`, table), f.teamB).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Errorf("bystander %s: got %d rows, want 1", table, n)
			}
		}

		// The dest is untouched, memberships included.
		for _, spec := range migratedTables {
			if got, want := countScoped(t, dstPool, spec, f.team), f.expectedCounts[spec.name]; got != want {
				t.Errorf("after detach, dest %s: got %d rows, want %d", spec.name, got, want)
			}
		}

		// A standalone validate during the soak must not read the detached
		// membership tables as data loss.
		if err := run(ctx, f.cfg(phaseValidate)); err != nil {
			t.Fatalf("validate on a detached source: %v", err)
		}

		// Detach is re-runnable as a pure no-op: a second pass during the
		// soak must not replay the cutover sweep or the rollup release over
		// the now-live dest. The sentinel cursor would be overwritten by a
		// replayed sweep (the source's frozen cursor differs).
		sentinel := time.Date(2032, 6, 1, 0, 0, 0, 0, time.UTC)
		mustExec(t, dstPool, `UPDATE billing_rollup_team_backfill_state SET next_hour_start = $2 WHERE team_id = $1`, f.team, sentinel)
		if err := run(ctx, cfg); err != nil {
			t.Fatalf("re-detach: %v", err)
		}
		var cursor time.Time
		if err := dstPool.QueryRow(ctx, `
			SELECT next_hour_start FROM billing_rollup_team_backfill_state WHERE team_id = $1`, f.team).Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		if !cursor.Equal(sentinel) {
			t.Fatalf("re-detach replayed the cutover sweep over the live dest (cursor=%v)", cursor)
		}
	})

	t.Run("purge refuses when the dest lost the team", func(t *testing.T) {
		// Blow away the dest membership chain: purge must refuse to delete
		// what is now the only reachable copy of those rows.
		rows, err := dstPool.Query(ctx, `SELECT user_id, status FROM team_memberships WHERE team_id = $1`, f.team)
		if err != nil {
			t.Fatal(err)
		}
		type membership struct {
			userID uuid.UUID
			status string
		}
		var saved []membership
		for rows.Next() {
			var m membership
			if err := rows.Scan(&m.userID, &m.status); err != nil {
				t.Fatal(err)
			}
			saved = append(saved, m)
		}
		rows.Close()
		mustExec(t, dstPool, `DELETE FROM team_memberships WHERE team_id = $1`, f.team)
		defer func() {
			for _, m := range saved {
				mustExec(t, dstPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, $3)`, f.team, m.userID, m.status)
			}
		}()

		cfg := f.cfg(phasePurge)
		cfg.confirmTeamName = "migration-drill"
		if err := run(ctx, cfg); err == nil || !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("purge with an empty dest membership chain must refuse, got: %v", err)
		}
		if got := countScoped(t, srcPool, tableSpec{"sandbox", "team_id = $1"}, f.team); got != f.expectedCounts["sandbox"] {
			t.Fatal("refused purge must not delete source rows")
		}
	})

	t.Run("purge after a live detached soak removes the source copy", func(t *testing.T) {
		// Simulate the soak: the dest is the live home and diverges — a
		// sandbox resumes, a dest-only activity row lands, the rollup
		// backfill cursor advances, and support flips the rollup flag off.
		// None of that may block purge, and none of it may be overwritten
		// by purge's dest writes (sweep, rollup restore) afterwards.
		mustExec(t, dstPool, `UPDATE sandbox SET status = 'active' WHERE id = $1`, f.sb1)
		mustExec(t, dstPool, `INSERT INTO activity (sandbox_id, team_id, actor_id, category, action, resource_type, sandbox_name)
			VALUES ($1, $2, $3, 'sandbox', 'create', 'sandbox', 'drill-soak-sb')`, f.sb1, f.team, f.owner)
		soakCursor := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
		mustExec(t, dstPool, `UPDATE billing_rollup_team_backfill_state SET next_hour_start = $2 WHERE team_id = $1`, f.team, soakCursor)
		mustExec(t, dstPool, `UPDATE team_feature_flag SET enabled = false WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, f.team)

		cfg := f.cfg(phasePurge)
		cfg.confirmTeamName = "migration-drill"
		if err := run(ctx, cfg); err != nil {
			t.Fatalf("purge: %v", err)
		}

		// The dest's live state survives: purge must not re-restore the
		// frozen source's flag or sweep the frozen cursor over the live one.
		var enabled bool
		if err := dstPool.QueryRow(ctx, `
			SELECT enabled FROM team_feature_flag
			WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, f.team).Scan(&enabled); err != nil || enabled {
			t.Fatalf("detached purge clobbered the dest's live rollup flag (enabled=%v, err=%v)", enabled, err)
		}
		var cursor time.Time
		if err := dstPool.QueryRow(ctx, `
			SELECT next_hour_start FROM billing_rollup_team_backfill_state WHERE team_id = $1`, f.team).Scan(&cursor); err != nil {
			t.Fatal(err)
		}
		if !cursor.Equal(soakCursor) {
			t.Fatalf("detached purge rewound the dest's live backfill cursor to %v", cursor)
		}

		for _, spec := range migratedTables {
			if spec.name == "profile" {
				continue
			}
			if got := countScoped(t, srcPool, spec, f.team); got != 0 {
				t.Errorf("source %s still has %d team rows", spec.name, got)
			}
		}

		// Profiles are global and stay; so does append-only audit history.
		for _, id := range []uuid.UUID{f.owner, f.member} {
			var exists bool
			if err := srcPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM profile WHERE id = $1)`, id).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if !exists {
				t.Errorf("profile %s deleted from source; profiles must stay", id)
			}
		}
		for _, table := range []string{"proxy_audit", "net_flow", "audit_logs"} {
			var n int64
			if err := srcPool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE team_id = $1`, table), f.team).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				t.Errorf("source %s emptied; audit history must stay", table)
			}
		}

		// The bystander team is untouched; the dest keeps the full copy.
		var n int64
		if err := srcPool.QueryRow(ctx, `SELECT count(*) FROM sandbox WHERE team_id = $1`, f.teamB).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("bystander team lost its sandbox (count=%d)", n)
		}
		for _, spec := range migratedTables {
			want := f.expectedCounts[spec.name]
			if spec.name == "activity" {
				want++ // the dest-only soak-divergence row above
			}
			if got := countScoped(t, dstPool, spec, f.team); got != want {
				t.Errorf("after purge, dest %s: got %d rows, want %d", spec.name, got, want)
			}
		}
	})
}

func TestSignupTrialMigrationDetach(t *testing.T) {
	ctx := context.Background()
	team, owner := uuid.New(), uuid.New()
	mustExec(t, dstPool, `INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
		VALUES ($1, '192.0.2.1:50051', '192.0.2.1:8080', $2, 65536, 32)
		ON CONFLICT (id) DO NOTHING`, destHostID, destRegion)
	mustExec(t, srcPool, `INSERT INTO profile (id, email) VALUES ($1, $2)`, owner, owner.String()+"@example.com")
	mustExec(t, srcPool, `INSERT INTO team (id, name) VALUES ($1, 'signup-detach')`, team)
	mustExec(t, srcPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, team, owner)
	mustExec(t, srcPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, team, owner)
	mustExec(t, srcPool, `INSERT INTO user_role_assignments (team_id, user_id, scope_type, role_id)
		SELECT $1, $2, 'team', id FROM roles WHERE name = 'team_owner'`, team, owner)
	if _, err := srcPool.Exec(ctx, `DELETE FROM user_role_assignments WHERE team_id = $1`, team); err == nil {
		t.Fatal("completed legacy signup must reject ordinary last-owner cleanup")
	}
	var grantID uuid.UUID
	if err := srcPool.QueryRow(ctx, `SELECT id FROM team_credit_grant
		WHERE team_id = $1 AND reason = 'signup trial credit'`, team).Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	cfg := config{phase: phaseCopy, teamID: team, sourceURL: srcURL, destURL: dstURL, destHostID: destHostID, destRegion: destRegion}
	if err := run(ctx, cfg); err != nil {
		t.Fatalf("copy: %v", err)
	}
	cfg.phase, cfg.confirmTeamName = phaseDetach, "signup-detach"
	if err := run(ctx, cfg); err != nil {
		t.Fatalf("detach completed legacy signup: %v", err)
	}
	for _, pool := range []*pgxpool.Pool{srcPool, dstPool} {
		var preserved bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM team_credit_grant
			WHERE id = $1 AND team_id = $2 AND amount_usd = 5 AND remaining_usd = 5)`, grantID, team).Scan(&preserved); err != nil || !preserved {
			t.Fatalf("original signup ledger preserved=%t, error=%v", preserved, err)
		}
	}
	var claimed, guarded, sourceOwner, destinationOwner bool
	if err := srcPool.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM user_signup_trial_claim WHERE user_id = $1 AND team_id = $2),
		EXISTS (SELECT 1 FROM team_signup_trial_provenance WHERE team_id = $2),
		EXISTS (SELECT 1 FROM user_role_assignments WHERE team_id = $2)`, owner, team).Scan(&claimed, &guarded, &sourceOwner); err != nil {
		t.Fatal(err)
	}
	if err := dstPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_role_assignments
		WHERE team_id = $1 AND user_id = $2 AND revoked_at IS NULL)`, team, owner).Scan(&destinationOwner); err != nil {
		t.Fatal(err)
	}
	if !claimed || guarded || sourceOwner || !destinationOwner {
		t.Fatalf("detach state: claimed=%t guarded=%t source owner=%t destination owner=%t", claimed, guarded, sourceOwner, destinationOwner)
	}
	assertMigratedSignupConsumed(t, dstPool, owner, &team)
	assertSignupRetryHasNoGrant(t, dstPool, owner)
}

func assertMigratedSignupConsumed(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, teamID *uuid.UUID) {
	t.Helper()
	var consumed bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM user_signup_trial_claim c JOIN user_promotion_entitlement e USING (user_id)
		WHERE c.user_id = $1 AND c.team_id IS NOT DISTINCT FROM $2::uuid
		  AND e.signup_trial_team_id IS NOT DISTINCT FROM $2::uuid
		  AND e.signup_trial_claimed_at = c.claimed_at)`, userID, teamID).Scan(&consumed); err != nil || !consumed {
		t.Fatalf("signup consumption missing for user %s: consumed=%t, error=%v", userID, consumed, err)
	}
}

func assertSignupRetryHasNoGrant(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID) {
	t.Helper()
	var teamID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM create_team_with_signup_trial($1, $2, 'usw')`, "signup-retry-"+uuid.NewString(), userID).Scan(&teamID); err != nil {
		t.Fatal(err)
	}
	var grants int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM team_credit_grant
		WHERE team_id = $1 AND reason = 'signup trial credit'`, teamID).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("migrated actor received another signup grant: count=%d, error=%v", grants, err)
	}
}

func TestCanonicalPromotionMigration(t *testing.T) {
	ctx := context.Background()
	mustExec(t, dstPool, `INSERT INTO host(id,vmd_addr,proxy_addr,region,capacity_memory_mib,capacity_vcpus)
		VALUES($1,'192.0.2.1:50051','192.0.2.1:8080',$2,65536,32) ON CONFLICT DO NOTHING`, destHostID, destRegion)
	newActor := func(pool *pgxpool.Pool, email string) uuid.UUID {
		user := uuid.New()
		mustExec(t, pool, `INSERT INTO profile(id,email) VALUES($1,$2)`, user, email)
		mustExec(t, pool, `UPDATE promotion_auth.identity_source SET email=$2,email_confirmed_at=now() WHERE id=$1`, user, email)
		return user
	}
	newTeam := func(user uuid.UUID) config {
		var team uuid.UUID
		if err := srcPool.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1,$2,'use')`, "canonical-move-"+uuid.NewString(), user).Scan(&team); err != nil {
			t.Fatal(err)
		}
		return config{phase: phaseCopy, teamID: team, sourceURL: srcURL, destURL: dstURL, destHostID: destHostID, destRegion: destRegion}
	}
	t.Run("canonical consumption precedes ownership and survives retries", func(t *testing.T) {
		mailbox := "moved" + strings.ReplaceAll(uuid.NewString(), "-", "")
		user := newActor(srcPool, mailbox+"@gmail.com")
		cfg := newTeam(user)
		mustExec(t, srcPool, `INSERT INTO team_billing_account(team_id,stripe_subscription_status) VALUES($1,'active')`, cfg.teamID)
		mustExec(t, srcPool, `SELECT reserve_stripe_promotion($1,$2)`, cfg.teamID, user)
		mustExec(t, srcPool, `SELECT finalize_stripe_promotion($1,$2,'credit_migrated')`, cfg.teamID, user)
		for range 2 {
			if err := run(ctx, cfg); err != nil {
				t.Fatal(err)
			}
		}
		alias := newActor(dstPool, mailbox[:5]+"."+mailbox[5:]+"+alias@googlemail.com")
		assertSignupRetryHasNoGrant(t, dstPool, alias)
		var key string
		if err := dstPool.QueryRow(ctx, `SELECT resolve_promotion_identity($1)`, alias).Scan(&key); err != nil {
			t.Fatal(err)
		}
		var consumed bool
		if err := dstPool.QueryRow(ctx, `SELECT signup_claimed_at IS NOT NULL AND stripe_redemption_at IS NOT NULL
			FROM promotion_identity WHERE identity_key=$1`, key).Scan(&consumed); err != nil || !consumed {
			t.Fatalf("migration lost canonical consumption: %t %v", consumed, err)
		}
	})
	t.Run("unresolved history stays quarantined", func(t *testing.T) {
		user := newActor(srcPool, uuid.NewString()+"@example.com")
		cfg := newTeam(user)
		history := "test-migration:" + cfg.teamID.String()
		mustExec(t, srcPool, `INSERT INTO promotion_identity_history(history_key,promotion,team_id,claimed_at) VALUES($1,'stripe',$2,now())`, history, cfg.teamID)
		t.Cleanup(func() {
			mustExec(t, srcPool, `DELETE FROM promotion_identity_history WHERE history_key=$1`, history)
			mustExec(t, dstPool, `DELETE FROM promotion_identity_history WHERE history_key=$1`, history)
		})
		if err := run(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		var pending bool
		if err := dstPool.QueryRow(ctx, `SELECT status='pending' AND cardinality(identity_keys)=0 FROM promotion_identity_history WHERE history_key=$1`, history).Scan(&pending); err != nil || !pending {
			t.Fatalf("migration invented historical identity: %t %v", pending, err)
		}
	})
	t.Run("checkout capture travels without becoming current evidence", func(t *testing.T) {
		user := newActor(srcPool, "captured"+strings.ReplaceAll(uuid.NewString(), "-", "")+"@gmail.com")
		cfg := newTeam(user)
		var version uuid.UUID
		if err := srcPool.QueryRow(ctx, `SELECT evidence_version FROM promotion_identity_current WHERE user_id=$1`, user).Scan(&version); err != nil {
			t.Fatal(err)
		}
		mustExec(t, srcPool, `INSERT INTO team_billing_account(team_id,stripe_checkout_actor_id,stripe_checkout_identity_evidence_version,checkout_initializing_at)
			VALUES($1,$2,$3,now())`, cfg.teamID, user, version)
		for range 2 {
			if err := run(ctx, cfg); err != nil {
				t.Fatal(err)
			}
		}
		var preserved, current bool
		if err := dstPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_billing_account a
			JOIN promotion_identity_evidence e ON e.evidence_version=a.stripe_checkout_identity_evidence_version
			WHERE a.team_id=$1 AND e.evidence_version=$2 AND e.user_id=$3),
			EXISTS(SELECT 1 FROM promotion_identity_current WHERE user_id=$3 AND evidence_version=$2)`, cfg.teamID, version, user).Scan(&preserved, &current); err != nil || !preserved || current {
			t.Fatalf("captured evidence transfer: preserved=%t promoted to current=%t err=%v", preserved, current, err)
		}
	})
	t.Run("ambiguous external reservation blocks move", func(t *testing.T) {
		user := newActor(srcPool, uuid.NewString()+"@example.com")
		cfg := newTeam(user)
		mustExec(t, srcPool, `INSERT INTO team_billing_account(team_id,stripe_subscription_status) VALUES($1,'active')`, cfg.teamID)
		mustExec(t, srcPool, `SELECT reserve_stripe_promotion($1,$2)`, cfg.teamID, user)
		if err := run(ctx, cfg); err == nil || !strings.Contains(err.Error(), "settle pending Stripe promotions") {
			t.Fatalf("ambiguous fence migrated: %v", err)
		}
		var owners int
		if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM user_role_assignments WHERE team_id=$1`, cfg.teamID).Scan(&owners); err != nil || owners != 0 {
			t.Fatalf("ownership copied before fence settlement: %d %v", owners, err)
		}
	})
	t.Run("reconciled destination cannot erase unknown source history", func(t *testing.T) {
		user := newActor(srcPool, uuid.NewString()+"@example.com")
		cfg := newTeam(user)
		history := "signup-user:" + user.String()
		mustExec(t, srcPool, `INSERT INTO promotion_identity_history(history_key,promotion,user_id,team_id,claimed_at)
			VALUES($1,'signup',$2,$3,now())`, history, user, cfg.teamID)
		t.Cleanup(func() {
			mustExec(t, srcPool, `DELETE FROM promotion_identity_history WHERE history_key=$1`, history)
			mustExec(t, dstPool, `DELETE FROM promotion_identity_history WHERE history_key=$1`, history)
		})
		mustExec(t, dstPool, `INSERT INTO promotion_identity_history(history_key,promotion,user_id,claimed_at,status,identity_keys,evidence_reference,reconciled_at)
			VALUES($1,'signup',$2::uuid,now()-interval '1 day','reconciled',ARRAY['user:'||($2::uuid)::text],'destination evidence',now())`, history, user)
		if err := run(ctx, cfg); err == nil || !strings.Contains(err.Error(), "conflicting historical promotion evidence") {
			t.Fatalf("unresolved source history discarded: %v", err)
		}
		var owners int
		if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM user_role_assignments WHERE team_id=$1`, cfg.teamID).Scan(&owners); err != nil || owners != 0 {
			t.Fatalf("ownership copied despite unresolved conflict: %d %v", owners, err)
		}
	})
	t.Run("restricted credential is rejected before destination writes", func(t *testing.T) {
		user := newActor(srcPool, uuid.NewString()+"@example.com")
		cfg := newTeam(user)
		role := "promotion_migration_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		mustExec(t, dstPool, "CREATE ROLE "+role+" LOGIN BYPASSRLS PASSWORD 'disposable-test-password'")
		t.Cleanup(func() {
			mustExec(t, dstPool, "DROP OWNED BY "+role)
			mustExec(t, dstPool, "DROP ROLE "+role)
		})
		mustExec(t, dstPool, "GRANT USAGE ON SCHEMA public TO "+role)
		mustExec(t, dstPool, "GRANT SELECT ON promotion_identity_history TO "+role)
		limited, err := url.Parse(dstURL)
		if err != nil {
			t.Fatal(err)
		}
		limited.User = url.UserPassword(role, "disposable-test-password")
		cfg.destURL = limited.String()
		if err := run(ctx, cfg); err == nil || !strings.Contains(err.Error(), "destination administrator credential") {
			t.Fatalf("restricted migration was not rejected early: %v", err)
		}
		var present bool
		if err := dstPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team WHERE id=$1) OR EXISTS(SELECT 1 FROM profile WHERE id=$2)`, cfg.teamID, user).Scan(&present); err != nil || present {
			t.Fatalf("restricted migration mutated destination: %t %v", present, err)
		}
	})
}

func TestStripeEntitlementMigration(t *testing.T) {
	ctx := context.Background()
	for _, role := range []string{"anon", "authenticated", "service_role"} {
		var exists bool
		if err := srcPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			options := ""
			if role == "service_role" {
				options = " BYPASSRLS"
			}
			mustExec(t, srcPool, "CREATE ROLE "+role+options)
			t.Cleanup(func() { mustExec(t, srcPool, "DROP ROLE "+role) })
		}
	}
	newUnactivatedCell := func() (*pgxpool.Pool, string) {
		name := "stripe_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		mustExec(t, srcPool, "CREATE DATABASE "+name)
		cellURL, err := rewriteDBName(srcURL, name)
		if err != nil {
			t.Fatal(err)
		}
		pool, err := pgxpool.New(ctx, cellURL)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			pool.Close()
			mustExec(t, srcPool, "DROP DATABASE "+name+" WITH (FORCE)")
		})
		if err := applyMigrations(ctx, pool); err != nil {
			t.Fatal(err)
		}
		return pool, cellURL
	}
	srcPool, srcURL := newUnactivatedCell()
	dstPool, dstURL := newUnactivatedCell()
	mustExec(t, dstPool, `INSERT INTO host(id,vmd_addr,proxy_addr,region,capacity_memory_mib,capacity_vcpus)
		VALUES($1,'192.0.2.1:50051','192.0.2.1:8080',$2,65536,32) ON CONFLICT DO NOTHING`, destHostID, destRegion)
	newTeam := func(pool *pgxpool.Pool) uuid.UUID {
		team := uuid.New()
		mustExec(t, pool, `INSERT INTO team(id,name) VALUES($1,$2)`, team, "stripe-move-"+team.String())
		return team
	}
	newFixture := func() (config, uuid.UUID) {
		actor := uuid.New()
		team := newTeam(srcPool)
		mustExec(t, srcPool, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
		mustExec(t, srcPool, `INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'member')`, team, actor)
		mustExec(t, srcPool, `INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, team, actor)
		return config{phase: phaseCopy, teamID: team, sourceURL: srcURL, destURL: dstURL, destHostID: destHostID, destRegion: destRegion}, actor
	}
	waitForLockWaiter := func(t *testing.T, blocker uint32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var waiting bool
			if err := srcPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				WHERE $1::integer=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("expected operation to wait on the source promotion lock")
	}
	t.Run("uncommitted reservation is observed before ownership copy", func(t *testing.T) {
		cfg, actor := newFixture()
		mustExec(t, srcPool, `INSERT INTO team_billing_account(team_id) VALUES($1)`, cfg.teamID)
		tx, err := srcPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var state string
		if err := tx.QueryRow(ctx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,'evt_uncommitted')`, cfg.teamID, actor).Scan(&state); err != nil || state != "acquired" {
			t.Fatalf("reserve: state=%s err=%v", state, err)
		}
		copyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- run(copyCtx, cfg) }()
		waitForLockWaiter(t, tx.Conn().PgConn().PID())
		var copied bool
		if err := dstPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_memberships WHERE team_id=$1)`, cfg.teamID).Scan(&copied); err != nil || copied {
			t.Fatalf("ownership published while reservation was uncommitted: copied=%t err=%v", copied, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil || !strings.Contains(err.Error(), "settle pending Stripe promotions") {
			t.Fatalf("committed reservation should block copy: %v", err)
		}
		if err := dstPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_memberships WHERE team_id=$1)`, cfg.teamID).Scan(&copied); err != nil || copied {
			t.Fatalf("ownership published despite pending reservation: copied=%t err=%v", copied, err)
		}
	})
	t.Run("queued reservation rechecks durable cutover fence", func(t *testing.T) {
		cfg, actor := newFixture()
		mustExec(t, srcPool, `INSERT INTO team_billing_account(team_id,stripe_customer_id) VALUES($1,'cus_migrated')`, cfg.teamID)
		tx, err := srcPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('stripe-promo-team:' || $1::uuid::text)::bigint)`, cfg.teamID); err != nil {
			t.Fatal(err)
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		type result struct {
			state string
			err   error
		}
		done := make(chan result, 1)
		go func() {
			var r result
			r.err = srcPool.QueryRow(requestCtx, `SELECT reserve_stripe_promotion_for_event_state($1,$2,'evt_queued')`, cfg.teamID, actor).Scan(&r.state)
			done <- r
		}()
		waitForLockWaiter(t, tx.Conn().PgConn().PID())
		if _, err := tx.Exec(ctx, `INSERT INTO stripe_promotion_migration_fence(team_id) VALUES($1)`, cfg.teamID); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if r := <-done; r.err != nil || r.state != "ineligible" {
			t.Fatalf("queued reservation ignored cutover: state=%s err=%v", r.state, r.err)
		}
		var unchanged bool
		if err := srcPool.QueryRow(ctx, `SELECT stripe_customer_id='cus_migrated'
			AND stripe_activation_credit_reserved_at IS NULL AND stripe_activation_credit_grant_id IS NULL
			AND NOT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$2 AND
			(stripe_redemption_at IS NOT NULL OR stripe_redemption_reserved_team_id IS NOT NULL))
			FROM team_billing_account WHERE team_id=$1`, cfg.teamID, actor).Scan(&unchanged); err != nil || !unchanged {
			t.Fatalf("fenced promotion mutated billing/entitlement: unchanged=%t err=%v", unchanged, err)
		}
		if err := run(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		var copiedFence bool
		if err := dstPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM stripe_promotion_migration_fence WHERE team_id=$1)`, cfg.teamID).Scan(&copiedFence); err != nil || copiedFence {
			t.Fatalf("source-only fence copied to destination: %t %v", copiedFence, err)
		}
		var readable, writable bool
		if err := srcPool.QueryRow(ctx, `SELECT has_table_privilege('service_role','stripe_promotion_migration_fence','SELECT'),
			has_table_privilege('service_role','stripe_promotion_migration_fence','INSERT,UPDATE,DELETE')
			OR has_table_privilege('authenticated','stripe_promotion_migration_fence','INSERT,UPDATE,DELETE')
			OR has_table_privilege('anon','stripe_promotion_migration_fence','INSERT,UPDATE,DELETE')`).Scan(&readable, &writable); err != nil || !readable || writable {
			t.Fatalf("fence privilege boundary: readable=%t writable=%t err=%v", readable, writable, err)
		}
		mustExec(t, srcPool, `DELETE FROM team_member WHERE team_id=$1`, cfg.teamID)
		mustExec(t, srcPool, `DELETE FROM team_memberships WHERE team_id=$1`, cfg.teamID)
		mustExec(t, srcPool, `DELETE FROM team WHERE id=$1`, cfg.teamID)
		var retained bool
		if err := srcPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM stripe_promotion_migration_fence WHERE team_id=$1)`, cfg.teamID).Scan(&retained); err != nil || !retained {
			t.Fatalf("source team deletion removed the cutover fence: retained=%t err=%v", retained, err)
		}
	})
	for _, association := range []string{"same-team", "other-team", "deleted-team", "departed-recipient"} {
		t.Run(association, func(t *testing.T) {
			cfg, actor := newFixture()
			grantTeam := cfg.teamID
			if association == "other-team" || association == "deleted-team" {
				grantTeam = newTeam(srcPool)
			}
			claimedAt := time.Now().UTC().Truncate(time.Microsecond).Add(-24 * time.Hour)
			mustExec(t, srcPool, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at,stripe_redemption_team_id)
				VALUES($1,$2,$3)`, actor, claimedAt, grantTeam)
			if association == "deleted-team" {
				mustExec(t, srcPool, `DELETE FROM team WHERE id=$1`, grantTeam)
			}
			if association == "departed-recipient" {
				mustExec(t, srcPool, `DELETE FROM team_member WHERE team_id=$1`, cfg.teamID)
				mustExec(t, srcPool, `DELETE FROM team_memberships WHERE team_id=$1`, cfg.teamID)
			}
			for range 2 {
				if err := run(ctx, cfg); err != nil {
					t.Fatal(err)
				}
			}
			var team any
			if grantTeam == cfg.teamID {
				team = grantTeam
			}
			var preserved, independent bool
			if err := dstPool.QueryRow(ctx, `SELECT stripe_redemption_at=$2 AND stripe_redemption_team_id IS NOT DISTINCT FROM $3::uuid,
				signup_trial_claimed_at IS NULL AND NOT EXISTS(SELECT 1 FROM promotion_identity_binding WHERE user_id=$1)
				FROM user_promotion_entitlement WHERE user_id=$1`, actor, claimedAt, team).Scan(&preserved, &independent); err != nil || !preserved || !independent {
				t.Fatalf("UUID consumption transfer: preserved=%t independent=%t err=%v", preserved, independent, err)
			}
			retryTeam := newTeam(dstPool)
			mustExec(t, dstPool, `INSERT INTO team_billing_account(team_id) VALUES($1)`, retryTeam)
			var eligible bool
			if err := dstPool.QueryRow(ctx, `SELECT stripe_promotion_eligible($1,$2)`, retryTeam, actor).Scan(&eligible); err != nil || eligible {
				t.Fatalf("migrated actor became eligible again: %t %v", eligible, err)
			}
		})
	}
	t.Run("existing destination redemption is never replaced", func(t *testing.T) {
		cfg, actor := newFixture()
		mustExec(t, srcPool, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at,stripe_redemption_team_id)
			VALUES($1,now()-interval '1 day',$2)`, actor, cfg.teamID)
		mustExec(t, dstPool, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
		prior := newTeam(dstPool)
		mustExec(t, dstPool, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at,stripe_redemption_team_id)
			VALUES($1,now()-interval '2 days',$2)`, actor, prior)
		before := scanString(t, dstPool, `SELECT to_jsonb(e)::text FROM user_promotion_entitlement e WHERE user_id=$1`, actor)
		if err := run(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		after := scanString(t, dstPool, `SELECT to_jsonb(e)::text FROM user_promotion_entitlement e WHERE user_id=$1`, actor)
		if after != before {
			t.Fatalf("destination entitlement changed: %s -> %s", before, after)
		}
	})
	for _, side := range []string{"source", "destination"} {
		t.Run(side+" pending reservation fails closed", func(t *testing.T) {
			cfg, actor := newFixture()
			pool := srcPool
			if side == "destination" {
				pool = dstPool
				mustExec(t, pool, `INSERT INTO profile(id,email) VALUES($1,$2)`, actor, actor.String()+"@example.com")
			}
			reservedTeam := newTeam(pool)
			mustExec(t, pool, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_reserved_team_id,stripe_redemption_reserved_at,stripe_redemption_attempted_at)
				VALUES($1,$2,now(),now())`, actor, reservedTeam)
			before := scanString(t, pool, `SELECT to_jsonb(e)::text FROM user_promotion_entitlement e WHERE user_id=$1`, actor)
			if err := run(ctx, cfg); err == nil || !strings.Contains(err.Error(), "settle pending") {
				t.Fatalf("pending Stripe fence should block migration: %v", err)
			}
			var fenced bool
			if err := srcPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM stripe_promotion_migration_fence WHERE team_id=$1)`, cfg.teamID).Scan(&fenced); err != nil || fenced != (side == "destination") {
				t.Fatalf("source fence must precede destination writes and survive failed copy: fenced=%t err=%v", fenced, err)
			}
			after := scanString(t, pool, `SELECT to_jsonb(e)::text FROM user_promotion_entitlement e WHERE user_id=$1`, actor)
			if after != before {
				t.Fatalf("pending Stripe fence changed: %s -> %s", before, after)
			}
			var copied bool
			if err := dstPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_memberships WHERE team_id=$1)`, cfg.teamID).Scan(&copied); err != nil || copied {
				t.Fatalf("pending Stripe fence permitted member copy: %t %v", copied, err)
			}
		})
	}
	t.Run("missing destination authority fails closed", func(t *testing.T) {
		cfg, actor := newFixture()
		mustExec(t, srcPool, `INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at) VALUES($1,now())`, actor)
		mustExec(t, dstPool, `ALTER TABLE user_promotion_entitlement RENAME TO test_unavailable_stripe_entitlement`)
		defer mustExec(t, dstPool, `ALTER TABLE test_unavailable_stripe_entitlement RENAME TO user_promotion_entitlement`)
		err := mergeStripePromotionState(ctx, srcPool, dstPool, cfg.teamID, fmt.Sprintf(`SELECT id FROM profile WHERE %s`, profileScope))
		if err == nil || !strings.Contains(err.Error(), "both cells require Stripe entitlement authority") {
			t.Fatalf("missing Stripe authority should block transfer: %v", err)
		}
	})
}

func TestSignupTrialMigrationClaims(t *testing.T) {
	ctx := context.Background()
	mustExec(t, dstPool, `INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
		VALUES ($1, '192.0.2.1:50051', '192.0.2.1:8080', $2, 65536, 32)
		ON CONFLICT (id) DO NOTHING`, destHostID, destRegion)
	newProfile := func(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
		id := uuid.New()
		mustExec(t, pool, `INSERT INTO profile (id, email) VALUES ($1, $2)`, id, id.String()+"@example.com")
		return id
	}
	newLegacyTeam := func(t *testing.T, owner uuid.UUID) config {
		team := uuid.New()
		mustExec(t, srcPool, `INSERT INTO team (id, name) VALUES ($1, $2)`, team, "signup-copy-"+team.String())
		mustExec(t, srcPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, team, owner)
		mustExec(t, srcPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, team, owner)
		mustExec(t, srcPool, `INSERT INTO user_role_assignments (team_id, user_id, scope_type, role_id)
			SELECT $1, $2, 'team', id FROM roles WHERE name = 'team_owner'`, team, owner)
		return config{phase: phaseCopy, teamID: team, sourceURL: srcURL, destURL: dstURL, destHostID: destHostID, destRegion: destRegion}
	}
	newExplicitTeam := func(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID) uuid.UUID {
		var team uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT id FROM create_team_with_signup_trial($1, $2, 'use')`, "signup-prior-"+uuid.NewString(), owner).Scan(&team); err != nil {
			t.Fatal(err)
		}
		return team
	}

	t.Run("consumption is present before owner roles and copy retries", func(t *testing.T) {
		owner := newProfile(t, srcPool)
		cfg := newLegacyTeam(t, owner)
		mustExec(t, dstPool, fmt.Sprintf(`CREATE FUNCTION test_migration_signup_guard() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  IF NEW.team_id = '%s'::uuid AND NOT EXISTS (
			    SELECT 1 FROM user_signup_trial_claim c JOIN user_promotion_entitlement e USING (user_id)
			    WHERE c.user_id = NEW.user_id AND e.signup_trial_claimed_at = c.claimed_at
			  ) THEN RAISE EXCEPTION 'owner was copied before signup consumption'; END IF;
			  RETURN NEW;
			END $$`, cfg.teamID))
		mustExec(t, dstPool, `CREATE TRIGGER test_migration_signup_guard BEFORE INSERT ON user_role_assignments
			FOR EACH ROW EXECUTE FUNCTION test_migration_signup_guard()`)
		t.Cleanup(func() {
			mustExec(t, dstPool, `DROP TRIGGER test_migration_signup_guard ON user_role_assignments`)
			mustExec(t, dstPool, `DROP FUNCTION test_migration_signup_guard()`)
		})
		for range 2 {
			if err := run(ctx, cfg); err != nil {
				t.Fatalf("copy: %v", err)
			}
		}
		assertMigratedSignupConsumed(t, srcPool, owner, &cfg.teamID)
		assertMigratedSignupConsumed(t, dstPool, owner, &cfg.teamID)
		assertSignupRetryHasNoGrant(t, dstPool, owner)
	})

	t.Run("former creator only referenced by consumption marker", func(t *testing.T) {
		creator, owner := newProfile(t, srcPool), newProfile(t, srcPool)
		cfg := newLegacyTeam(t, creator)
		mustExec(t, srcPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, cfg.teamID, owner)
		mustExec(t, srcPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, cfg.teamID, owner)
		mustExec(t, srcPool, `INSERT INTO user_role_assignments (team_id, user_id, scope_type, role_id)
			SELECT $1, $2, 'team', id FROM roles WHERE name = 'team_owner'`, cfg.teamID, owner)
		mustExec(t, srcPool, `DELETE FROM user_role_assignments WHERE team_id=$1 AND user_id=$2`, cfg.teamID, creator)
		mustExec(t, srcPool, `DELETE FROM team_memberships WHERE team_id=$1 AND user_id=$2`, cfg.teamID, creator)
		mustExec(t, srcPool, `DELETE FROM team_member WHERE team_id=$1 AND profile_id=$2`, cfg.teamID, creator)
		mustExec(t, srcPool, `UPDATE team_credit_grant SET created_by=NULL WHERE team_id=$1`, cfg.teamID)
		if err := run(ctx, cfg); err != nil {
			t.Fatalf("copy: %v", err)
		}
		assertMigratedSignupConsumed(t, dstPool, creator, &cfg.teamID)
		assertSignupRetryHasNoGrant(t, dstPool, creator)
		var ownerClaimed bool
		if err := dstPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_signup_trial_claim WHERE user_id=$1)`, owner).Scan(&ownerClaimed); err != nil || ownerClaimed {
			t.Fatalf("replacement owner consumed the former creator's entitlement: claimed=%t, error=%v", ownerClaimed, err)
		}
	})

	for _, association := range []string{"other-team", "deleted-team"} {
		t.Run(association, func(t *testing.T) {
			owner := newProfile(t, srcPool)
			priorTeam := newExplicitTeam(t, srcPool, owner)
			if association == "deleted-team" {
				mustExec(t, srcPool, `DELETE FROM team_credit_grant WHERE team_id=$1`, priorTeam)
				mustExec(t, srcPool, `DELETE FROM team WHERE id=$1`, priorTeam)
			}
			cfg := newLegacyTeam(t, owner)
			if err := run(ctx, cfg); err != nil {
				t.Fatalf("copy: %v", err)
			}
			assertMigratedSignupConsumed(t, dstPool, owner, nil)
			assertSignupRetryHasNoGrant(t, dstPool, owner)
			var eligible bool
			if err := dstPool.QueryRow(ctx, `SELECT team_sandbox_billing_eligible($1)`, cfg.teamID).Scan(&eligible); err != nil || eligible {
				t.Fatalf("migrated denied team must remain billing-ineligible: eligible=%t, error=%v", eligible, err)
			}
		})
	}

	for _, authority := range []string{"claim", "entitlement-only", "deleted-team"} {
		t.Run("departed denied creator with "+authority, func(t *testing.T) {
			creator, owner := newProfile(t, srcPool), newProfile(t, srcPool)
			priorTeam := newExplicitTeam(t, srcPool, creator)
			claimedTeam := &priorTeam
			if authority == "deleted-team" {
				mustExec(t, srcPool, `DELETE FROM team_credit_grant WHERE team_id=$1`, priorTeam)
				mustExec(t, srcPool, `DELETE FROM team WHERE id=$1`, priorTeam)
				claimedTeam = nil
			}
			cfg := newLegacyTeam(t, creator)
			mustExec(t, srcPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, cfg.teamID, owner)
			mustExec(t, srcPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, cfg.teamID, owner)
			mustExec(t, srcPool, `INSERT INTO user_role_assignments (team_id, user_id, scope_type, role_id)
				SELECT $1, $2, 'team', id FROM roles WHERE name = 'team_owner'`, cfg.teamID, owner)
			mustExec(t, srcPool, `DELETE FROM user_role_assignments WHERE team_id=$1 AND user_id=$2`, cfg.teamID, creator)
			mustExec(t, srcPool, `DELETE FROM team_memberships WHERE team_id=$1 AND user_id=$2`, cfg.teamID, creator)
			mustExec(t, srcPool, `DELETE FROM team_member WHERE team_id=$1 AND profile_id=$2`, cfg.teamID, creator)
			var inProfileScope, completedDenial bool
			if err := srcPool.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM profile WHERE id=$2 AND (%s)),
				EXISTS (SELECT 1 FROM team_signup_trial_provenance p JOIN team_signup_trial_denial d USING (team_id)
				WHERE p.team_id=$1 AND p.creator_user_id=$2 AND p.completed_at IS NOT NULL)`, profileScope),
				cfg.teamID, creator).Scan(&inProfileScope, &completedDenial); err != nil || inProfileScope || !completedDenial {
				t.Fatalf("creator must remain linked only by completed provenance: in scope=%t, denied=%t, error=%v", inProfileScope, completedDenial, err)
			}
			assertMigratedSignupConsumed(t, srcPool, creator, claimedTeam)
			if authority == "entitlement-only" {
				mustExec(t, srcPool, `DELETE FROM user_signup_trial_claim WHERE user_id=$1`, creator)
			}
			for range 2 {
				if err := run(ctx, cfg); err != nil {
					t.Fatalf("copy: %v", err)
				}
				assertMigratedSignupConsumed(t, dstPool, creator, nil)
			}
			cfg.phase = phaseDetach
			cfg.confirmTeamName = "signup-copy-" + cfg.teamID.String()
			if err := run(ctx, cfg); err != nil {
				t.Fatalf("detach: %v", err)
			}
			assertMigratedSignupConsumed(t, dstPool, creator, nil)
			assertSignupRetryHasNoGrant(t, dstPool, creator)
			var eligible, ownerClaimed bool
			if err := dstPool.QueryRow(ctx, `SELECT team_sandbox_billing_eligible($1),
				EXISTS (SELECT 1 FROM user_signup_trial_claim WHERE user_id=$2)`, cfg.teamID, owner).Scan(&eligible, &ownerClaimed); err != nil || eligible || ownerClaimed {
				t.Fatalf("denial and replacement owner eligibility must be preserved: eligible=%t, owner claimed=%t, error=%v", eligible, ownerClaimed, err)
			}
			// Model a further destination with no consumption for this actor.
			// Detach has removed the source's old provenance, so this transfer
			// can recover the actor only from the first destination's link.
			mustExec(t, srcPool, `DELETE FROM user_signup_trial_claim WHERE user_id=$1`, creator)
			mustExec(t, srcPool, `DELETE FROM user_promotion_entitlement WHERE user_id=$1`, creator)
			if err := mergeSignupTrialState(ctx, dstPool, srcPool, cfg.teamID); err != nil {
				t.Fatalf("second-hop consumption transfer: %v", err)
			}
			assertMigratedSignupConsumed(t, srcPool, creator, nil)
			assertSignupRetryHasNoGrant(t, srcPool, creator)
		})
	}

	t.Run("preserves destination claims and independent Stripe state", func(t *testing.T) {
		owner := newProfile(t, srcPool)
		cfg := newLegacyTeam(t, owner)
		mustExec(t, dstPool, `INSERT INTO profile (id, email) VALUES ($1, $2)`, owner, owner.String()+"@example.com")
		priorTeam := newExplicitTeam(t, dstPool, owner)
		mustExec(t, dstPool, `UPDATE user_promotion_entitlement SET stripe_redemption_at=now(), stripe_redemption_team_id=$2 WHERE user_id=$1`, owner, priorTeam)
		before := scanString(t, dstPool, `SELECT to_jsonb(e)::text FROM user_promotion_entitlement e WHERE user_id=$1`, owner)
		for range 2 {
			if err := run(ctx, cfg); err != nil {
				t.Fatalf("copy: %v", err)
			}
		}
		after := scanString(t, dstPool, `SELECT to_jsonb(e)::text FROM user_promotion_entitlement e WHERE user_id=$1`, owner)
		if before != after {
			t.Fatalf("destination entitlement changed: before=%s, after=%s", before, after)
		}
		assertMigratedSignupConsumed(t, dstPool, owner, &priorTeam)
		assertSignupRetryHasNoGrant(t, dstPool, owner)
	})

	t.Run("source entitlement-only consumption", func(t *testing.T) {
		owner := newProfile(t, srcPool)
		cfg := newLegacyTeam(t, owner)
		mustExec(t, srcPool, `DELETE FROM user_signup_trial_claim WHERE user_id=$1`, owner)
		if err := run(ctx, cfg); err != nil {
			t.Fatalf("copy: %v", err)
		}
		assertMigratedSignupConsumed(t, dstPool, owner, &cfg.teamID)
		assertSignupRetryHasNoGrant(t, dstPool, owner)
	})

	t.Run("destination entitlement-only consumption wins", func(t *testing.T) {
		owner := newProfile(t, srcPool)
		cfg := newLegacyTeam(t, owner)
		mustExec(t, dstPool, `INSERT INTO profile (id, email) VALUES ($1, $2)`, owner, owner.String()+"@example.com")
		priorTeam := newExplicitTeam(t, dstPool, owner)
		mustExec(t, dstPool, `DELETE FROM user_signup_trial_claim WHERE user_id=$1`, owner)
		if err := run(ctx, cfg); err != nil {
			t.Fatalf("copy: %v", err)
		}
		assertMigratedSignupConsumed(t, dstPool, owner, &priorTeam)
	})

	t.Run("missing destination schema fails before copying ownership", func(t *testing.T) {
		owner := newProfile(t, srcPool)
		cfg := newLegacyTeam(t, owner)
		mustExec(t, dstPool, `ALTER TABLE user_signup_trial_claim RENAME TO test_unavailable_signup_claim`)
		defer mustExec(t, dstPool, `ALTER TABLE test_unavailable_signup_claim RENAME TO user_signup_trial_claim`)
		err := run(ctx, cfg)
		if err == nil || !strings.Contains(err.Error(), "cannot preserve consumed signup claims") {
			t.Fatalf("missing schema must block migration: %v", err)
		}
		var owners int
		if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM user_role_assignments WHERE team_id=$1`, cfg.teamID).Scan(&owners); err != nil || owners != 0 {
			t.Fatalf("unsupported destination received ownership: owners=%d, error=%v", owners, err)
		}
	})

	t.Run("missing destination denial schema fails before copying ownership", func(t *testing.T) {
		owner := newProfile(t, srcPool)
		newExplicitTeam(t, srcPool, owner)
		cfg := newLegacyTeam(t, owner)
		mustExec(t, dstPool, `ALTER TABLE team_signup_trial_denial RENAME TO test_unavailable_signup_denial`)
		defer mustExec(t, dstPool, `ALTER TABLE test_unavailable_signup_denial RENAME TO team_signup_trial_denial`)
		err := run(ctx, cfg)
		if err == nil || !strings.Contains(err.Error(), "cannot preserve signup denial") {
			t.Fatalf("missing denial schema must block migration: %v", err)
		}
		var owners int
		if err := dstPool.QueryRow(ctx, `SELECT count(*) FROM user_role_assignments WHERE team_id=$1`, cfg.teamID).Scan(&owners); err != nil || owners != 0 {
			t.Fatalf("unsupported destination received ownership: owners=%d, error=%v", owners, err)
		}
	})

	t.Run("older source requires backfill before expanded destination", func(t *testing.T) {
		owner := newProfile(t, srcPool)
		cfg := newLegacyTeam(t, owner)
		tx, err := srcPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `ALTER TABLE user_signup_trial_claim RENAME TO test_old_signup_claim;
			ALTER TABLE user_promotion_entitlement RENAME TO test_old_promotion_entitlement;
			ALTER TABLE team_signup_trial_denial RENAME TO test_old_signup_denial`); err != nil {
			t.Fatal(err)
		}
		if err := mergeSignupTrialState(ctx, tx, dstPool, cfg.teamID); err == nil || !strings.Contains(err.Error(), "source has no promotion authority") {
			t.Fatalf("old source consumption must not be lost: %v", err)
		}
		// Old-to-old migrations retain their existing contract. Both sides
		// must install the backfill before enabling promotion enforcement.
		for _, table := range []string{"user_signup_trial_claim", "user_promotion_entitlement", "team_signup_trial_denial"} {
			mustExec(t, dstPool, "ALTER TABLE "+table+" RENAME TO test_old_"+table)
			defer mustExec(t, dstPool, "ALTER TABLE test_old_"+table+" RENAME TO "+table)
		}
		if err := mergeSignupTrialState(ctx, tx, dstPool, cfg.teamID); err != nil {
			t.Fatalf("old-to-old migration: %v", err)
		}
	})

	t.Run("consumed claims from source without legacy provenance", func(t *testing.T) {
		owner := newProfile(t, srcPool)
		cfg := newLegacyTeam(t, owner)
		tx, err := srcPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `ALTER TABLE team_signup_trial_provenance RENAME TO test_old_signup_provenance`); err != nil {
			t.Fatal(err)
		}
		if err := mergeSignupTrialState(ctx, tx, dstPool, cfg.teamID); err != nil {
			t.Fatalf("source without provenance: %v", err)
		}
		assertMigratedSignupConsumed(t, dstPool, owner, nil)
		assertSignupRetryHasNoGrant(t, dstPool, owner)
	})
}

// TestPurgeWithoutDetach proves purge still stands alone: a source that never
// went through detach keeps its membership rows, so the internal validate
// must compare them in full (nothing is skipped) and the deletes take the
// whole team in one pass — the pre-split decommission behavior.
func TestPurgeWithoutDetach(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()
	owner := uuid.New()
	sb := uuid.New()

	mustExec(t, dstPool, `
		INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
		VALUES ($1, '10.1.0.1:50051', '10.1.0.1:8080', $2, 65536, 32)
		ON CONFLICT (id) DO NOTHING`, destHostID, destRegion)

	mustExec(t, srcPool, `INSERT INTO team (id, name) VALUES ($1, 'purge-direct-drill')`, team)
	mustExec(t, srcPool, `INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, 'direct-owner@example.com', 'google', 'google-direct')`, owner)
	mustExec(t, srcPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, team, owner)
	mustExec(t, srcPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, team, owner)
	mustExec(t, srcPool, `
		INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id, granted_by)
		SELECT $2, r.id, 'team', $1, $2 FROM roles r WHERE r.name = 'team_owner'`, team, owner)
	sbDir := "/srv/sandboxes/" + sb.String()
	mustExec(t, srcPool, `
		INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id,
		                     snapshot_path, mem_path, base_path, delta_path)
		VALUES ($1, $2, 'direct-sb', 'paused', 1, 1024, $3,
		        $4||'/vmstate.snap', $4||'/mem.snap', $4||'/base.ext4', $4||'/delta.ext4')`,
		sb, team, sourceHostID, sbDir)

	cfg := config{
		teamID:     team,
		sourceURL:  srcURL,
		destURL:    dstURL,
		destHostID: destHostID,
		destRegion: destRegion,
	}

	cfg.phase = phaseCopy
	if err := run(ctx, cfg); err != nil {
		t.Fatalf("copy: %v", err)
	}

	cfg.phase = phasePurge
	cfg.confirmTeamName = "purge-direct-drill"
	if err := run(ctx, cfg); err != nil {
		t.Fatalf("purge without a prior detach: %v", err)
	}

	for _, table := range []string{"team_member", "team_memberships", "sandbox"} {
		var n int64
		if err := srcPool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE team_id = $1`, table), team).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("source %s still has %d team rows", table, n)
		}
	}
	var n int64
	if err := srcPool.QueryRow(ctx, `SELECT count(*) FROM team WHERE id = $1`, team).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("source team row survived the purge")
	}
	for table, want := range map[string]int64{"team": 1, "team_member": 1, "team_memberships": 1, "sandbox": 1} {
		q := `SELECT count(*) FROM ` + table + ` WHERE team_id = $1`
		if table == "team" {
			q = `SELECT count(*) FROM team WHERE id = $1`
		}
		if err := dstPool.QueryRow(ctx, q, team).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("dest %s: got %d rows, want %d", table, n, want)
		}
	}
}

// A deleted saved snapshot no sandbox refers to is a retry key with no
// artifacts: it neither holds the copy back nor survives the purge. A live
// one holds the copy back.
func TestDeletedSnapshotsNeitherBlockNorSurvive(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()
	owner := uuid.New()
	sb := uuid.New()

	mustExec(t, dstPool, `
		INSERT INTO host (id, vmd_addr, proxy_addr, region, capacity_memory_mib, capacity_vcpus)
		VALUES ($1, '10.1.0.1:50051', '10.1.0.1:8080', $2, 65536, 32)
		ON CONFLICT (id) DO NOTHING`, destHostID, destRegion)
	mustExec(t, srcPool, `INSERT INTO team (id, name) VALUES ($1, 'snapshot-drill')`, team)
	mustExec(t, srcPool, `INSERT INTO profile (id, email, provider, provider_id) VALUES ($1, 'snapshot-owner@example.com', 'google', 'google-snapshot')`, owner)
	mustExec(t, srcPool, `INSERT INTO team_member (team_id, profile_id, role) VALUES ($1, $2, 'owner')`, team, owner)
	mustExec(t, srcPool, `INSERT INTO team_memberships (team_id, user_id, status) VALUES ($1, $2, 'active')`, team, owner)
	mustExec(t, srcPool, `
		INSERT INTO user_role_assignments (user_id, role_id, scope_type, team_id, granted_by)
		SELECT $2, r.id, 'team', $1, $2 FROM roles r WHERE r.name = 'team_owner'`, team, owner)
	sbDir := "/srv/sandboxes/" + sb.String()
	mustExec(t, srcPool, `
		INSERT INTO sandbox (id, team_id, name, status, vcpu_count, memory_mib, host_id,
		                     snapshot_path, mem_path, base_path, delta_path)
		VALUES ($1, $2, 'snapshot-sb', 'paused', 1, 1024, $3,
		        $4||'/vmstate.snap', $4||'/mem.snap', $4||'/base.ext4', $4||'/delta.ext4')`,
		sb, team, sourceHostID, sbDir)
	deleted := uuid.New()
	mustExec(t, srcPool, `
		INSERT INTO sandbox_snapshot (id, team_id, sandbox_id, kind, status, host_id, vcpu_count, memory_mib, disk_mib, base_path, deleted_at)
		VALUES ($1, $2, $3, 'mem+fs', 'deleting', $4, 1, 1024, 4096, $5||'/base.ext4', now())`,
		deleted, team, sb, sourceHostID, sbDir)

	cfg := config{teamID: team, sourceURL: srcURL, destURL: dstURL, destHostID: destHostID, destRegion: destRegion}
	live := uuid.New()
	mustExec(t, srcPool, `
		INSERT INTO sandbox_snapshot (id, team_id, sandbox_id, kind, status, host_id, vcpu_count, memory_mib, disk_mib, base_path, overlay_path, snapshot_path, mem_path)
		VALUES ($1, $2, $3, 'mem+fs', 'ready', $4, 1, 1024, 4096, $5||'/base.ext4', '/o', '/v', '/m')`,
		live, team, sb, sourceHostID, sbDir)
	cfg.phase = phaseCopy
	err := run(ctx, cfg)
	if err == nil || !strings.Contains(err.Error(), live.String()) || strings.Contains(err.Error(), deleted.String()) {
		t.Fatalf("copy with a live snapshot: want a refusal naming only the live one, got %v", err)
	}
	mustExec(t, srcPool, `UPDATE sandbox_snapshot SET status = 'deleting', deleted_at = now() WHERE id = $1`, live)

	if err := run(ctx, cfg); err != nil {
		t.Fatalf("copy with only deleted snapshots: %v", err)
	}
	cfg.phase = phasePurge
	cfg.confirmTeamName = "snapshot-drill"
	if err := run(ctx, cfg); err != nil {
		t.Fatalf("purge: %v", err)
	}
	var n int64
	if err := srcPool.QueryRow(ctx, `SELECT count(*) FROM sandbox_snapshot WHERE team_id = $1`, team).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("source still holds %d deleted snapshot rows after the purge", n)
	}
	if err := srcPool.QueryRow(ctx, `SELECT count(*) FROM team WHERE id = $1`, team).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("source team row survived the purge")
	}
}
