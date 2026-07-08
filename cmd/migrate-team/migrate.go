package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

const (
	phasePlan           = "plan"
	phaseCopy           = "copy"
	phaseValidate       = "validate"
	phaseDecommission   = "decommission"
	phaseReleaseRollups = "release-rollups"

	copyBatchSize = 500
)

type config struct {
	teamID          uuid.UUID
	sourceURL       string
	destURL         string
	destHostID      string
	destRegion      string
	phase           string
	confirmTeamName string
	pathsOut        string
}

// dbIdentity fingerprints the database a pool is connected to by cluster
// identity plus database name — never by connection endpoint. The same
// database reached through a pooler and directly must collapse to ONE
// identity (endpoint-based fingerprints pass the guard and turn
// copy/validate into self-comparisons before decommission deletes the only
// copy), while two databases in one cluster stay distinct via
// current_database(). system_identifier is initdb-unique and stable across
// restarts; where a managed provider restricts pg_control_system(), the
// postmaster start time is a practically-collision-free stand-in.
func dbIdentity(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `
		SELECT system_identifier::text || '|' || current_database()
		FROM pg_control_system()`).Scan(&id)
	if err == nil {
		return id, nil
	}
	log.Warn().Err(err).Msg("pg_control_system() unavailable; falling back to postmaster start time for the same-DB guard")
	err = pool.QueryRow(ctx, `
		SELECT pg_postmaster_start_time()::text || '|' || current_database()`).Scan(&id)
	return id, err
}

func run(ctx context.Context, cfg config) error {
	src, err := pgxpool.New(ctx, cfg.sourceURL)
	if err != nil {
		return fmt.Errorf("connect to source: %w", err)
	}
	defer src.Close()

	var dst *pgxpool.Pool
	if cfg.destURL != "" {
		dst, err = pgxpool.New(ctx, cfg.destURL)
		if err != nil {
			return fmt.Errorf("connect to dest: %w", err)
		}
		defer dst.Close()

		// Fail fast if both DSNs land on the same database — string
		// comparison can't catch pooler-vs-direct spellings of one DB, so
		// compare live identity instead. With source == dest every later
		// safeguard becomes a self-comparison: copy no-ops, validate
		// passes against itself, and decommission would delete the only
		// copy of the team.
		srcID, err := dbIdentity(ctx, src)
		if err != nil {
			return fmt.Errorf("identify source database: %w", err)
		}
		dstID, err := dbIdentity(ctx, dst)
		if err != nil {
			return fmt.Errorf("identify dest database: %w", err)
		}
		if srcID == dstID {
			return fmt.Errorf("--source-db and --dest-db resolve to the same database; refusing every dest-touching phase")
		}
	}

	var teamName string
	if err := src.QueryRow(ctx, `SELECT name FROM team WHERE id = $1`, cfg.teamID).Scan(&teamName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("team %s not found in source", cfg.teamID)
		}
		return fmt.Errorf("look up team: %w", err)
	}
	log.Info().Str("phase", cfg.phase).Str("team", teamName).Str("team_id", cfg.teamID.String()).Msg("migrate-team")

	switch cfg.phase {
	case phasePlan:
		return runPlan(ctx, src, cfg)
	case phaseCopy:
		return runCopy(ctx, src, dst, cfg)
	case phaseValidate:
		return runValidate(ctx, src, dst, cfg)
	case phaseDecommission:
		return runDecommission(ctx, src, dst, cfg, teamName)
	case phaseReleaseRollups:
		return runReleaseRollups(ctx, src, dst, cfg)
	}
	return fmt.Errorf("unknown phase %q", cfg.phase)
}

// ---------------------------------------------------------------------------
// release-rollups
// ---------------------------------------------------------------------------

// runReleaseRollups lifts the copy's rollup hold at cutover: any earlier and
// the dest scheduler can mint rollup state from the copied intervals that
// never existed in source, wedging validate or drifting after it. Restores
// the source's actual flag state — its value when a row exists there,
// absence when none does.
func runReleaseRollups(ctx context.Context, src, dst *pgxpool.Pool, cfg config) error {
	var srcEnabled *bool
	if err := src.QueryRow(ctx, `
		SELECT enabled FROM team_feature_flag WHERE team_id = $1 AND key = 'billing_hourly_rollups'`,
		cfg.teamID).Scan(&srcEnabled); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check source rollup flag: %w", err)
	}
	return restoreRollupFlag(ctx, dst, cfg.teamID, srcEnabled)
}

// restoreRollupFlag writes the source's rollup-flag state into the dest: the
// source's value when a row existed, absence when none did. Shared by the
// standalone release-rollups phase (source still present) and decommission
// (which captures the state before deleting the source).
func restoreRollupFlag(ctx context.Context, dst *pgxpool.Pool, teamID uuid.UUID, srcEnabled *bool) error {
	if srcEnabled == nil {
		if _, err := dst.Exec(ctx, `
			DELETE FROM team_feature_flag WHERE team_id = $1 AND key = 'billing_hourly_rollups'`, teamID); err != nil {
			return fmt.Errorf("release dest rollup hold: %w", err)
		}
		log.Info().Msg("rollup hold removed; dest follows the default")
		return nil
	}
	if _, err := dst.Exec(ctx, `
		INSERT INTO team_feature_flag (team_id, key, enabled)
		VALUES ($1, 'billing_hourly_rollups', $2)
		ON CONFLICT (team_id, key) DO UPDATE SET enabled = $2`, teamID, *srcEnabled); err != nil {
		return fmt.Errorf("restore dest rollup flag: %w", err)
	}
	log.Info().Bool("enabled", *srcEnabled).Msg("dest rollup flag restored to the source state")
	return nil
}

// ---------------------------------------------------------------------------
// plan

func runPlan(ctx context.Context, src *pgxpool.Pool, cfg config) error {
	for _, t := range migratedTables {
		var n int64
		q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s`, t.name, t.effectiveCopyScope())
		if err := src.QueryRow(ctx, q, cfg.teamID).Scan(&n); err != nil {
			return fmt.Errorf("count %s: %w", t.name, err)
		}
		log.Info().Str("table", t.name).Int64("rows", n).Msg("plan: will copy")
	}
	for _, s := range skippedTables {
		log.Info().Str("table", s.name).Str("reason", s.reason).Msg("plan: will NOT copy")
	}

	blockers, err := activeSandboxes(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	if len(blockers) > 0 {
		for _, b := range blockers {
			log.Warn().Str("sandbox", b).Msg("plan: BLOCKER — sandbox not paused; copy will refuse")
		}
	} else {
		log.Info().Msg("plan: no active sandboxes; copy can proceed")
	}

	builds, err := activeBuilds(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	for _, b := range builds {
		log.Warn().Str("build", b).Msg("plan: BLOCKER — template build in flight; copy will refuse")
	}
	liveKeys, err := unrevokedKeys(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	for _, k := range liveKeys {
		log.Warn().Str("api_key", k).Msg("plan: BLOCKER — key not revoked; copy will refuse (freeze rotates keys)")
	}

	return reportArtifactDirs(ctx, src, cfg)
}

// unrevokedKeys returns the team's live API keys ("<id> (<name>)"). The
// freeze must revoke every key before copy: key strings carry a plaintext
// region prefix that hashes can't rewrite, so an un-revoked ss_live_use_
// key would keep routing clients at the old cell after cutover — and its
// hash, copied here, would silently authenticate against the new cell if
// pointed there by hand. Revoked rows copy as history; live ones block.
func unrevokedKeys(ctx context.Context, src *pgxpool.Pool, teamID uuid.UUID) ([]string, error) {
	rows, err := src.Query(ctx, `
		SELECT id, name FROM api_key
		WHERE team_id = $1 AND revoked_at IS NULL
		ORDER BY created_at`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list unrevoked keys: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s (%s)", id, name))
	}
	return out, rows.Err()
}

// activeBuilds returns in-flight template builds ("<id> status=<status>")
// for the team. The freeze must wait these out (or cancel them): copying
// mid-build template rows would strand half-written artifacts, and the
// build rows themselves are pinned to source-cell build VMs.
func activeBuilds(ctx context.Context, src querier, teamID uuid.UUID) ([]string, error) {
	rows, err := src.Query(ctx, `
		SELECT id, status FROM template_build
		WHERE team_id = $1 AND status IN ('pending', 'building', 'snapshotting')
		ORDER BY created_at`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list active builds: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id uuid.UUID
		var status string
		if err := rows.Scan(&id, &status); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s status=%s", id, status))
	}
	return out, rows.Err()
}

// activeSandboxes returns "<id> (<name>) status=<status>" for every sandbox
// that must be paused or destroyed before copy may run. 'pausing' blocks
// too: quota is already freed but snapshot finalization is in flight, so
// the on-disk artifacts are not yet quiescent. 'failed' blocks as well —
// a failed sandbox may still hold a VM, rundir, and snapshot dir that the
// destroy path tears down; migrating the row and then deleting it from the
// source with raw SQL would strand those host resources. Destroy failed
// sandboxes before the window.
func activeSandboxes(ctx context.Context, src *pgxpool.Pool, teamID uuid.UUID) ([]string, error) {
	rows, err := src.Query(ctx, `
		SELECT id, name, status FROM sandbox
		WHERE team_id = $1 AND destroyed_at IS NULL
		  AND status IN ('active', 'starting', 'resuming', 'pausing', 'failed')
		ORDER BY created_at`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list active sandboxes: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id uuid.UUID
		var name, status string
		if err := rows.Scan(&id, &name, &status); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s (%s) status=%s", id, name, status))
	}
	return out, rows.Err()
}

// artifactDirs returns the distinct directories holding the team's template
// and sandbox/snapshot artifacts on the source hosts. The runbook's GCS copy
// step consumes this list. Soft-deleted templates and destroyed sandboxes are
// excluded — their artifacts are already reaped.
func artifactDirs(ctx context.Context, src *pgxpool.Pool, teamID uuid.UUID) ([]string, error) {
	rows, err := src.Query(ctx, `
		SELECT DISTINCT p FROM (
			SELECT unnest(ARRAY[rootfs_path, snapshot_path, mem_path, base_path, delta_path]) AS p
			FROM template WHERE team_id = $1 AND deleted_at IS NULL
			UNION ALL
			SELECT unnest(ARRAY[snapshot_path, mem_path, base_path, delta_path])
			FROM sandbox WHERE team_id = $1 AND destroyed_at IS NULL
			UNION ALL
			SELECT unnest(ARRAY[sn.path, sn.mem_path])
			FROM snapshot sn JOIN sandbox s ON s.id = sn.sandbox_id
			WHERE sn.team_id = $1 AND s.destroyed_at IS NULL
		) q WHERE p IS NOT NULL AND p <> ''`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list artifact paths: %w", err)
	}
	defer rows.Close()

	dirs := map[string]struct{}{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		dirs[path.Dir(p)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(dirs))
	for d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// reportArtifactDirs logs the artifact directory list and, when --paths-out
// is set, writes it one dir per line for the runbook's copy step.
func reportArtifactDirs(ctx context.Context, src *pgxpool.Pool, cfg config) error {
	dirs, err := artifactDirs(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	for _, d := range dirs {
		log.Info().Str("dir", d).Msg("artifact directory (copy via GCS, out of scope for this tool)")
	}
	log.Info().Int("count", len(dirs)).Msg("artifact directories")
	if cfg.pathsOut == "" {
		return nil
	}
	var buf bytes.Buffer
	for _, d := range dirs {
		buf.WriteString(d)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(cfg.pathsOut, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write --paths-out: %w", err)
	}
	log.Info().Str("file", cfg.pathsOut).Msg("wrote artifact directory list")
	return nil
}

// ---------------------------------------------------------------------------
// copy

// rowTransform mutates a row (as a column→value map) before it is inserted
// into the dest.
type rowTransform func(row map[string]any) error

func runCopy(ctx context.Context, src, dst *pgxpool.Pool, cfg config) error {
	// The window requires everything paused or destroyed. Hard-stop otherwise.
	blockers, err := activeSandboxes(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	if len(blockers) > 0 {
		return fmt.Errorf("refusing to copy: %d sandbox(es) not paused/destroyed:\n  %s",
			len(blockers), strings.Join(blockers, "\n  "))
	}
	builds, err := activeBuilds(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	if len(builds) > 0 {
		return fmt.Errorf("refusing to copy: %d template build(s) in flight (wait or cancel):\n  %s",
			len(builds), strings.Join(builds, "\n  "))
	}
	liveKeys, err := unrevokedKeys(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	if len(liveKeys) > 0 {
		return fmt.Errorf("refusing to copy: %d API key(s) not revoked (freeze step — the region prefix in the key string cannot follow the team):\n  %s",
			len(liveKeys), strings.Join(liveKeys, "\n  "))
	}

	// The dest host must exist and live in the dest region before any
	// sandbox row points at it.
	var hostRegion string
	if err := dst.QueryRow(ctx, `SELECT region FROM host WHERE id = $1`, cfg.destHostID).Scan(&hostRegion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("dest host %q not found in dest cell; insert the host row first", cfg.destHostID)
		}
		return fmt.Errorf("look up dest host: %w", err)
	}
	if hostRegion != cfg.destRegion {
		return fmt.Errorf("dest host %q is in region %q, not --dest-region %q", cfg.destHostID, hostRegion, cfg.destRegion)
	}

	transforms, err := buildTransforms(ctx, src, dst, cfg)
	if err != nil {
		return err
	}

	var totalCopied, totalSkipped int64
	for _, t := range migratedTables {
		copied, skipped, err := copyTable(ctx, src, dst, t, cfg.teamID, transforms[t.name])
		if err == nil && t.name == "team" {
			// The moment intervals land, the dest scheduler could discover
			// this team under the default-TRUE rollup flag and mint jobs,
			// cursors, and hourly rows that never existed in source —
			// dest-only rows this tool never deletes, wedging validate.
			// Hold rollups off with an explicit false override as soon as
			// the team row (FK target) exists; team_feature_flag copies
			// next and converges over this row when the source has its own,
			// and the post-loop cleanup removes it when the source has none.
			if _, herr := dst.Exec(ctx, `
				INSERT INTO team_feature_flag (team_id, key, enabled)
				VALUES ($1, 'billing_hourly_rollups', false)
				ON CONFLICT (team_id, key) DO UPDATE SET enabled = false`, cfg.teamID); herr != nil {
				return fmt.Errorf("hold dest rollups: %w", herr)
			}
		}
		if err != nil {
			return fmt.Errorf("copy %s: %w", t.name, err)
		}
		totalCopied += copied
		totalSkipped += skipped
		log.Info().Str("table", t.name).Int64("copied", copied).Int64("skipped", skipped).Msg("copy")
	}

	relinked, err := relinkSnapshots(ctx, src, dst, cfg.teamID)
	if err != nil {
		return fmt.Errorf("relink sandbox.snapshot_id: %w", err)
	}
	log.Info().Int64("relinked", relinked).Msg("copy: sandbox.snapshot_id relinked from source")

	log.Info().Msg("copy: dest rollups remain HELD for this team — decommission releases the hold itself; for migrations that keep the source, run --phase release-rollups at cutover after validate")

	for _, s := range skippedTables {
		log.Info().Str("table", s.name).Str("reason", s.reason).Msg("copy: NOT copied")
	}
	log.Info().Int64("copied", totalCopied).Int64("skipped_existing", totalSkipped).Msg("copy: done")
	log.Info().Msg("note: sandbox UUIDs are preserved but public IDs re-mint with the dest region prefix on next fetch — clients holding pre-migration sb-<region>- IDs or preview URLs must re-resolve after cutover")
	return nil
}

// buildTransforms wires up the per-table row rewrites: host remap, region
// rehoming, snapshot-cycle break, and the role-id remap by role name.
// querier is the read surface shared by pgxpool.Pool and pgx.Tx, so the
// transform builders can run against a locked transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func buildTransforms(ctx context.Context, src, dst querier, cfg config) (map[string]rowTransform, error) {
	srcRoleNames, err := roleNamesByID(ctx, src)
	if err != nil {
		return nil, fmt.Errorf("load source roles: %w", err)
	}
	destRoleIDs, err := roleIDsByName(ctx, dst)
	if err != nil {
		return nil, fmt.Errorf("load dest roles: %w", err)
	}
	foreignTemplates, err := foreignTemplateRemap(ctx, src, dst, cfg.teamID)
	if err != nil {
		return nil, err
	}

	return map[string]rowTransform{
		"team": func(row map[string]any) error {
			// Rehome on every write — upserts converge, so a retry
			// re-asserts the dest region rather than trusting a stale row.
			row["home_region"] = cfg.destRegion
			// Dest quota triggers recount as sandbox rows land; starting
			// from the source's counter would double-count.
			row["active_sandbox_count"] = 0
			return nil
		},
		"sandbox": func(row map[string]any) error {
			row["host_id"] = cfg.destHostID
			// Break the sandbox.snapshot_id ↔ snapshot.sandbox_id cycle:
			// insert with NULL, relink after snapshots are in.
			row["snapshot_id"] = nil
			// Sandboxes booted from a system template reference the SYSTEM
			// team's template row, which is seeded per cell under a
			// different id — remap by name. The team's own templates copy
			// with their ids preserved and pass through untouched.
			if tid, ok := row["template_id"].(string); ok && tid != "" {
				if destID, foreign := foreignTemplates[tid]; foreign {
					row["template_id"] = destID
				}
			}
			return nil
		},
		"user_role_assignments": func(row map[string]any) error {
			// Role ids are migration-seeded per cell and differ; remap by
			// role NAME through the dest's roles table.
			roleID, _ := row["role_id"].(string)
			name, ok := srcRoleNames[roleID]
			if !ok {
				return fmt.Errorf("role %s not found in source roles", roleID)
			}
			destID, ok := destRoleIDs[name]
			if !ok {
				return fmt.Errorf("role %q has no counterpart in dest roles; seed dest migrations first", name)
			}
			row["role_id"] = destID
			return nil
		},
	}, nil
}

// foreignTemplateRemap maps source template ids that the team's sandboxes
// reference but the team does NOT own (system templates, e.g.
// superserve/base) to the dest cell's template of the same name. System
// templates are seeded per cell with fresh ids, so copying sandbox rows
// verbatim would point their template_id FK at nothing. Fails fast when the
// dest is missing a referenced template — seed the dest cell first.
func foreignTemplateRemap(ctx context.Context, src, dst querier, teamID uuid.UUID) (map[string]string, error) {
	rows, err := src.Query(ctx, `
		SELECT DISTINCT t.id::text, t.name, tm.name
		FROM sandbox s
		JOIN template t ON t.id = s.template_id
		JOIN team tm ON tm.id = t.team_id
		WHERE s.team_id = $1 AND t.team_id <> $1`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list foreign templates: %w", err)
	}
	defer rows.Close()

	type foreignTpl struct{ name, ownerName string }
	srcTpls := map[string]foreignTpl{}
	for rows.Next() {
		var id, name, ownerName string
		if err := rows.Scan(&id, &name, &ownerName); err != nil {
			return nil, err
		}
		srcTpls[id] = foreignTpl{name: name, ownerName: ownerName}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Resolve in dest through the OWNING team's name, never "any other
	// team": template names are only unique per team, so a customer
	// template that happens to shadow a system name must not be chosen.
	// Team names are unique per cell and the system team is seeded with
	// the same name in every cell, so (owner name, template name) is a
	// stable cross-cell identity.
	remap := map[string]string{}
	for id, tpl := range srcTpls {
		var destID string
		err := dst.QueryRow(ctx, `
			SELECT t.id::text FROM template t
			JOIN team tm ON tm.id = t.team_id
			WHERE t.name = $1 AND tm.name = $2 AND t.deleted_at IS NULL AND t.status = 'ready'
			ORDER BY t.created_at DESC LIMIT 1`, tpl.name, tpl.ownerName).Scan(&destID)
		if err != nil {
			return nil, fmt.Errorf("template %q owned by team %q (referenced by the migrating team's sandboxes) has no ready counterpart in dest — seed the dest cell first: %w", tpl.name, tpl.ownerName, err)
		}
		remap[id] = destID
	}
	return remap, nil
}

func roleNamesByID(ctx context.Context, pool querier) (map[string]string, error) {
	rows, err := pool.Query(ctx, `SELECT id::text, name FROM roles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

func roleIDsByName(ctx context.Context, pool querier) (map[string]string, error) {
	byID, err := roleNamesByID(ctx, pool)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(byID))
	for id, name := range byID {
		out[name] = id
	}
	return out, nil
}

// conflictClause builds the ON CONFLICT arm for a table's upsert: update
// every non-key column from EXCLUDED, keyed on the primary key. No primary
// key (nothing to target) degrades to DO NOTHING.
// insertOnlyTables never update an existing dest row. profile rows are
// per-cell projections of global identity shared across ALL of a user's
// teams in that cell — the migration promises a member's profile EXISTS in
// the dest, never that it overwrites what the user's other teams already
// maintain there. Content checksums skip these for the same reason; count
// parity over the member scope still applies.
// validationExemptTables are copied for safety but never gated on:
// sandbox_revocation and revoked_proxy_token rows self-expire, and the
// SOURCE reaper prunes expired rows on its own schedule while this tool
// never deletes dest rows — so parity between the two sides is expected to
// drift and carries no migration-correctness signal. The rows exist to stop
// stale sandbox JWTs from replaying against the dest proxy; extras are
// harmless, missing expired ones equally so.
var validationExemptTables = map[string]bool{
	"sandbox_revocation":  true,
	"revoked_proxy_token": true,
}

var insertOnlyTables = map[string]bool{
	"profile": true,
}

// allColumns lists a table's column names in attnum order.
func allColumns(ctx context.Context, dst *pgxpool.Pool, table string) ([]string, error) {
	rows, err := dst.Query(ctx, `
		SELECT a.attname FROM pg_attribute a
		WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum`, table)
	if err != nil {
		return nil, fmt.Errorf("columns of %s: %w", table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// conflictTargets overrides the upsert's conflict column set where a table's
// natural uniqueness isn't its primary key. billing_rollup_job: the DEST
// cell's own rollup scheduler enqueues (team_id, hour_start) rows the moment
// the copied team + intervals become visible, under a fresh id — a PK-keyed
// upsert then hits the (team_id, hour_start) unique constraint and can never
// converge. Conflicting on the natural key instead lets the copy overwrite
// scheduler-created rows (id included) and re-runs stay idempotent.
var conflictTargets = map[string]string{
	"billing_rollup_job": "(team_id, hour_start)",
}

func conflictClause(ctx context.Context, dst *pgxpool.Pool, table string) (string, error) {
	if insertOnlyTables[table] {
		return "ON CONFLICT DO NOTHING", nil
	}
	if target, ok := conflictTargets[table]; ok {
		cols, err := allColumns(ctx, dst, table)
		if err != nil {
			return "", err
		}
		targetCols := map[string]bool{}
		for _, c := range strings.Split(strings.Trim(target, "()"), ",") {
			targetCols[strings.TrimSpace(c)] = true
		}
		var updates []string
		for _, col := range cols {
			if targetCols[col] {
				continue
			}
			q := pgx.Identifier{col}.Sanitize()
			updates = append(updates, q+" = EXCLUDED."+q)
		}
		return fmt.Sprintf("ON CONFLICT %s DO UPDATE SET %s", target, strings.Join(updates, ", ")), nil
	}
	rows, err := dst.Query(ctx, `
		SELECT a.attname, COALESCE(i.indisprimary, false)
		FROM pg_attribute a
		LEFT JOIN pg_index i ON i.indrelid = a.attrelid AND i.indisprimary
			AND a.attnum = ANY (i.indkey)
		WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum`, table)
	if err != nil {
		return "", fmt.Errorf("introspect %s: %w", table, err)
	}
	defer rows.Close()

	var pks, updates []string
	for rows.Next() {
		var col string
		var isPK bool
		if err := rows.Scan(&col, &isPK); err != nil {
			return "", err
		}
		if isPK {
			pks = append(pks, pgx.Identifier{col}.Sanitize())
		} else {
			q := pgx.Identifier{col}.Sanitize()
			updates = append(updates, q+" = EXCLUDED."+q)
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(pks) == 0 {
		log.Warn().Str("table", table).Msg("no primary key — upsert degrades to DO NOTHING; checksum validation is the backstop")
		return "ON CONFLICT DO NOTHING", nil
	}
	if len(updates) == 0 {
		return fmt.Sprintf("ON CONFLICT (%s) DO NOTHING", strings.Join(pks, ", ")), nil
	}
	return fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET %s", strings.Join(pks, ", "), strings.Join(updates, ", ")), nil
}

// copyTable streams the team-scoped rows of one table from source to dest.
//
// Rows travel as jsonb (to_jsonb on the source, jsonb_populate_recordset on
// the dest), which round-trips every column type — uuid, enum, bytea, inet,
// numeric, arrays, nested jsonb — without this tool naming a single column,
// so schema drift in either cell surfaces as a loud error instead of silent
// truncation. Inserts upsert on the table's primary key (DO UPDATE with
// every non-key column from EXCLUDED): re-runs CONVERGE the dest onto the
// source's current content instead of skipping rows that already landed —
// a retry after a partial copy must never preserve a stale dest row while
// the source moved on (background writers keep running through the freeze).
// Tables without a primary key fall back to DO NOTHING with a warning;
// validate's per-row checksums remain the backstop either way.
func copyTable(ctx context.Context, src querier, dst *pgxpool.Pool, t tableSpec, teamID uuid.UUID, transform rowTransform) (copied, skipped int64, err error) {
	selectQ := fmt.Sprintf(`SELECT to_jsonb(t) FROM %s t WHERE %s`, t.name, t.effectiveCopyScope())
	conflict, err := conflictClause(ctx, dst, t.name)
	if err != nil {
		return 0, 0, err
	}
	insertQ := fmt.Sprintf(
		`INSERT INTO %s SELECT * FROM jsonb_populate_recordset(NULL::%s, $1::jsonb) %s`,
		t.name, t.name, conflict)

	rows, err := src.Query(ctx, selectQ, teamID)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	var total int64
	batch := make([]json.RawMessage, 0, copyBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		payload, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		tag, err := dst.Exec(ctx, insertQ, payload)
		if err != nil {
			return err
		}
		copied += tag.RowsAffected()
		batch = batch[:0]
		return nil
	}

	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return copied, 0, err
		}
		if transform != nil {
			raw, err = transformRow(raw, transform)
			if err != nil {
				return copied, 0, err
			}
		}
		batch = append(batch, json.RawMessage(raw))
		total++
		if len(batch) >= copyBatchSize {
			if err := flush(); err != nil {
				return copied, 0, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return copied, 0, err
	}
	if err := flush(); err != nil {
		return copied, 0, err
	}
	return copied, total - copied, nil
}

// transformRow decodes a row's jsonb, applies the transform, and re-encodes.
// UseNumber keeps bigint/numeric values as exact decimal strings — float64
// round-tripping would corrupt them.
func transformRow(raw []byte, transform rowTransform) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	row := map[string]any{}
	if err := dec.Decode(&row); err != nil {
		return nil, err
	}
	if err := transform(row); err != nil {
		return nil, err
	}
	return json.Marshal(row)
}

// relinkSnapshots restores sandbox.snapshot_id in the dest from the source's
// values, after snapshot rows exist. Idempotent: IS DISTINCT FROM makes a
// re-run a no-op.
func relinkSnapshots(ctx context.Context, src, dst *pgxpool.Pool, teamID uuid.UUID) (int64, error) {
	rows, err := src.Query(ctx,
		`SELECT id, snapshot_id FROM sandbox WHERE team_id = $1 AND snapshot_id IS NOT NULL`, teamID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type pair struct{ sandboxID, snapshotID uuid.UUID }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.sandboxID, &p.snapshotID); err != nil {
			return 0, err
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var relinked int64
	b := &pgx.Batch{}
	for _, p := range pairs {
		b.Queue(`UPDATE sandbox SET snapshot_id = $2 WHERE id = $1 AND snapshot_id IS DISTINCT FROM $2`,
			p.sandboxID, p.snapshotID)
	}
	br := dst.SendBatch(ctx, b)
	defer br.Close()
	for range pairs {
		tag, err := br.Exec()
		if err != nil {
			return relinked, err
		}
		relinked += tag.RowsAffected()
	}
	return relinked, br.Close()
}

// ---------------------------------------------------------------------------
// validate

func runValidate(ctx context.Context, src, dst *pgxpool.Pool, cfg config) error {
	mismatches, err := validateTeam(ctx, src, dst, cfg)
	if err != nil {
		return err
	}
	if err := reportArtifactDirs(ctx, src, cfg); err != nil {
		return err
	}
	if len(mismatches) > 0 {
		for _, m := range mismatches {
			log.Error().Msg("validate: MISMATCH — " + m)
		}
		return fmt.Errorf("validation failed: %d mismatch(es):\n  %s",
			len(mismatches), strings.Join(mismatches, "\n  "))
	}
	log.Info().Msg("validate: source and dest agree")
	return nil
}

// validateTeam runs every read-only parity check and returns the list of
// mismatches (empty = pass). Query errors are returned as err.
func validateTeam(ctx context.Context, src, dst *pgxpool.Pool, cfg config) ([]string, error) {
	var mismatches []string
	teamID := cfg.teamID

	// 1. Per-table row-count parity over the team's scope.
	for _, t := range migratedTables {
		if validationExemptTables[t.name] {
			continue // self-expiring advisory rows; see validationExemptTables.
		}
		q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s`, t.name, t.effectiveCopyScope())
		var srcN, dstN int64
		if err := src.QueryRow(ctx, q, teamID).Scan(&srcN); err != nil {
			return nil, fmt.Errorf("count source %s: %w", t.name, err)
		}
		if err := dst.QueryRow(ctx, q, teamID).Scan(&dstN); err != nil {
			return nil, fmt.Errorf("count dest %s: %w", t.name, err)
		}
		if srcN != dstN {
			mismatches = append(mismatches, fmt.Sprintf("%s: source=%d dest=%d rows", t.name, srcN, dstN))
		} else {
			log.Info().Str("table", t.name).Int64("rows", srcN).Msg("validate: count parity")
		}
	}

	// 1b. Per-row content checksums, transform-aware. Counts can match while
	// a source row changed after the copy (background writers run through
	// the freeze); decommission must be gated on content equality.
	transforms, err := buildTransforms(ctx, src, dst, cfg)
	if err != nil {
		return nil, err
	}
	for _, t := range migratedTables {
		if insertOnlyTables[t.name] || validationExemptTables[t.name] {
			continue // see insertOnlyTables / validationExemptTables.
		}
		tf := transforms[t.name]
		if t.name == "sandbox" {
			copyTf := tf
			// The copy nulls snapshot_id and relinks afterwards; a settled
			// dest row carries the source's value, so validation keeps it.
			tf = func(row map[string]any) error {
				keep := row["snapshot_id"]
				if err := copyTf(row); err != nil {
					return err
				}
				row["snapshot_id"] = keep
				return nil
			}
		}
		srcSums, err := rowChecksums(ctx, src, t, teamID, tf)
		if err != nil {
			return nil, err
		}
		dstSums, err := rowChecksums(ctx, dst, t, teamID, nil)
		if err != nil {
			return nil, err
		}
		if srcOnly, dstOnly := diffChecksums(srcSums, dstSums); srcOnly+dstOnly > 0 {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: content drift — %d source row(s) and %d dest row(s) without an equal counterpart (source changed after copy? re-run copy)",
				t.name, srcOnly, dstOnly))
		} else {
			log.Info().Str("table", t.name).Msg("validate: content parity")
		}
	}

	// 2. Billing sums. Compared as text — numeric must round-trip exactly.
	billingSums := []struct{ name, query string }{
		{"team_billing_usage_hourly sums", `SELECT COALESCE(SUM(vcpu_seconds), 0)::text || '|' ||
			COALESCE(SUM(memory_mib_seconds), 0)::text || '|' ||
			COALESCE(SUM(storage_mib_seconds), 0)::text
			FROM team_billing_usage_hourly WHERE team_id = $1`},
		{"team_billing_usage sums", `SELECT COALESCE(SUM(vcpu_seconds), 0)::text || '|' ||
			COALESCE(SUM(memory_mib_seconds), 0)::text || '|' ||
			COALESCE(SUM(storage_mib_seconds), 0)::text
			FROM team_billing_usage WHERE team_id = $1`},
		{"team_credit_grant sums", `SELECT COALESCE(SUM(amount_usd), 0)::text || '|' ||
			COALESCE(SUM(remaining_usd), 0)::text
			FROM team_credit_grant WHERE team_id = $1`},
	}
	for _, bs := range billingSums {
		var srcV, dstV string
		if err := src.QueryRow(ctx, bs.query, teamID).Scan(&srcV); err != nil {
			return nil, fmt.Errorf("source %s: %w", bs.name, err)
		}
		if err := dst.QueryRow(ctx, bs.query, teamID).Scan(&dstV); err != nil {
			return nil, fmt.Errorf("dest %s: %w", bs.name, err)
		}
		if srcV != dstV {
			mismatches = append(mismatches, fmt.Sprintf("%s: source=%s dest=%s", bs.name, srcV, dstV))
		}
	}

	// 3. Every live paused sandbox in the dest must carry its artifact paths;
	// resume depends on them.
	rows, err := dst.Query(ctx, `
		SELECT id FROM sandbox
		WHERE team_id = $1 AND destroyed_at IS NULL AND status = 'paused'
		  AND (snapshot_path IS NULL OR mem_path IS NULL OR base_path IS NULL OR delta_path IS NULL)`, teamID)
	if err != nil {
		return nil, fmt.Errorf("check dest sandbox artifact paths: %w", err)
	}
	missing, err := collectStrings(rows)
	if err != nil {
		return nil, err
	}
	for _, id := range missing {
		mismatches = append(mismatches, fmt.Sprintf("dest sandbox %s: paused but missing artifact path column(s)", id))
	}

	// 4. Every member profile must exist in the dest.
	rows, err = src.Query(ctx, `
		SELECT profile_id::text FROM team_member WHERE team_id = $1
		UNION SELECT user_id::text FROM team_memberships WHERE team_id = $1`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list source members: %w", err)
	}
	members, err := collectStrings(rows)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		var exists bool
		if err := dst.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM profile WHERE id = $1)`, m).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check dest profile %s: %w", m, err)
		}
		if !exists {
			mismatches = append(mismatches, fmt.Sprintf("member profile %s missing in dest", m))
		}
	}

	// 5. Role assignments must resolve to the same (user, role name, active)
	// set on both sides — this is what proves the by-name remap worked.
	const assignmentQ = `
		SELECT ura.user_id::text || '|' || r.name || '|' || (ura.revoked_at IS NULL)::text
		FROM user_role_assignments ura JOIN roles r ON r.id = ura.role_id
		WHERE ura.team_id = $1 ORDER BY 1`
	srcRows, err := src.Query(ctx, assignmentQ, teamID)
	if err != nil {
		return nil, fmt.Errorf("source role assignments: %w", err)
	}
	srcAssign, err := collectStrings(srcRows)
	if err != nil {
		return nil, err
	}
	dstRows, err := dst.Query(ctx, assignmentQ, teamID)
	if err != nil {
		return nil, fmt.Errorf("dest role assignments: %w", err)
	}
	dstAssign, err := collectStrings(dstRows)
	if err != nil {
		return nil, err
	}
	if strings.Join(srcAssign, "\n") != strings.Join(dstAssign, "\n") {
		mismatches = append(mismatches, fmt.Sprintf(
			"role assignments differ (source=%d dest=%d):\n  source: %v\n  dest:   %v",
			len(srcAssign), len(dstAssign), srcAssign, dstAssign))
	}

	// 6. The sandbox↔snapshot relink must reproduce the source's pairs.
	const pairQ = `SELECT id::text || '|' || COALESCE(snapshot_id::text, '') FROM sandbox WHERE team_id = $1 ORDER BY 1`
	srcRows, err = src.Query(ctx, pairQ, teamID)
	if err != nil {
		return nil, fmt.Errorf("source snapshot pairs: %w", err)
	}
	srcPairs, err := collectStrings(srcRows)
	if err != nil {
		return nil, err
	}
	dstRows, err = dst.Query(ctx, pairQ, teamID)
	if err != nil {
		return nil, fmt.Errorf("dest snapshot pairs: %w", err)
	}
	dstPairs, err := collectStrings(dstRows)
	if err != nil {
		return nil, err
	}
	if strings.Join(srcPairs, "\n") != strings.Join(dstPairs, "\n") {
		mismatches = append(mismatches, "sandbox→snapshot links differ between source and dest")
	}

	// 7. When the dest host is known, every dest sandbox must point at it.
	if cfg.destHostID != "" {
		rows, err := dst.Query(ctx,
			`SELECT id::text FROM sandbox WHERE team_id = $1 AND host_id <> $2`, teamID, cfg.destHostID)
		if err != nil {
			return nil, fmt.Errorf("check dest sandbox hosts: %w", err)
		}
		wrongHost, err := collectStrings(rows)
		if err != nil {
			return nil, err
		}
		for _, id := range wrongHost {
			mismatches = append(mismatches, fmt.Sprintf("dest sandbox %s not on host %q", id, cfg.destHostID))
		}
	}

	return mismatches, nil
}

func collectStrings(rows pgx.Rows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// decommission

func runDecommission(ctx context.Context, src, dst *pgxpool.Pool, cfg config, teamName string) error {
	if cfg.confirmTeamName != teamName {
		return fmt.Errorf("--confirm-team-name %q does not match team name %q; refusing to delete", cfg.confirmTeamName, teamName)
	}

	// Re-check quiescence immediately before deleting: a sandbox resumed or
	// a build started after the copy would survive validate (row-count
	// parity doesn't see a status flip), and deleting its rows would pull
	// the DB out from under a running VM.
	blockers, err := activeSandboxes(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	if len(blockers) > 0 {
		return fmt.Errorf("aborting decommission: %d sandbox(es) no longer quiescent:\n  %s",
			len(blockers), strings.Join(blockers, "\n  "))
	}
	builds, err := activeBuilds(ctx, src, cfg.teamID)
	if err != nil {
		return err
	}
	if len(builds) > 0 {
		return fmt.Errorf("aborting decommission: %d template build(s) in flight:\n  %s",
			len(builds), strings.Join(builds, "\n  "))
	}

	// A validate pass is a precondition in the same invocation — never
	// delete a source we haven't just proven the dest matches.
	log.Info().Msg("decommission: running validate first")
	mismatches, err := validateTeam(ctx, src, dst, cfg)
	if err != nil {
		return err
	}
	if len(mismatches) > 0 {
		for _, m := range mismatches {
			log.Error().Msg("decommission: MISMATCH — " + m)
		}
		return fmt.Errorf("aborting decommission: validate found %d mismatch(es); source not touched", len(mismatches))
	}

	// Validate takes real time; a sandbox resume or build dispatch could
	// slip in behind the checks above. Re-run both blockers immediately
	// before the deletes — with the team's keys revoked (a copy
	// precondition) only internal actors can still race this window, and
	// they lose by one statement rather than by the whole validate pass.
	if blockers, err := activeSandboxes(ctx, src, cfg.teamID); err != nil {
		return err
	} else if len(blockers) > 0 {
		return fmt.Errorf("aborting decommission: sandbox became non-quiescent during validate:\n  %s", strings.Join(blockers, "\n  "))
	}
	if builds, err := activeBuilds(ctx, src, cfg.teamID); err != nil {
		return err
	} else if len(builds) > 0 {
		return fmt.Errorf("aborting decommission: template build started during validate:\n  %s", strings.Join(builds, "\n  "))
	}

	// One transaction: the source either loses the whole team or nothing.
	tx, err := src.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// Lock the team's rows first: the auto-delete worker claims paused
	// sandboxes past their deadline with an UPDATE, which now blocks behind
	// these locks instead of racing the deletes (its claim matches zero
	// rows once we commit). activeSandboxes can't see that worker — it
	// flips rows straight to destroyed — so locking is the only guard that
	// closes the window rather than shrinking it.
	if _, err := tx.Exec(ctx, `SELECT id FROM team WHERE id = $1 FOR UPDATE`, cfg.teamID); err != nil {
		return fmt.Errorf("lock team: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM sandbox WHERE team_id = $1 FOR UPDATE`, cfg.teamID); err != nil {
		return fmt.Errorf("lock sandboxes: %w", err)
	}
	// Secret attach/detach paths don't touch the sandbox row — they
	// serialize on the app's per-sandbox advisory lock instead
	// (LockSandboxForSecretWrites). Take the identical lock for every
	// sandbox so a detach on a paused sandbox blocks behind this
	// transaction rather than racing the deletes.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(id::text)::bigint) FROM sandbox WHERE team_id = $1`, cfg.teamID); err != nil {
		return fmt.Errorf("advisory-lock sandboxes: %w", err)
	}
	// Build admission serializes on the app's per-TEAM advisory lock
	// (CountInFlightBuildsForTeam's caller contract) — take it so a
	// CreateTemplateBuild that would slip a pending row past the earlier
	// check blocks behind this transaction, then recheck under the lock.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, cfg.teamID.String()); err != nil {
		return fmt.Errorf("advisory-lock team builds: %w", err)
	}
	if builds, err := activeBuilds(ctx, tx, cfg.teamID); err != nil {
		return err
	} else if len(builds) > 0 {
		return fmt.Errorf("aborting decommission: template build slipped in before the locks:\n  %s", strings.Join(builds, "\n  "))
	}
	// The source rows die below, so capture the rollup-flag state now and
	// restore it into the dest after the deletes commit — decommissioned
	// migrations must not depend on a later release-rollups run that would
	// find no source to read.
	var srcRollupEnabled *bool
	if err := tx.QueryRow(ctx, `
		SELECT enabled FROM team_feature_flag WHERE team_id = $1 AND key = 'billing_hourly_rollups'`,
		cfg.teamID).Scan(&srcRollupEnabled); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("capture source rollup flag: %w", err)
	}
	// Under the locks, re-verify that sandbox rows and secret bindings
	// still match the dest — catches anything (auto-delete, secret detach)
	// that mutated them between validate and the locks landing.
	drift, err := contentDriftUnderLock(ctx, tx, dst, cfg)
	if err != nil {
		return err
	}
	if drift != "" {
		return fmt.Errorf("aborting decommission: %s changed after validate (auto-delete, resume, or secret detach raced the window) — re-run copy and validate", drift)
	}

	// Async writers (logSandboxActivity fires-and-forgets; revocation rows
	// arrive from workers) can land rows after validate without holding any
	// lock we can take, and locking the shared tables would block the whole
	// platform. Instead of aborting on stragglers, sweep them: re-copy
	// those tables from this transaction's view into the dest, so whatever
	// the deletes below can see has already been preserved. A row that
	// commits mid-transaction survives our DELETE's snapshot and then
	// fails the team-row delete's FK check — the transaction rolls back
	// and a re-run sweeps it too.
	// Rollup workers on the SOURCE keep running too — a tick after
	// validate can upsert jobs, advance the backfill cursor, or rewrite
	// hourly rows from the already-copied intervals, none of which touch
	// the locked sandbox/secret rows. Same remedy as the async writers:
	// sweep them into dest under this transaction before deleting.
	for _, name := range []string{
		"activity", "sandbox_revocation", "revoked_proxy_token",
		"billing_rollup_job", "billing_rollup_team_backfill_state", "team_billing_usage_hourly",
	} {
		spec, ok := tableByName(name)
		if !ok {
			return fmt.Errorf("sweep: unknown table %s", name)
		}
		copied, _, err := copyTable(ctx, tx, dst, spec, cfg.teamID, nil)
		if err != nil {
			return fmt.Errorf("final sweep of %s: %w", name, err)
		}
		if copied > 0 {
			log.Info().Str("table", name).Int64("swept", copied).Msg("decommission: straggler rows copied to dest before delete")
		}
	}

	// Break the sandbox↔snapshot cycle so snapshots can go before sandboxes.
	if _, err := tx.Exec(ctx, `UPDATE sandbox SET snapshot_id = NULL WHERE team_id = $1`, cfg.teamID); err != nil {
		return fmt.Errorf("null sandbox.snapshot_id: %w", err)
	}

	var total int64
	for i := len(migratedTables) - 1; i >= 0; i-- {
		t := migratedTables[i]
		if t.name == "profile" {
			// Profiles are global (multi-team, shared with Auth); they stay.
			continue
		}
		tag, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE %s`, t.name, t.scope), cfg.teamID)
		if err != nil {
			return fmt.Errorf("delete from %s: %w", t.name, err)
		}
		total += tag.RowsAffected()
		log.Info().Str("table", t.name).Int64("deleted", tag.RowsAffected()).Msg("decommission")
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	if err := restoreRollupFlag(ctx, dst, cfg.teamID, srcRollupEnabled); err != nil {
		return fmt.Errorf("source deleted but dest rollup flag not restored — apply release-rollups semantics by hand: %w", err)
	}
	log.Info().Msg("decommission: dest rollup hold released to the source's pre-delete state")

	log.Info().Int64("deleted", total).Msg("decommission: source rows removed (profiles and append-only audit tables retained)")
	return nil
}
