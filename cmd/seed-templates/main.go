// Command seed-templates inserts curated public templates into the template
// table under the system team, enqueues their first build, and (by default)
// blocks until every build reaches a terminal status.
//
// Flow per run:
//   1. Upsert each JSON under seeds/templates/ into the template table
//      owned by SYSTEM_TEAM_ID (idempotent on alias).
//   2. Decide whether to enqueue a build for each template:
//        - Template row just inserted → enqueue.
//        - Previous build failed / never ran → enqueue.
//        - Spec hash differs from the last successful build → enqueue.
//        - --force-rebuild → always enqueue (for "host was replaced").
//        - Otherwise → skip.
//   3. Poll until every enqueued build is ready / failed / cancelled.
//      Exit 0 when all succeed, non-zero if any fail.
//
// Intended to run at platform bootstrap and whenever the curated spec
// list changes. Not scheduled in CI (invoked via a workflow_dispatch-able
// action instead).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/builder"
	"github.com/superserve-ai/sandbox/internal/db"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	var (
		dir          string
		forceRebuild bool
		waitDeadline time.Duration
		noWait       bool
	)
	flag.StringVar(&dir, "dir", "seeds/templates", "directory containing template JSON files")
	flag.BoolVar(&forceRebuild, "force-rebuild", false, "re-enqueue a build even when the template is already ready; use after host replacement")
	flag.DurationVar(&waitDeadline, "wait", 30*time.Minute, "max time to wait for all builds to reach terminal status")
	flag.BoolVar(&noWait, "no-wait", false, "enqueue builds but don't block until they finish")
	flag.Parse()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal().Msg("DATABASE_URL is required")
	}
	systemTeamIDRaw := os.Getenv("SYSTEM_TEAM_ID")
	if systemTeamIDRaw == "" {
		log.Fatal().Msg("SYSTEM_TEAM_ID is required; set it to the uuid of the team that owns curated templates")
	}
	systemTeamID, err := uuid.Parse(systemTeamIDRaw)
	if err != nil {
		log.Fatal().Err(err).Msg("SYSTEM_TEAM_ID is not a valid UUID")
	}

	// Budget = expected wait + slack for seeding + poll intervals.
	ctx, cancel := context.WithTimeout(context.Background(), waitDeadline+2*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect to database")
	}
	defer pool.Close()

	q := db.New(pool)

	if _, err := q.GetTeam(ctx, systemTeamID); err != nil {
		log.Fatal().Err(err).Str("system_team_id", systemTeamID.String()).Msg("system team not found; create it first")
	}

	specs, err := loadSpecs(dir)
	if err != nil {
		log.Fatal().Err(err).Str("dir", dir).Msg("load seed files")
	}
	if len(specs) == 0 {
		log.Warn().Str("dir", dir).Msg("no seed files found")
		return
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Alias < specs[j].Alias })

	var queued []uuid.UUID
	var seedFailures int
	for _, s := range specs {
		buildID, queuedIt, err := seedOne(ctx, pool, systemTeamID, s, forceRebuild)
		if err != nil {
			seedFailures++
			log.Error().Err(err).Str("alias", s.Alias).Msg("seed failed")
			continue
		}
		if !queuedIt {
			log.Info().Str("alias", s.Alias).Msg("already up-to-date; nothing to build (pass --force-rebuild to override)")
			continue
		}
		queued = append(queued, buildID)
		log.Info().Str("alias", s.Alias).Str("build_id", buildID.String()).Msg("build queued")
	}

	if noWait || len(queued) == 0 {
		if seedFailures > 0 {
			os.Exit(1)
		}
		return
	}

	log.Info().Int("count", len(queued)).Dur("timeout", waitDeadline).Msg("waiting for builds to finish")
	waitCtx, waitCancel := context.WithTimeout(ctx, waitDeadline)
	defer waitCancel()
	buildFailures := waitForBuilds(waitCtx, pool, queued)

	if seedFailures > 0 || buildFailures > 0 {
		log.Error().Int("seed_failures", seedFailures).Int("build_failures", buildFailures).Msg("completed with failures")
		os.Exit(1)
	}
	log.Info().Int("count", len(queued)).Msg("all builds ready")
}

// seedSpec mirrors the wire shape users POST to /templates. Kept local so
// this binary doesn't pull in the HTTP handler package.
type seedSpec struct {
	Alias     string          `json:"alias"`
	Vcpu      *int32          `json:"vcpu,omitempty"`
	MemoryMib *int32          `json:"memory_mib,omitempty"`
	DiskMib   *int32          `json:"disk_mib,omitempty"`
	BuildSpec json.RawMessage `json:"build_spec"`
}

func loadSpecs(dir string) ([]seedSpec, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []seedSpec
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var s seedSpec
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if s.Alias == "" {
			return nil, fmt.Errorf("%s: alias is required", path)
		}
		if len(s.BuildSpec) == 0 {
			return nil, fmt.Errorf("%s: build_spec is required", path)
		}
		out = append(out, s)
	}
	return out, nil
}

// seedOne upserts one template and, if appropriate, enqueues a build.
// Returns (buildID, queued, err) — queued=false means "template is already
// up-to-date and --force-rebuild wasn't set."
func seedOne(ctx context.Context, pool *pgxpool.Pool, teamID uuid.UUID, s seedSpec, forceRebuild bool) (uuid.UUID, bool, error) {
	vcpu, memMib, diskMib := resolvedResources(s)

	specHash, err := canonicalSpecHash(s.BuildSpec)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("hash build_spec: %w", err)
	}

	// Upsert and capture the resulting status so we can decide whether to
	// enqueue a build in one follow-up query.
	const upsertQ = `
		INSERT INTO template (team_id, alias, build_spec, vcpu, memory_mib, disk_mib)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (team_id, alias) DO UPDATE
		SET build_spec = EXCLUDED.build_spec,
		    vcpu = EXCLUDED.vcpu,
		    memory_mib = EXCLUDED.memory_mib,
		    disk_mib = EXCLUDED.disk_mib,
		    updated_at = now()
		RETURNING id, status;
	`
	var tplID uuid.UUID
	var tplStatus string
	if err := pool.QueryRow(ctx, upsertQ,
		teamID, s.Alias, []byte(s.BuildSpec), vcpu, memMib, diskMib,
	).Scan(&tplID, &tplStatus); err != nil {
		return uuid.Nil, false, fmt.Errorf("upsert template: %w", err)
	}

	// Decide whether to enqueue a build.
	needsBuild := forceRebuild || tplStatus != "ready"
	if !needsBuild {
		lastHash, err := latestReadyBuildHash(ctx, pool, tplID)
		if err != nil {
			return uuid.Nil, false, fmt.Errorf("read latest ready build: %w", err)
		}
		if lastHash != specHash {
			needsBuild = true
		}
	}
	if !needsBuild {
		return uuid.Nil, false, nil
	}

	// Insert the template_build row. If an in-flight build already exists
	// for this (template, hash), the unique partial index rejects with
	// 23505 — we then return that existing build's id so the wait loop
	// watches the right row.
	const insertBuildQ = `
		INSERT INTO template_build (template_id, team_id, build_spec_hash)
		VALUES ($1, $2, $3)
		RETURNING id;
	`
	var buildID uuid.UUID
	err = pool.QueryRow(ctx, insertBuildQ, tplID, teamID, specHash).Scan(&buildID)
	if err == nil {
		return buildID, true, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		const existingQ = `
			SELECT id FROM template_build
			WHERE template_id = $1 AND build_spec_hash = $2
			  AND status IN ('pending','building','snapshotting')
			ORDER BY created_at DESC LIMIT 1;
		`
		if scanErr := pool.QueryRow(ctx, existingQ, tplID, specHash).Scan(&buildID); scanErr == nil {
			return buildID, true, nil
		}
	}
	return uuid.Nil, false, fmt.Errorf("insert build: %w", err)
}

// latestReadyBuildHash returns the hash of the most recent successful
// build for this template, or "" when none exists.
func latestReadyBuildHash(ctx context.Context, pool *pgxpool.Pool, templateID uuid.UUID) (string, error) {
	const q = `
		SELECT build_spec_hash FROM template_build
		WHERE template_id = $1 AND status = 'ready'
		ORDER BY finalized_at DESC NULLS LAST LIMIT 1;
	`
	var hash string
	err := pool.QueryRow(ctx, q, templateID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return hash, err
}

// canonicalSpecHash matches the handler's internal hashing: unmarshal into
// builder.BuildSpec, re-marshal with encoding/json (field order = struct
// field order, map keys sorted), then sha256. The seeder and the handler
// must produce identical hashes for idempotency to work across both
// submission paths.
func canonicalSpecHash(raw []byte) (string, error) {
	var spec builder.BuildSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return "", err
	}
	reMarshaled, err := json.Marshal(&spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(reMarshaled)
	return hex.EncodeToString(sum[:]), nil
}

// waitForBuilds polls every tracked build until it hits a terminal state
// or the context fires. Returns the number of non-success terminal states.
func waitForBuilds(ctx context.Context, pool *pgxpool.Pool, ids []uuid.UUID) int {
	const tick = 5 * time.Second
	remaining := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		remaining[id] = struct{}{}
	}

	failures := 0
	for {
		if len(remaining) == 0 {
			return failures
		}
		for id := range remaining {
			status, errMsg, terminal, err := queryBuildStatus(ctx, pool, id)
			if err != nil {
				log.Warn().Err(err).Str("build_id", id.String()).Msg("poll build status")
				continue
			}
			if !terminal {
				continue
			}
			delete(remaining, id)
			switch status {
			case "ready":
				log.Info().Str("build_id", id.String()).Msg("build ready")
			default:
				failures++
				log.Error().Str("build_id", id.String()).Str("status", status).Str("error", errMsg).Msg("build finished in non-success state")
			}
		}

		if len(remaining) == 0 {
			return failures
		}
		select {
		case <-ctx.Done():
			log.Error().Int("still_running", len(remaining)).Msg("wait deadline exceeded; builds still in flight — check supervisor logs")
			return failures + len(remaining)
		case <-time.After(tick):
		}
	}
}

// queryBuildStatus fetches the current status + error message for a build.
// terminal=true when the status is in {ready, failed, cancelled}.
func queryBuildStatus(ctx context.Context, pool *pgxpool.Pool, buildID uuid.UUID) (string, string, bool, error) {
	const q = `SELECT status, COALESCE(error_message, '') FROM template_build WHERE id = $1;`
	var status, errMsg string
	if err := pool.QueryRow(ctx, q, buildID).Scan(&status, &errMsg); err != nil {
		return "", "", false, err
	}
	switch status {
	case "ready", "failed", "cancelled":
		return status, errMsg, true, nil
	default:
		return status, errMsg, false, nil
	}
}

func resolvedResources(s seedSpec) (int32, int32, int32) {
	vcpu := int32(1)
	if s.Vcpu != nil {
		vcpu = *s.Vcpu
	}
	memMib := int32(1024)
	if s.MemoryMib != nil {
		memMib = *s.MemoryMib
	}
	diskMib := int32(4096)
	if s.DiskMib != nil {
		diskMib = *s.DiskMib
	}
	return vcpu, memMib, diskMib
}
