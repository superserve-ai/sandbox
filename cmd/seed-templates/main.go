// Command seed-templates inserts curated public templates into the template
// table under the system team. Reads every *.json file under seeds/templates/
// (path configurable via --dir) and upserts on (team_id, alias).
//
// Idempotent: existing rows are updated in place (build_spec + resources),
// so iterating on a template's definition is a matter of editing the JSON
// and re-running. Does NOT kick off builds — that's the operator's call
// after seeding (so the SDK and docs can reference alias without racing a
// long build).
//
// Intended to run once at bootstrap and whenever the curated spec list
// changes. Not scheduled.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	var dir string
	flag.StringVar(&dir, "dir", "seeds/templates", "directory containing template JSON files")
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect to database")
	}
	defer pool.Close()

	// Verify the system team row actually exists. Saves debugging a 404
	// on every sandbox create if the operator set the wrong UUID.
	if _, err := db.New(pool).GetTeam(ctx, systemTeamID); err != nil {
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

	for _, s := range specs {
		if err := upsertTemplate(ctx, pool, systemTeamID, s); err != nil {
			log.Error().Err(err).Str("alias", s.Alias).Msg("upsert failed")
			continue
		}
		log.Info().Str("alias", s.Alias).Msg("template seeded")
	}
}

// seedSpec mirrors createTemplateRequest from internal/api/handlers_template.go
// at wire level. Decoupled copy so this tool doesn't drag the entire api
// package into the seed binary.
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

// upsertTemplate inserts or updates a seed template under the system team.
// Uses a raw SQL statement rather than going through sqlc because sqlc's
// generated CreateTemplate doesn't support an ON CONFLICT clause and we
// want this tool to be safely re-runnable.
//
// On conflict we update resources + build_spec and null-out any prior
// error_message. Status is NOT reset to 'pending' — that would invalidate
// existing builds; operators can trigger a rebuild via POST /builds.
func upsertTemplate(ctx context.Context, pool *pgxpool.Pool, teamID uuid.UUID, s seedSpec) error {
	const q = `
		INSERT INTO template (team_id, alias, build_spec, vcpu, memory_mib, disk_mib)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (team_id, alias) DO UPDATE
		SET build_spec = EXCLUDED.build_spec,
		    vcpu = EXCLUDED.vcpu,
		    memory_mib = EXCLUDED.memory_mib,
		    disk_mib = EXCLUDED.disk_mib,
		    error_message = NULL,
		    updated_at = now();
	`
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
	_, err := pool.Exec(ctx, q, teamID, s.Alias, []byte(s.BuildSpec), vcpu, memMib, diskMib)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("unexpected 0-row response from upsert")
		}
		return err
	}
	return nil
}

