// Command migrate-team moves one team's complete dataset from the primary
// cell's Postgres to another cell's Postgres, for use inside a maintenance
// window where every one of the team's sandboxes is paused or destroyed.
//
// Phases (--phase, default plan):
//
//	plan          read-only. Prints per-table row counts for the team's scope,
//	              the artifact directory list the runbook's GCS copy step
//	              consumes (--paths-out), and any blockers (sandboxes still
//	              active). Sizes are deliberately not reported: size_bytes
//	              columns are not reliably populated (snapshot.size_bytes is
//	              all zeros in prod), so the runbook sizes the real files
//	              rather than trusting DB claims about them.
//	copy          reads team-scoped rows from --source-db and idempotently
//	              upserts them into --dest-db in FK dependency order. Every
//	              UUID is preserved; sandbox.host_id is remapped to
//	              --dest-host-id; user_role_assignments.role_id is remapped by
//	              role NAME (role ids are migration-seeded per cell and
//	              differ); team.home_region becomes --dest-region on insert.
//	              Refuses to run while any sandbox is active/starting/resuming.
//	              Safe to re-run: a second copy inserts zero new rows.
//	validate      read-only against both DBs. Per-table row-count parity,
//	              billing usage sums, artifact path completeness, member
//	              profile presence, and role-assignment resolution. Exits
//	              non-zero with a report on any mismatch.
//	detach        deletes ONLY the team's membership rows from the SOURCE —
//	              user_role_assignments (team-scoped), team_memberships, and
//	              team_member — in one transaction, after running validate
//	              internally. With the RBAC chain gone no console or API path
//	              reaches the source copy, so the team has exactly one live
//	              home; everything else stays as a cold fallback for the soak
//	              period. Requires --confirm-team-name. Reversible: re-insert
//	              the membership rows, or run the tool in reverse.
//	purge         deletes the team's rows from the SOURCE in reverse FK order,
//	              run after the post-detach soak. Requires --confirm-team-name
//	              to match the team's exact name, and runs validate internally
//	              first — any mismatch aborts. (--phase decommission is a
//	              deprecated alias.)
//
// Deliberately out of scope:
//   - Artifact files on hosts (template rootfs/snapshots, sandbox snapshots)
//     are copied via GCS by the runbook; plan/validate print the directory
//     list that step consumes.
//   - proxy_audit, net_flow, audit_logs, and reconciler_log stay in the
//     source cell: they are append-only audit history (audit_logs even
//     blocks deletes with a trigger) and are host/cell-scoped.
//
// The DB URLs must belong to a role that bypasses RLS (service role /
// postgres), like every other control-plane process.
package main

import (
	"context"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	var (
		teamIDRaw       string
		cfg             config
		confirmTeamName string
	)
	flag.StringVar(&teamIDRaw, "team", "", "uuid of the team to migrate (required)")
	flag.StringVar(&cfg.sourceURL, "source-db", os.Getenv("SOURCE_DATABASE_URL"), "source cell Postgres URL (defaults to SOURCE_DATABASE_URL)")
	flag.StringVar(&cfg.destURL, "dest-db", os.Getenv("DEST_DATABASE_URL"), "dest cell Postgres URL (defaults to DEST_DATABASE_URL)")
	flag.StringVar(&cfg.destHostID, "dest-host-id", "", "host row id in the dest cell (e.g. usw2); required for copy")
	flag.StringVar(&cfg.destRegion, "dest-region", "", "dest region token (e.g. usw); required for copy")
	flag.StringVar(&cfg.phase, "phase", phasePlan, "plan | copy | validate | detach | purge | release-rollups (decommission is a deprecated alias for purge)")
	flag.StringVar(&confirmTeamName, "confirm-team-name", "", "exact team name; required for detach and purge")
	flag.StringVar(&cfg.pathsOut, "paths-out", "", "file to write the artifact directory list to, one dir per line (plan/validate)")
	flag.Parse()

	if teamIDRaw == "" {
		log.Fatal().Msg("--team is required")
	}
	teamID, err := uuid.Parse(teamIDRaw)
	if err != nil {
		log.Fatal().Err(err).Msg("--team is not a valid UUID")
	}
	cfg.teamID = teamID
	cfg.confirmTeamName = confirmTeamName

	if cfg.phase == phaseDecommission {
		log.Warn().Msg("--phase decommission is deprecated; running purge (the membership-only cutover step is --phase detach)")
		cfg.phase = phasePurge
	}

	if cfg.sourceURL == "" {
		log.Fatal().Msg("--source-db (or SOURCE_DATABASE_URL) is required")
	}
	switch cfg.phase {
	case phasePlan:
		// Read-only; dest is optional.
	case phaseCopy, phaseValidate, phaseDetach, phasePurge, phaseReleaseRollups:
		if cfg.destURL == "" {
			log.Fatal().Msg("--dest-db (or DEST_DATABASE_URL) is required for " + cfg.phase)
		}
	default:
		log.Fatal().Str("phase", cfg.phase).Msg("unknown phase; want plan | copy | validate | detach | purge | release-rollups")
	}
	// copy rewrites rows with these values; validate, detach, and purge apply
	// the same transforms when checksumming the source, so running them
	// without the flags would compare against empty rewrites and report
	// false drift on every team and sandbox row.
	if cfg.phase != phasePlan && cfg.phase != phaseReleaseRollups && (cfg.destHostID == "" || cfg.destRegion == "") {
		log.Fatal().Msg("--dest-host-id and --dest-region are required for " + cfg.phase)
	}
	if (cfg.phase == phaseDetach || cfg.phase == phasePurge) && cfg.confirmTeamName == "" {
		log.Fatal().Msg("--confirm-team-name is required for " + cfg.phase)
	}

	if err := run(context.Background(), cfg); err != nil {
		// Redact DSNs — pgx errors can echo the URL (password included).
		msg := redactDSN(err.Error(), cfg.sourceURL)
		msg = redactDSN(msg, cfg.destURL)
		log.Fatal().Msg(msg)
	}
}

// redactDSN strips a raw database URL from an error string.
func redactDSN(msg, dsn string) string {
	if dsn == "" {
		return msg
	}
	return strings.ReplaceAll(msg, dsn, "<dsn>")
}
