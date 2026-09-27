//go:build integration

package integration

import (
	"context"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var promotionCLIMigrations = []string{
	"20260925195213_promotion_redemption_limits.sql",
	"20260925195235_canonical_promotion_identity.sql",
	"20260925195248_canonical_stripe_promotion_fences.sql",
}

// The ordinary migration harness sends a whole file as one query, which gives
// LOCK TABLE an implicit transaction and conceals the deployment CLI failure.
func TestPromotionMigrationsSupabaseCLI(t *testing.T) {
	if os.Getenv("SUPABASE_CLI_REGRESSION") != "1" {
		t.Skip("set SUPABASE_CLI_REGRESSION=1 to exercise the deployment CLI")
	}
	cli, err := exec.LookPath("supabase")
	if err != nil {
		t.Fatal("SUPABASE_CLI_REGRESSION=1 requires the Supabase CLI on PATH")
	}
	migrationsDir, err := findMigrationsDir()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name          string
		migration     int
		noTransaction bool
	}{
		{name: "redemption missing transaction", migration: 0, noTransaction: true},
		{name: "canonical missing transaction", migration: 1, noTransaction: true},
		{name: "redemption rollback and retry", migration: 0},
		{name: "canonical rollback and retry", migration: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, dbURL := promotionCLIDatabase(t, migrationsDir)
			ctx := context.Background()
			actor, team := uuid.New(), uuid.New()
			seed := func(sql string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			seed(`INSERT INTO profile(id,email) VALUES($1,'migration@example.com')`, actor)
			seed(`INSERT INTO team(id,name) VALUES($1,'migration-team')`, team)
			seed(`INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'owner')`, team, actor)
			seed(`UPDATE team_credit_grant SET created_by=$2 WHERE team_id=$1 AND reason='signup trial credit'`, team, actor)
			seed(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_by)
				VALUES($1,5,5,'stripe promotional credit',$2)`, team, actor)
			seed(`INSERT INTO team_billing_account(team_id) VALUES($1) ON CONFLICT DO NOTHING`, team)

			project := t.TempDir()
			runCLI := func(args ...string) (string, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				cmd := exec.CommandContext(ctx, cli, append(args, "--workdir", project, "--yes")...)
				output, err := cmd.CombinedOutput()
				redacted := strings.ReplaceAll(string(output), dbURL, "<test database>")
				if password := pool.Config().ConnConfig.Password; password != "" {
					redacted = strings.ReplaceAll(redacted, password, "<redacted>")
				}
				return redacted, err
			}
			if output, err := runCLI("init"); err != nil {
				t.Fatalf("initialize temporary CLI project: %v\n%s", err, output)
			}
			projectMigrations := filepath.Join(project, "supabase", "migrations")
			if err := os.MkdirAll(projectMigrations, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range promotionCLIMigrations {
				data, err := os.ReadFile(filepath.Join(migrationsDir, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(projectMigrations, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(projectMigrations, promotionCLIMigrations[tc.migration])
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(original), "BEGIN;\n") || !strings.HasSuffix(string(original), "COMMIT;\n") {
				t.Fatal("migration must have an explicit transaction")
			}
			broken := strings.TrimSuffix(string(original), "COMMIT;\n")
			wantSQLState := "22012"
			if tc.noTransaction {
				broken = strings.Replace(broken, "BEGIN;\n", "", 1)
				wantSQLState = "25P01"
			} else {
				broken += "SELECT 1 / 0;\nCOMMIT;\n"
			}
			if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := runCLI("db", "push", "--db-url", dbURL)
			if err == nil || !strings.Contains(output, "SQLSTATE "+wantSQLState) {
				t.Fatalf("expected CLI SQLSTATE %s, got %v\n%s", wantSQLState, err, output)
			}
			assertPromotionCLIHistory(t, pool, tc.migration)
			var redemptionPresent, canonicalPresent, stripeBackfilled bool
			if err := pool.QueryRow(ctx, `SELECT
				to_regclass('public.user_signup_trial_claim') IS NOT NULL,
				to_regclass('public.promotion_identity_history') IS NOT NULL,
				stripe_activation_credit_granted_at IS NOT NULL
				FROM team_billing_account WHERE team_id=$1`, team).Scan(
				&redemptionPresent, &canonicalPresent, &stripeBackfilled); err != nil {
				t.Fatal(err)
			}
			if redemptionPresent != (tc.migration == 1) || canonicalPresent || stripeBackfilled != (tc.migration == 1) {
				t.Fatalf("failed migration committed schema/backfill: redemption=%t canonical=%t stripe=%t",
					redemptionPresent, canonicalPresent, stripeBackfilled)
			}

			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if output, err := runCLI("db", "push", "--db-url", dbURL); err != nil {
					t.Fatalf("fixed CLI push %d: %v\n%s", attempt+1, err, output)
				}
				assertPromotionCLIHistory(t, pool, len(promotionCLIMigrations))
				var enabled, signupClaimed, stripeClaimed, fencePresent bool
				var historicalClaims int
				if err := pool.QueryRow(ctx, `SELECT canonical_promotion_identity_enabled(),
					EXISTS(SELECT 1 FROM user_signup_trial_claim WHERE user_id=$1 AND team_id=$2),
					EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1
						AND signup_trial_team_id=$2 AND stripe_redemption_team_id=$2 AND stripe_redemption_at IS NOT NULL),
					(SELECT count(*) FROM promotion_identity_history WHERE user_id=$1 AND team_id=$2),
					to_regclass('public.stripe_promotion_migration_fence') IS NOT NULL`, actor, team).Scan(
					&enabled, &signupClaimed, &stripeClaimed, &historicalClaims, &fencePresent); err != nil {
					t.Fatal(err)
				}
				if enabled || !signupClaimed || !stripeClaimed || historicalClaims != 2 || !fencePresent {
					t.Fatalf("push %d: enabled=%t signup=%t stripe=%t history=%d fence=%t",
						attempt+1, enabled, signupClaimed, stripeClaimed, historicalClaims, fencePresent)
				}
			}
		})
	}
}

func promotionCLIDatabase(t *testing.T, migrationsDir string) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	config := testPool.Config()
	host := config.ConnConfig.Host
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		t.Fatal("CLI migration regression requires a local administrative test database")
	}
	name := "promotion_cli_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := testPool.Exec(ctx, "CREATE DATABASE "+identifier); err != nil {
		t.Fatalf("create isolated migration database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := testPool.Exec(ctx, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
	})
	config.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	// Baseline files use the ordinary harness; only the affected chain is handed
	// to the CLI so unrelated historical files need no synthetic CLI history.
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") || entry.Name() >= promotionCLIMigrations[0] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(migrationsDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			t.Fatalf("apply baseline %s: %v", entry.Name(), err)
		}
	}
	conn := config.ConnConfig
	dbURL := url.URL{
		Scheme: "postgres", User: url.UserPassword(conn.User, conn.Password),
		Host: net.JoinHostPort(host, strconv.Itoa(int(conn.Port))), Path: "/" + name,
		RawQuery: "sslmode=disable",
	}
	return pool, dbURL.String()
}

func assertPromotionCLIHistory(t *testing.T, pool *pgxpool.Pool, count int) {
	t.Helper()
	var got []string
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(array_agg(version ORDER BY version),'{}')
		FROM supabase_migrations.schema_migrations`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	want := make([]string, count)
	for i := range want {
		want[i] = strings.SplitN(promotionCLIMigrations[i], "_", 2)[0]
	}
	if !slices.Equal(got, want) {
		t.Fatalf("CLI migration history = %v, want %v", got, want)
	}
}
