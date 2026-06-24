//go:build integration

package integration

import (
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

const allowTestSchemaResetEnv = "ALLOW_TEST_SCHEMA_RESET"

func init() {
	if err := requireSafeSchemaResetTarget(os.Getenv("DATABASE_URL"), os.Getenv(allowTestSchemaResetEnv)); err != nil {
		fmt.Fprintf(os.Stderr, "integration test database safety check failed: %v\n", err)
		os.Exit(1)
	}
}

func requireSafeSchemaResetTarget(dbURL, allowReset string) error {
	if allowReset == "1" {
		return nil
	}
	if dbURL == "" {
		return nil
	}

	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return fmt.Errorf("parse DATABASE_URL: %w", err)
	}

	dbName := cfg.ConnConfig.Database
	if dbName == "sandbox_test" || strings.HasSuffix(dbName, "_test") {
		return nil
	}

	return fmt.Errorf("refusing to reset schema for database %q; use a *_test database or set %s=1", dbName, allowTestSchemaResetEnv)
}
