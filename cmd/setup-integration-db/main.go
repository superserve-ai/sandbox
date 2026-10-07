//go:build integration

// setup-integration-db resets and seeds a disposable integration database.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/integrationdb"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL must identify a disposable integration database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to test database: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping test database: %w", err)
	}

	lockCtx, stopLockWait := context.WithTimeout(context.Background(), 5*time.Minute)
	defer stopLockWait()
	lockConn, err := pgx.Connect(lockCtx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to test database for schema lock: %w", err)
	}
	defer lockConn.Close(context.Background())
	if _, err := lockConn.Exec(lockCtx, `SELECT pg_advisory_lock($1)`, integrationdb.SchemaLockKey); err != nil {
		return fmt.Errorf("lock integration test database: %w", err)
	}

	setupCtx, stopSetup := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopSetup()
	if _, err := integrationdb.Reset(setupCtx, pool); err != nil {
		return err
	}
	if _, err := lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, integrationdb.SchemaLockKey); err != nil {
		return fmt.Errorf("unlock integration test database: %w", err)
	}
	return nil
}
