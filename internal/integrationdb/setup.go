//go:build integration

// Package integrationdb initializes disposable databases for integration tests.
package integrationdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/preview"
	"github.com/superserve-ai/sandbox/internal/promotiontest"
)

const DefaultHostID = "default"

// SchemaLockKey serializes setup with integration suites using the same database.
const SchemaLockKey int64 = 0x5355504552534552

// Reset drops the test schemas, applies all migrations, and seeds the shared
// fixtures. The caller must hold SchemaLockKey for the duration of database use.
func Reset(ctx context.Context, pool *pgxpool.Pool) (uuid.UUID, error) {
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS promotion_auth CASCADE; DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		return uuid.Nil, fmt.Errorf("reset test schema: %w", err)
	}
	if err := ApplyMigrations(ctx, pool); err != nil {
		return uuid.Nil, fmt.Errorf("migration failed: %w", err)
	}
	if err := promotiontest.Install(ctx, pool); err != nil {
		return uuid.Nil, fmt.Errorf("install trusted identity fixture: %w", err)
	}
	q := db.New(pool)
	teamID, err := seedSystemTemplate(ctx, pool, q)
	if err != nil {
		return uuid.Nil, fmt.Errorf("seed system template: %w", err)
	}
	if err := seedPreviewCapableHost(ctx, q); err != nil {
		return uuid.Nil, fmt.Errorf("seed preview-capable host: %w", err)
	}
	return teamID, nil
}

// seedSystemTemplate creates the system team + a ready `superserve/base`
// template so CreateSandbox's default from_template lookup resolves. Every
// integration test that POSTs /sandboxes without an explicit from_template
// relies on this.
func seedSystemTemplate(ctx context.Context, pool *pgxpool.Pool, q *db.Queries) (uuid.UUID, error) {
	team, err := q.CreateTeam(ctx, "superserve-system")
	if err != nil {
		return uuid.Nil, fmt.Errorf("create system team: %w", err)
	}
	tpl, err := q.CreateTemplate(ctx, db.CreateTemplateParams{
		TeamID:    team.ID,
		Name:      "superserve/base",
		BuildSpec: []byte(`{"from":"test","steps":[]}`),
		Vcpu:      1,
		MemoryMib: 1024,
		DiskMib:   4096,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("create superserve/base: %w", err)
	}

	// Flip to 'ready' with plausible paths so handlers.go's ready-check
	// passes. The stubVMD ignores these values.
	_, err = pool.Exec(ctx,
		`UPDATE template SET status = 'ready',
		   rootfs_path = '/tmp/test/rootfs.ext4',
		   snapshot_path = '/tmp/test/vmstate.snap',
		   mem_path = '/tmp/test/mem.snap',
		   size_bytes = 0,
		   built_at = now()
		 WHERE id = $1`, tpl.ID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("mark superserve/base ready: %w", err)
	}
	return team.ID, nil
}

// seedPreviewCapableHost creates the fallback host selected by integration
// routers and binds its preview capability to the current heartbeat. Strict
// sandbox creation intentionally rejects hosts without this live attestation.
func seedPreviewCapableHost(ctx context.Context, q *db.Queries) error {
	if _, err := q.CreateHost(ctx, db.CreateHostParams{
		ID:                DefaultHostID,
		VmdAddr:           "localhost:0",
		ProxyAddr:         "localhost:0",
		Region:            "test",
		CapacityMemoryMib: 1024,
		CapacityVcpus:     1,
	}); err != nil {
		return fmt.Errorf("create default host: %w", err)
	}
	if _, err := q.UpdateHostHeartbeat(ctx, DefaultHostID); err != nil {
		return fmt.Errorf("heartbeat default host: %w", err)
	}
	capabilities := []string{
		preview.HostCapabilityPorts,
		preview.HostCapabilityPortAccess,
		preview.HostCapabilityPortTokens,
		preview.HostCapabilityPortBrowserAuth,
	}
	if err := q.SyncHostCapabilities(ctx, db.SyncHostCapabilitiesParams{
		HostID: DefaultHostID, Capabilities: capabilities,
	}); err != nil {
		return fmt.Errorf("advertise capabilities: %w", err)
	}

	capable, err := q.HostHasCapabilities(ctx, db.HostHasCapabilitiesParams{
		AllowedStatuses: []string{"active"},
		HostID:          DefaultHostID, RequiredCapabilities: []string{preview.HostCapabilityPorts},
	})
	if err != nil {
		return fmt.Errorf("verify preview capability: %w", err)
	}
	if !capable {
		return fmt.Errorf("preview capability is not bound to the current heartbeat")
	}
	return nil
}

func FindMigrationsDir() (string, error) {
	// Find the repository migrations from either a command or test working directory.
	dir, _ := os.Getwd()
	for {
		migrationsDir := filepath.Join(dir, "supabase", "migrations")
		if _, err := os.Stat(migrationsDir); err == nil {
			return migrationsDir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find supabase/migrations from %s", dir)
		}
		dir = parent
	}
}

// ApplyMigrations executes the repository migrations in filename order.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	migrationsDir, err := FindMigrationsDir()
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(migrationsDir, e.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("exec %s: %w", e.Name(), err)
		}
	}
	return nil
}
