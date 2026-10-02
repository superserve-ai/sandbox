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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/builder"
)

var seedDBURL string

func TestMain(m *testing.M) {
	os.Exit(runSeedTests(m))
}

func runSeedTests(m *testing.M) int {
	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL must name an integration database")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to integration database: %v\n", err)
		return 1
	}
	defer admin.Close(context.Background())

	name := "seed_templates_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12] + "_test"
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		fmt.Fprintf(os.Stderr, "create seed test database: %v\n", err)
		return 1
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), `DROP DATABASE `+name+` WITH (FORCE)`); err != nil {
			fmt.Fprintf(os.Stderr, "drop seed test database: %v\n", err)
		}
	}()
	u, err := url.Parse(adminURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse DATABASE_URL: %v\n", err)
		return 1
	}
	u.Path = "/" + name
	seedDBURL = u.String()
	pool, err := pgxpool.New(ctx, seedDBURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open seed test database: %v\n", err)
		return 1
	}
	defer pool.Close()
	if err := migrateSeedTestDB(ctx, pool); err != nil {
		fmt.Fprintf(os.Stderr, "migrate seed test database: %v\n", err)
		return 1
	}
	return m.Run()
}

func migrateSeedTestDB(ctx context.Context, pool *pgxpool.Pool) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	for {
		path := filepath.Join(dir, "supabase", "migrations")
		if _, err := os.Stat(path); err == nil {
			entries, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".sql") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(path, entry.Name()))
				if err != nil {
					return fmt.Errorf("read %s: %w", entry.Name(), err)
				}
				if _, err := pool.Exec(ctx, string(data)); err != nil {
					return fmt.Errorf("exec %s: %w", entry.Name(), err)
				}
			}
			return nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("could not find supabase/migrations")
		}
		dir = parent
	}
}

// These tests use a disposable, migrated database separate from other packages.
func seedTestDB(t *testing.T) (*pgxpool.Pool, uuid.UUID) {
	t.Helper()
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, seedDBURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	teamID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO team(id,name) VALUES ($1,$2)`, teamID, "seed-test-"+teamID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, query := range []string{
			`DELETE FROM template_build_identity WHERE build_id IN (SELECT id FROM template_build WHERE team_id=$1)`,
			`DELETE FROM template_build_execution WHERE build_id IN (SELECT id FROM template_build WHERE team_id=$1)`,
			`DELETE FROM template_build WHERE team_id=$1`,
			`DELETE FROM template WHERE team_id=$1`,
			`DELETE FROM team_credit_grant WHERE team_id=$1`,
			`DELETE FROM team WHERE id=$1`,
		} {
			if _, err := pool.Exec(ctx, query, teamID); err != nil {
				t.Errorf("clean up seed fixtures: %v", err)
			}
		}
	})
	return pool, teamID
}

func seedBuildCount(t *testing.T, pool *pgxpool.Pool, teamID uuid.UUID) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM template_build WHERE team_id=$1`, teamID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func setSeedBuildStatus(t *testing.T, pool *pgxpool.Pool, buildID uuid.UUID, status string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE template_build SET status=$2,finalized_at=now() WHERE id=$1`, buildID, status); err != nil {
		t.Fatal(err)
	}
}

func readySeedFixture(t *testing.T, pool *pgxpool.Pool, teamID uuid.UUID, s seedSpec) uuid.UUID {
	t.Helper()
	vcpu, memory, disk := resolvedResources(s)
	hash, err := builder.InputHash(s.BuildSpec, vcpu, memory, disk)
	if err != nil {
		t.Fatal(err)
	}
	var templateID, buildID uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO template(team_id,name,build_spec,vcpu,memory_mib,disk_mib,status)
		VALUES ($1,$2,$3,$4,$5,$6,'ready') RETURNING id`, teamID, s.Name, []byte(s.BuildSpec), vcpu, memory, disk).Scan(&templateID); err != nil {
		t.Fatal(err)
	}
	// A historical ready row has no captured input or execution and is accepted
	// by the rollout path without fabricating a publication.
	if err := pool.QueryRow(t.Context(), `INSERT INTO template_build(template_id,team_id,build_spec_hash,status,finalized_at)
		VALUES ($1,$2,$3,'ready',now()) RETURNING id`, templateID, teamID, hash).Scan(&buildID); err != nil {
		t.Fatal(err)
	}
	return buildID
}

func TestSeedSubmissionRerunAndSpecChange(t *testing.T) {
	pool, teamID := seedTestDB(t)
	ctx := t.Context()
	s := seedSpec{Name: "example-template", BuildSpec: []byte(`{"from":"example/image:v1"}`)}
	first := readySeedFixture(t, pool, teamID, s)
	if id, queued, err := seedOne(ctx, pool, teamID, s, false); err != nil || queued || id != uuid.Nil {
		t.Fatalf("unchanged rerun: id=%s queued=%v err=%v", id, queued, err)
	}
	if count := seedBuildCount(t, pool, teamID); count != 1 {
		t.Fatalf("unchanged rerun created %d builds", count)
	}

	s.BuildSpec = []byte(`{"from":"example/image:v2"}`)
	specBuild, queued, err := seedOne(ctx, pool, teamID, s, false)
	if err != nil || !queued || specBuild == first {
		t.Fatalf("spec change: id=%s queued=%v err=%v", specBuild, queued, err)
	}
	if count := seedBuildCount(t, pool, teamID); count != 2 {
		t.Fatalf("spec change created %d builds", count)
	}
}

func TestSeedSubmissionResourceOnlyChange(t *testing.T) {
	pool, teamID := seedTestDB(t)
	s := seedSpec{Name: "example-template", BuildSpec: []byte(`{"from":"example/image:v1"}`)}
	first := readySeedFixture(t, pool, teamID, s)
	vcpu := int32(2)
	s.Vcpu = &vcpu
	resourceBuild, queued, err := seedOne(t.Context(), pool, teamID, s, false)
	if err != nil || !queued || resourceBuild == first {
		t.Fatalf("resource change: id=%s queued=%v err=%v", resourceBuild, queued, err)
	}
	var capturedVCPU int32
	if err := pool.QueryRow(t.Context(), `SELECT vcpu FROM template_build_input WHERE build_id=$1`, resourceBuild).Scan(&capturedVCPU); err != nil || capturedVCPU != vcpu {
		t.Fatalf("resource snapshot: vcpu=%d err=%v", capturedVCPU, err)
	}
	if count := seedBuildCount(t, pool, teamID); count != 2 {
		t.Fatalf("resource change created %d builds", count)
	}
}

func TestSeedSubmissionJoinsConcurrentInput(t *testing.T) {
	pool, teamID := seedTestDB(t)
	s := seedSpec{Name: "example-template", BuildSpec: []byte(`{"from":"example/image:v1"}`)}
	start := make(chan struct{})
	type result struct {
		id     uuid.UUID
		queued bool
		err    error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id, queued, err := seedOne(t.Context(), pool, teamID, s, false)
			results <- result{id, queued, err}
		}()
	}
	close(start)
	wg.Wait()
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || !a.queued || !b.queued || a.id == uuid.Nil || a.id != b.id {
		t.Fatalf("concurrent submissions did not join: %+v %+v", a, b)
	}
	if count := seedBuildCount(t, pool, teamID); count != 1 {
		t.Fatalf("concurrent submissions created %d builds", count)
	}
}

func TestSeedSubmissionTerminalRebuildAndForce(t *testing.T) {
	for _, terminal := range []string{"failed", "cancelled"} {
		t.Run(terminal, func(t *testing.T) {
			pool, teamID := seedTestDB(t)
			s := seedSpec{Name: "example-template", BuildSpec: []byte(`{"from":"example/image:v1"}`)}
			first := readySeedFixture(t, pool, teamID, s)
			s.BuildSpec = []byte(`{"from":"example/image:v2"}`)
			failedRebuild, queued, err := seedOne(t.Context(), pool, teamID, s, false)
			if err != nil || !queued || failedRebuild == first {
				t.Fatalf("changed input: id=%s queued=%v err=%v", failedRebuild, queued, err)
			}
			setSeedBuildStatus(t, pool, failedRebuild, terminal)
			rebuild, queued, err := seedOne(t.Context(), pool, teamID, s, false)
			if err != nil || !queued || rebuild == failedRebuild {
				t.Fatalf("%s rebuild: id=%s queued=%v err=%v", terminal, rebuild, queued, err)
			}
			if count := seedBuildCount(t, pool, teamID); count != 3 {
				t.Fatalf("expected three builds, got %d", count)
			}
		})
	}
}

func TestSeedSubmissionForceRebuild(t *testing.T) {
	pool, teamID := seedTestDB(t)
	s := seedSpec{Name: "example-template", BuildSpec: []byte(`{"from":"example/image:v1"}`)}
	ready := readySeedFixture(t, pool, teamID, s)
	forced, queued, err := seedOne(t.Context(), pool, teamID, s, true)
	if err != nil || !queued || forced == ready {
		t.Fatalf("forced rebuild: id=%s queued=%v err=%v", forced, queued, err)
	}
	if count := seedBuildCount(t, pool, teamID); count != 2 {
		t.Fatalf("expected two builds, got %d", count)
	}
}
