package db

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPreviewPublicationMigrationPreservesRollingScannerShapes(t *testing.T) {
	path := filepath.Join("..", "..", "supabase", "migrations", "20260727000001_preview_port_publication.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(raw)
	for _, table := range []string{"sandbox_preview_policy", "sandbox_published_port", "host_capability"} {
		if !strings.Contains(sql, "CREATE TABLE "+table) {
			t.Errorf("migration does not create %s side table", table)
		}
		if !strings.Contains(sql, "ALTER TABLE public."+table+" ENABLE ROW LEVEL SECURITY") {
			t.Errorf("migration does not protect %s with row-level security", table)
		}
	}
	for _, existingTable := range []string{"sandbox", "host"} {
		pattern := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:public\.)?` + existingTable + `\b`)
		if pattern.MatchString(sql) {
			t.Errorf("migration alters existing %s row shape, which breaks old SELECT */RETURNING * scanners", existingTable)
		}
	}
	if !strings.Contains(sql, "port <> 49983") {
		t.Fatal("published-port constraint permits boxd's reserved port 49983")
	}
}

func TestMissingPreviewPolicyRowRemainsLegacyPublic(t *testing.T) {
	path := filepath.Join("..", "..", "db", "queries", "sandboxes.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sandbox queries: %v", err)
	}
	queries := string(raw)
	if !strings.Contains(queries, "LEFT JOIN sandbox_preview_policy") ||
		!strings.Contains(queries, "COALESCE(p.default_access, p.access, 'legacy_public')") {
		t.Fatal("effective preview policy no longer maps an absent old-writer row to legacy_public")
	}
}

func TestPreviewAccessMigrationKeepsRollbackStateInSideTables(t *testing.T) {
	path := filepath.Join("..", "..", "supabase", "migrations", "20260727000002_preview_port_access_policy.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(raw)
	for _, existingTable := range []string{"sandbox", "host"} {
		pattern := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:public\.)?` + existingTable + `\b`)
		if pattern.MatchString(sql) {
			t.Errorf("phase 2 alters existing %s row shape", existingTable)
		}
	}
	for _, required := range []string{
		"ALTER TABLE sandbox_preview_policy",
		"ADD COLUMN default_access text",
		"ALTER TABLE sandbox_published_port",
		"sandbox_preview_policy_maintain_fallback",
		"sandbox_published_port_default_access",
		"sandbox_published_port_refresh_fallback",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing rollback guard %q", required)
		}
	}
	if strings.Contains(sql, "ALTER COLUMN access SET DEFAULT") {
		t.Fatal("published-port access has a SQL default; Phase 1 omitted inserts must use the true policy default trigger")
	}
}

func TestPublishPortOmissionPreservesExistingModeAndUsesTrueDefaultOnlyOnInsert(t *testing.T) {
	path := filepath.Join("..", "..", "db", "queries", "sandboxes.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sandbox queries: %v", err)
	}
	queries := string(raw)
	for _, required := range []string{
		"CASE WHEN p.default_access = 'private' THEN 'private' ELSE 'public' END",
		"COALESCE(sqlc.narg('access')::text, sandbox_published_port.access)",
		"SET default_access = $2",
		"RETURNING default_access AS access, access AS wire_access, revision",
	} {
		if !strings.Contains(queries, required) {
			t.Errorf("sandbox queries missing %q", required)
		}
	}
}

func TestSandboxCreationWritesStrictPolicyInQuotaAdmissionStatement(t *testing.T) {
	path := filepath.Join("..", "..", "db", "queries", "sandboxes.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sandbox queries: %v", err)
	}
	queries := string(raw)
	for _, name := range []string{
		"CreateSandbox",
		"CreateSandboxFromTemplate",
		"CreateSandboxWithSecrets",
		"CreateSandboxFromTemplateWithSecrets",
	} {
		marker := "-- name: " + name + " :one"
		start := strings.Index(queries, marker)
		if start < 0 {
			t.Errorf("missing %s query", name)
			continue
		}
		query := queries[start+len(marker):]
		if end := strings.Index(query, "-- name: "); end >= 0 {
			query = query[:end]
		}
		if !strings.Contains(query, "INSERT INTO sandbox_preview_policy") {
			t.Errorf("%s does not create the strict preview policy atomically", name)
		}
		if !strings.Contains(query, "preview_access") {
			t.Errorf("%s does not accept the new sandbox's preview access", name)
		}
		if !strings.Contains(query, "JOIN preview_policy") {
			t.Errorf("%s does not require the policy insert before returning", name)
		}
	}
	if strings.Contains(queries, "-- name: CreateSandboxPreviewPolicy") {
		t.Fatal("standalone preview-policy creation would widen the quota admission transaction")
	}
}

func TestHostCapabilityAttestationIsBoundToCurrentHeartbeat(t *testing.T) {
	path := filepath.Join("..", "..", "db", "queries", "hosts.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read host queries: %v", err)
	}
	queries := string(raw)
	if !strings.Contains(queries, "SELECT id, sqlc.arg(capability), last_heartbeat_at") {
		t.Fatal("capability insert is not stamped with the heartbeat it attests")
	}
	if got := strings.Count(queries, "hc.heartbeat_at = h.last_heartbeat_at"); got < 2 {
		t.Fatalf("current-heartbeat attestation checks = %d, want both host gate and scheduler", got)
	}
	if !strings.Contains(queries, "h.status = 'active'") {
		t.Fatal("host capability gate accepts capabilities from an unhealthy host")
	}
}
