package db

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPreviewTokenGenerationMigrationOrderingAndCompatibility(t *testing.T) {
	const (
		phase2Migration = "20260727000002_preview_port_access_policy.sql"
		phase3Migration = "20260727000003_preview_port_token_generation.sql"
	)
	if phase2Migration >= phase3Migration {
		t.Fatalf("token generation migration %q must sort after access-policy prerequisite %q", phase3Migration, phase2Migration)
	}

	path := filepath.Join("..", "..", "supabase", "migrations", phase3Migration)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(raw)

	for _, required := range []string{
		phase2Migration,
		"CREATE TABLE sandbox_preview_port_token_generation",
		"ALTER TABLE public.sandbox_preview_port_token_generation ENABLE ROW LEVEL SECURITY",
		"REFERENCES sandbox (id) ON DELETE CASCADE",
		"CHECK (port >= 1024 AND port <= 65535 AND port <> 49983)",
		"CHECK (token_version > 0)",
		"9223372036854775807::bigint",
		"AFTER INSERT ON sandbox_published_port",
		"AFTER UPDATE OF access ON sandbox_published_port",
		"OLD.access IS DISTINCT FROM NEW.access",
		"ON CONFLICT (sandbox_id, port) DO UPDATE",
		"FROM sandbox_published_port",
		"ON CONFLICT (sandbox_id, port) DO NOTHING",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration is missing %q", required)
		}
	}

	// The generation row is a tombstone. A foreign key to the publication
	// would silently delete it and let re-publication revive version-1 tokens.
	publicationFK := regexp.MustCompile(`(?is)REFERENCES\s+(?:public\.)?sandbox_published_port\b`)
	if publicationFK.MatchString(sql) {
		t.Fatal("token generation must not reference sandbox_published_port")
	}
	if got := strings.Count(strings.ToUpper(sql), "REFERENCES "); got != 1 {
		t.Fatalf("token generation migration has %d foreign keys, want only the sandbox FK", got)
	}

	// Phase 2 binaries use SELECT/RETURNING shapes compiled before this phase.
	// Keeping all new state in a side table preserves those scanner contracts.
	for _, existingTable := range []string{"sandbox", "sandbox_published_port"} {
		alter := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:public\.)?` + existingTable + `\b`)
		if alter.MatchString(sql) {
			t.Errorf("migration alters existing %s row shape, breaking old Phase 2 scanners", existingTable)
		}
	}
}

func TestPreviewTokenGenerationUsesPostConflictTriggerSemantics(t *testing.T) {
	path := filepath.Join("..", "..", "supabase", "migrations", "20260727000003_preview_port_token_generation.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(raw)

	insertTrigger := regexp.MustCompile(`(?is)CREATE\s+TRIGGER\s+trg_preview_port_token_generation_on_insert\s+AFTER\s+INSERT\s+ON\s+sandbox_published_port`)
	if !insertTrigger.MatchString(sql) {
		t.Fatal("publication generation trigger must be AFTER INSERT so ON CONFLICT UPDATE does not bump")
	}
	accessTrigger := regexp.MustCompile(`(?is)CREATE\s+TRIGGER\s+trg_preview_port_token_generation_on_access_update\s+AFTER\s+UPDATE\s+OF\s+access\s+ON\s+sandbox_published_port.*?WHEN\s*\(OLD\.access\s+IS\s+DISTINCT\s+FROM\s+NEW\.access\)`)
	if !accessTrigger.MatchString(sql) {
		t.Fatal("access trigger must bump only for an actual public/private transition")
	}
}
