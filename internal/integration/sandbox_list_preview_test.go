//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

// A sandbox with no policy row must report the legacy default, one with a
// policy its own value. Handler unit tests mock the DB, so only a real query
// catches a join that drops rows or resolves the wrong column.
func TestIntegration_ListSandboxesCarriesPreviewAccess(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	legacyID := insertSandboxAt(t, teamID, "legacy-"+uuid.New().String()[:8], "active", time.Now().Add(-time.Minute))
	strictID := insertSandboxAt(t, teamID, "strict-"+uuid.New().String()[:8], "active", time.Now())

	if _, err := testPool.Exec(ctx,
		`INSERT INTO sandbox_preview_policy (sandbox_id, access, default_access, revision)
		 VALUES ($1, 'public', 'public', 1)`, strictID); err != nil {
		t.Fatalf("insert preview policy: %v", err)
	}

	assertAccess := func(t *testing.T, name string, got map[uuid.UUID]string) {
		t.Helper()
		if len(got) != 2 {
			t.Fatalf("%s: returned %d sandboxes, want 2", name, len(got))
		}
		if got[legacyID] != "legacy_public" {
			t.Errorf("%s: no-policy sandbox access = %q, want legacy_public", name, got[legacyID])
		}
		if got[strictID] != "public" {
			t.Errorf("%s: policy-bearing sandbox access = %q, want public", name, got[strictID])
		}
	}

	descRows, err := testQueries.ListSandboxesByTeamCreatedDesc(ctx, db.ListSandboxesByTeamCreatedDescParams{
		TeamID:   teamID,
		Metadata: []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("ListSandboxesByTeamCreatedDesc: %v", err)
	}
	desc := make(map[uuid.UUID]string, len(descRows))
	for _, r := range descRows {
		desc[r.Sandbox.ID] = r.PreviewAccess
	}
	assertAccess(t, "created_desc", desc)
	// Newest first: the ordering must survive the join.
	if descRows[0].Sandbox.ID != strictID {
		t.Errorf("created_desc: first row = %s, want the newest sandbox %s", descRows[0].Sandbox.ID, strictID)
	}

	pagedRows, err := testQueries.ListSandboxesByTeamPaged(ctx, db.ListSandboxesByTeamPagedParams{
		TeamID:   teamID,
		Metadata: []byte(`{}`),
		SortBy:   "name",
		SortDir:  "asc",
	})
	if err != nil {
		t.Fatalf("ListSandboxesByTeamPaged: %v", err)
	}
	paged := make(map[uuid.UUID]string, len(pagedRows))
	for _, r := range pagedRows {
		paged[r.Sandbox.ID] = r.PreviewAccess
	}
	assertAccess(t, "paged", paged)
}
