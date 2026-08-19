//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

func revocationExists(t *testing.T, sandboxID uuid.UUID) bool {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(),
		`SELECT count(*) FROM sandbox_revocation WHERE sandbox_id = $1`, sandboxID,
	).Scan(&n); err != nil {
		t.Fatalf("count revocations for %s: %v", sandboxID, err)
	}
	return n > 0
}

func destroy(t *testing.T, teamID, sandboxID uuid.UUID) {
	t.Helper()
	if _, err := testQueries.DestroySandbox(context.Background(), db.DestroySandboxParams{
		ID:                      sandboxID,
		TeamID:                  teamID,
		StaleTransitionalBefore: time.Now(),
		RevocationExpiresAt:     time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("destroy %s: %v", sandboxID, err)
	}
}

// Destroy writes a revocation only for sandboxes that ever had a secret
// binding: the proxy consults that set only after a secrets JWT authenticates,
// and a JWT is minted only for bound sandboxes. Revoking the rest accumulated
// entries no request could ever match.
func TestIntegration_DestroyRevokesOnlySecretsSandboxes(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)

	plain := insertSandboxAt(t, teamID, "plain-"+uuid.New().String()[:8], "active", time.Now())
	destroy(t, teamID, plain)
	if revocationExists(t, plain) {
		t.Error("sandbox that never had a binding was revoked; the set grows with every delete")
	}

	bound := insertSandboxAt(t, teamID, "bound-"+uuid.New().String()[:8], "active", time.Now())
	if _, err := testPool.Exec(ctx,
		`UPDATE sandbox SET had_secret_bindings = true WHERE id = $1`, bound); err != nil {
		t.Fatalf("mark bound: %v", err)
	}
	destroy(t, teamID, bound)
	if !revocationExists(t, bound) {
		t.Error("sandbox that had a binding was NOT revoked; a leaked JWT would stay valid")
	}
}

// The marker must survive the binding going away. Detach clears the row, and the
// mark-failed paths clear all of them, but a JWT may already have been minted
// and injected — so a live-bindings check would under-revoke exactly there.
func TestIntegration_SecretsMarkerSurvivesBindingRemoval(t *testing.T) {
	ctx := context.Background()
	teamID, _ := seedTeamAndKey(t)
	sandboxID := insertSandboxAt(t, teamID, "detached-"+uuid.New().String()[:8], "active", time.Now())

	var secretID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO secret (team_id, name, auth_type, hosts, ciphertext, encrypted_dek, kek_id)
		 VALUES ($1, $2, 'bearer', ARRAY['example.com'], '\x00'::bytea, '\x00'::bytea, 'test-kek')
		 RETURNING id`,
		teamID, "sec-"+uuid.New().String()[:8],
	).Scan(&secretID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	token := "tok-" + uuid.New().String()[:8]
	if err := testQueries.AddSandboxSecret(ctx, db.AddSandboxSecretParams{
		SandboxID: sandboxID, SecretID: secretID, EnvKey: "API_KEY", ProxyToken: &token,
	}); err != nil {
		t.Fatalf("AddSandboxSecret: %v", err)
	}

	// Clear every binding, as the mark-failed paths do.
	if err := testQueries.DeleteSandboxSecrets(ctx, sandboxID); err != nil {
		t.Fatalf("DeleteSandboxSecrets: %v", err)
	}

	destroy(t, teamID, sandboxID)
	if !revocationExists(t, sandboxID) {
		t.Error("marker did not survive binding removal; a JWT minted earlier would stay valid")
	}
}
