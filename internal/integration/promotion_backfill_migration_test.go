//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPromotionBackfillPreservesExplicitSignupActor(t *testing.T) {
	migration, err := os.ReadFile("../../supabase/migrations/20260925195213_promotion_redemption_limits.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Execute the migration's backfill after seeding pre-migration history in
	// the current schema; copying its queries would miss future regressions.
	start := strings.Index(string(migration), "INSERT INTO user_signup_trial_claim(user_id, claimed_at, team_id)")
	end := strings.Index(string(migration), "-- Legacy Stripe grant rows retain")
	if start < 0 || end <= start {
		t.Fatal("signup promotion backfill not found in migration")
	}
	backfill := string(migration[start:end])

	for _, tc := range []struct {
		name           string
		explicitActor  bool
		legacyGrant    bool
		ownerMode      string
		wantCreator    bool
		wantLaterOwner bool
	}{
		{name: "explicit creator excludes later owner", explicitActor: true, wantCreator: true},
		{name: "mixed grant history excludes later owner", explicitActor: true, legacyGrant: true, wantCreator: true},
		{name: "legacy grant retains owner fallback", legacyGrant: true, wantLaterOwner: true},
		{name: "legacy grant without owner does not claim later member", legacyGrant: true, ownerMode: "none"},
		{name: "legacy grant with multiple owners does not claim later member", legacyGrant: true, ownerMode: "multiple"},
		{name: "grantless team retains earliest membership", wantCreator: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			teamID, creatorID, laterOwnerID := uuid.New(), uuid.New(), uuid.New()
			if _, err := tx.Exec(ctx, `INSERT INTO team (id, name) VALUES ($1, $2)`, teamID, "promotion-backfill-"+teamID.String()); err != nil {
				t.Fatal(err)
			}
			// These fixtures predate pending signup provenance.
			if _, err := tx.Exec(ctx, `DELETE FROM team_signup_trial_provenance WHERE team_id = $1`, teamID); err != nil {
				t.Fatal(err)
			}
			for _, userID := range []uuid.UUID{creatorID, laterOwnerID} {
				if _, err := tx.Exec(ctx, `INSERT INTO profile (id, email) VALUES ($1, $2)`, userID, userID.String()+"@example.com"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO team_memberships (team_id, user_id, status, created_at)
				VALUES ($1, $2, 'active', now() - interval '2 days'), ($1, $3, 'active', now() - interval '1 day')`, teamID, creatorID, laterOwnerID); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO team_member (team_id, profile_id, role)
				VALUES ($1, $2, 'member'), ($1, $3, 'owner')`, teamID, creatorID, laterOwnerID); err != nil {
				t.Fatal(err)
			}
			if tc.ownerMode != "" {
				role := "member"
				if tc.ownerMode == "multiple" {
					role = "owner"
				}
				if _, err := tx.Exec(ctx, `UPDATE team_member SET role = $2 WHERE team_id = $1`, teamID, role); err != nil {
					t.Fatal(err)
				}
			}
			if tc.explicitActor {
				if _, err := tx.Exec(ctx, `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, created_by)
					VALUES ($1, 5, 5, 'signup trial credit', $2)`, teamID, creatorID); err != nil {
					t.Fatal(err)
				}
			}
			if tc.legacyGrant {
				if _, err := tx.Exec(ctx, `INSERT INTO team_credit_grant (team_id, amount_usd, remaining_usd, reason, created_by, created_at)
					VALUES ($1, 5, 5, 'signup trial credit', NULL, now() - interval '3 days')`, teamID); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := 1; attempt <= 2; attempt++ {
				if _, err := tx.Exec(ctx, backfill); err != nil {
					t.Fatalf("backfill attempt %d: %v", attempt, err)
				}
				for _, user := range []struct {
					id   uuid.UUID
					want bool
				}{
					{creatorID, tc.wantCreator},
					{laterOwnerID, tc.wantLaterOwner},
				} {
					var claimed, entitled bool
					if err := tx.QueryRow(ctx, `SELECT
						EXISTS (SELECT 1 FROM user_signup_trial_claim WHERE user_id = $1),
						EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = $1 AND signup_trial_claimed_at IS NOT NULL)`, user.id).Scan(&claimed, &entitled); err != nil {
						t.Fatal(err)
					}
					if claimed != user.want || entitled != user.want {
						t.Fatalf("attempt %d user %s: claimed=%t entitled=%t, want %t", attempt, user.id, claimed, entitled, user.want)
					}
					if user.want {
						var claimTeam, entitlementTeam uuid.UUID
						if err := tx.QueryRow(ctx, `SELECT c.team_id, e.signup_trial_team_id
							FROM user_signup_trial_claim c JOIN user_promotion_entitlement e ON e.user_id = c.user_id
							WHERE c.user_id = $1`, user.id).Scan(&claimTeam, &entitlementTeam); err != nil {
							t.Fatal(err)
						}
						if claimTeam != teamID || entitlementTeam != teamID {
							t.Fatalf("backfilled team = %s/%s, want %s", claimTeam, entitlementTeam, teamID)
						}
					}
				}
			}
		})
	}
}

func TestStripePromotionBackfillRequiresRecordedActor(t *testing.T) {
	migration, err := os.ReadFile("../../supabase/migrations/20260925195213_promotion_redemption_limits.sql")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(migration), "-- Legacy Stripe grant rows retain")
	end := strings.Index(string(migration), "-- Current ownership or membership alone")
	if start < 0 || end <= start {
		t.Fatal("Stripe promotion backfill not found in migration")
	}
	backfill := string(migration[start:end])
	canonical, err := os.ReadFile("../../supabase/migrations/20260925195235_canonical_promotion_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	historyStart := strings.Index(string(canonical), "INSERT INTO promotion_identity_history(history_key, promotion, user_id, team_id, claimed_at, grant_state)")
	historyEnd := strings.Index(string(canonical), "CREATE FUNCTION reconcile_promotion_identity_history(")
	if historyStart < 0 || historyEnd <= historyStart {
		t.Fatal("Stripe canonical history backfill not found in migration")
	}
	for _, tc := range []struct {
		name          string
		ledger        string
		accountActor  bool
		accountMarker bool
		wantActor     bool
	}{
		{name: "current owner and later invitee are not payer evidence", accountMarker: true},
		{name: "anonymous ledger preserves team fence", ledger: "anonymous"},
		{name: "operator author is not a team member", ledger: "operator"},
		{name: "member ledger author is supported", ledger: "member", wantActor: true},
		{name: "RBAC member ledger author is supported", ledger: "rbac", wantActor: true},
		{name: "conflicting ledger authors remain unresolved", ledger: "conflict"},
		{name: "recorded activation actor wins over conflicting ledger", ledger: "owner", accountActor: true, accountMarker: true, wantActor: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := tx.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			team, actor, owner, invitee, consumed := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
			exec(`INSERT INTO team(id,name) VALUES($1,$2)`, team, "historical-promotion-"+team.String())
			for _, user := range []uuid.UUID{actor, owner, invitee, consumed} {
				exec(`INSERT INTO profile(id,email) VALUES($1,$2)`, user, user.String()+"@example.com")
			}
			exec(`INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'owner'),($1,$3,'member')`, team, owner, invitee)
			exec(`INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active'),($1,$3,'active')`, team, owner, invitee)
			if tc.ledger == "member" || tc.ledger == "conflict" {
				exec(`INSERT INTO team_member(team_id,profile_id,role) VALUES($1,$2,'member')`, team, actor)
			}
			if tc.ledger == "rbac" {
				exec(`INSERT INTO team_memberships(team_id,user_id,status) VALUES($1,$2,'active')`, team, actor)
			}
			var recordedActor any
			if tc.accountActor {
				recordedActor = actor
			}
			if tc.accountMarker {
				exec(`INSERT INTO team_billing_account(team_id,stripe_activation_user_id,stripe_activation_credit_grant_id)
					VALUES($1,$2,'historical-grant')`, team, recordedActor)
			}
			var authors []any
			switch tc.ledger {
			case "anonymous":
				authors = []any{nil}
			case "owner":
				authors = []any{owner}
			case "conflict":
				authors = []any{actor, owner}
			case "member", "rbac", "operator":
				authors = []any{actor}
			}
			for _, author := range authors {
				exec(`INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason,created_by,created_at)
					VALUES($1,95,95,'stripe promotional credit',$2,now()-interval '30 days')`, team, author)
			}
			exec(`INSERT INTO user_promotion_entitlement(user_id,stripe_redemption_at)
				VALUES($1,now()-interval '60 days')`, consumed)
			var consumedBefore string
			if err := tx.QueryRow(ctx, `SELECT to_jsonb(e)::text FROM user_promotion_entitlement e WHERE user_id=$1`, consumed).Scan(&consumedBefore); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				exec(backfill)
			}
			for _, user := range []uuid.UUID{actor, owner, invitee} {
				var redeemed bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_promotion_entitlement
					WHERE user_id=$1 AND stripe_redemption_at IS NOT NULL)`, user).Scan(&redeemed); err != nil {
					t.Fatal(err)
				}
				if want := user == actor && tc.wantActor; redeemed != want {
					t.Fatalf("user %s redeemed=%t, want %t", user, redeemed, want)
				}
			}
			var teamMarked, actorMatches bool
			if tc.wantActor {
				recordedActor = actor
			}
			if err := tx.QueryRow(ctx, `SELECT stripe_activation_credit_grant_id IS NOT NULL,
				stripe_activation_user_id IS NOT DISTINCT FROM $2::uuid FROM team_billing_account WHERE team_id=$1`, team, recordedActor).Scan(&teamMarked, &actorMatches); err != nil || !teamMarked || !actorMatches {
				t.Fatalf("team marker=%t actor matches=%t err=%v", teamMarked, actorMatches, err)
			}
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM team_credit_grant WHERE team_id=$1 AND reason='stripe promotional credit'`, team).Scan(&count); err != nil || count != len(authors) {
				t.Fatalf("historical grants changed: count=%d want=%d err=%v", count, len(authors), err)
			}
			var consumedAfter string
			if err := tx.QueryRow(ctx, `SELECT to_jsonb(e)::text FROM user_promotion_entitlement e WHERE user_id=$1`, consumed).Scan(&consumedAfter); err != nil || consumedBefore != consumedAfter {
				t.Fatalf("existing redemption was changed: %s -> %s (%v)", consumedBefore, consumedAfter, err)
			}
			exec(`DELETE FROM promotion_identity_history WHERE promotion='stripe'`)
			exec(string(canonical[historyStart:historyEnd]))
			var pending bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotion_identity_history WHERE team_id=$1
				AND promotion='stripe' AND status='pending' AND cardinality(identity_keys)=0)`, team).Scan(&pending); err != nil || !pending {
				t.Fatalf("historical identity should require reconciliation: pending=%t err=%v", pending, err)
			}
		})
	}
}
