//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

func TestAuthoritativeAbuseTrustOwnersAndOverlap(t *testing.T) {
	ctx := context.Background()
	trusted := mustCreateTeam(t, ctx, "trusted-"+uuid.NewString()[:8])
	personal := mustCreateTeam(t, ctx, "personal-"+uuid.NewString()[:8])
	unrelated := mustCreateTeam(t, ctx, "unrelated-"+uuid.NewString()[:8])
	owner := seedRBACProfile(t)
	seedMembership(t, ctx, trusted, owner)
	seedMembership(t, ctx, personal, owner)
	seedTeamRoleAssignment(t, ctx, owner, mustRoleID(t, ctx, "team_owner"), personal)
	if _, err := testPool.Exec(ctx, `INSERT INTO abuse_team_trust(team_id,verified) VALUES($1,true)`, trusted); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='enforce'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='off'`) })
	for _, id := range []uuid.UUID{trusted, personal, unrelated} {
		if _, err := testPool.Exec(ctx, `INSERT INTO abuse_restrictions(subject_type,subject_value,subject_team_id,action,source,reason) VALUES('team',$1,$2,'create','test','synthetic')`, id.String(), id); err != nil {
			t.Fatal(err)
		}
	}
	first := abuse.NewAuthoritativeSource(testPool, abuse.AuthoritativeOptions{})
	second := abuse.NewAuthoritativeSource(testPool, abuse.AuthoritativeOptions{})
	for _, source := range []*abuse.AuthoritativeSource{first, second} {
		source.Refresh(ctx)
		if !source.Stats().Ready {
			t.Fatal("bootstrap did not publish")
		}
		for _, id := range []uuid.UUID{trusted, personal} {
			if !source.TeamPolicy(id).Trusted || source.TeamPolicy(id).Restricted {
				t.Fatalf("confirmed trust did not win: %+v", source.TeamPolicy(id))
			}
		}
		if !source.TeamPolicy(unrelated).Restricted {
			t.Fatal("unrelated team inherited trust")
		}
		if (&abuse.ComputeEvaluator{Source: source}).Evaluate(unrelated, abuse.ActionResume).Outcome != "blocked" {
			t.Fatal("create-only persisted row did not block resume")
		}
	}
	// Membership changes have no abuse change-feed row; full repair must still
	// revoke inherited trust without affecting the explicitly verified team.
	if _, err := testPool.Exec(ctx, `UPDATE team_memberships SET status='inactive' WHERE team_id=$1 AND user_id=$2`, trusted, owner); err != nil {
		t.Fatal(err)
	}
	first.Refresh(ctx)
	if first.TeamPolicy(personal).Trusted || !first.TeamPolicy(personal).Restricted || !first.TeamPolicy(trusted).Trusted {
		t.Fatal("membership revocation was not projected")
	}
	var permanent uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM abuse_restrictions WHERE subject_team_id=$1`, unrelated).Scan(&permanent); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO abuse_restrictions(subject_type,subject_value,subject_team_id,action,source,reason,expires_at) VALUES('team',$1,$2,'resume','test','expired',now()-interval '1 second')`, unrelated.String(), unrelated); err != nil {
		t.Fatal(err)
	}
	first.Refresh(ctx)
	if !first.TeamPolicy(unrelated).Restricted {
		t.Fatal("expired overlap removed permanent restriction")
	}
	if _, err := testPool.Exec(ctx, `UPDATE abuse_restrictions SET released_at=now() WHERE id=$1`, permanent); err != nil {
		t.Fatal(err)
	}
	for _, source := range []*abuse.AuthoritativeSource{first, second} {
		source.Refresh(ctx)
		if source.TeamPolicy(unrelated).Restricted {
			t.Fatal("released team stayed restricted")
		}
	}
	policy, err := abuse.ResolveTeamPolicy(ctx, testPool, personal)
	if err != nil || !policy.Known || policy.Trusted || !policy.Restricted {
		t.Fatalf("authoritative check disagreed: %+v %v", policy, err)
	}
}

func TestAuthoritativeAbuseModeAdminAndPrivacy(t *testing.T) {
	ctx := context.Background()
	admin := seedPlatformAdminProfile(t)
	nonAdmin := seedSuperserveEmailProfile(t)
	r := newInternalRouter(t)
	t.Cleanup(func() { testPool.Exec(ctx, `UPDATE abuse_runtime_settings SET mode='off'`) })
	if w := doInternal(r, http.MethodPut, "/internal/abuse/mode", nonAdmin.String(), `{"mode":"enforce"}`); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin mode change: %d", w.Code)
	}
	if w := doInternal(r, http.MethodPut, "/internal/abuse/mode", admin.String(), `{"mode":"invalid"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode accepted: %d", w.Code)
	}
	if w := doInternal(r, http.MethodPut, "/internal/abuse/mode", admin.String(), `{"mode":"observe"}`); w.Code != http.StatusNoContent {
		t.Fatalf("mode update: %d %s", w.Code, w.Body)
	}
	var mode string
	var auditCount int
	if err := testPool.QueryRow(ctx, `SELECT mode FROM abuse_runtime_settings WHERE singleton`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE actor_user_id=$1 AND event_type='abuse.mode.changed'`, admin).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if mode != "observe" || auditCount != 1 {
		t.Fatalf("mode/audit=%s/%d", mode, auditCount)
	}
	var exposed bool
	if err := testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('authenticated','anon') AND (has_table_privilege(oid,'abuse_runtime_settings','SELECT') OR has_table_privilege(oid,'abuse_runtime_settings','UPDATE')))`).Scan(&exposed); err != nil {
		t.Fatal(err)
	}
	if exposed {
		t.Fatal("runtime policy exposed to tenant roles")
	}
}

func TestAuthoritativeAbuseCorporateProof(t *testing.T) {
	ctx := context.Background()
	team := mustCreateTeam(t, ctx, "corporate-"+uuid.NewString()[:8])
	owner := seedRBACProfile(t)
	seedMembership(t, ctx, team, owner)
	seedTeamRoleAssignment(t, ctx, owner, mustRoleID(t, ctx, "team_owner"), team)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// The plain PostgreSQL harness has no auth service. Keep its synthetic
	// provider table transaction-local; never replace a real auth schema.
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT to_regclass('auth.identities') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Skip("synthetic auth schema test requires plain PostgreSQL harness")
	}
	for _, sql := range []string{
		`CREATE SCHEMA IF NOT EXISTS auth`,
		`CREATE TABLE auth.identities(user_id uuid,provider text,identity_data jsonb)`,
		`UPDATE abuse_runtime_settings SET mode='enforce'`,
		`INSERT INTO abuse_trusted_identities(auth_provider,domain) VALUES('google','corporate.example')`,
	} {
		if _, err = tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO abuse_restrictions(subject_type,subject_value,subject_team_id,action,source,reason) VALUES('team',$1,$2,'resume','test','synthetic')`, team.String(), team); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		data    string
		trusted bool
	}{
		{`{"email":"owner@corporate.example","email_verified":true}`, false},
		{`{"email":"owner@corporate.example","email_verified":false,"hd":"corporate.example"}`, false},
		{`{"email":"owner@personal.example","email_verified":true,"hd":"corporate.example"}`, false},
		{`{"email":"owner@corporate.example","email_verified":true,"hd":"corporate.example"}`, true},
	} {
		if _, err = tx.Exec(ctx, `DELETE FROM auth.identities`); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO auth.identities VALUES($1,'google',$2)`, owner, tc.data); err != nil {
			t.Fatal(err)
		}
		policy, err := abuse.ResolveTeamPolicy(ctx, tx, team)
		if err != nil || policy.Trusted != tc.trusted || policy.Restricted == tc.trusted {
			t.Fatalf("proof=%s policy=%+v err=%v", tc.data, policy, err)
		}
		source := abuse.NewAuthoritativeSource(tx, abuse.AuthoritativeOptions{})
		source.Refresh(ctx)
		if !source.Stats().Ready || source.TeamPolicy(team).Trusted != tc.trusted || source.TeamPolicy(team).Restricted == tc.trusted {
			t.Fatalf("proof=%s cached policy=%+v", tc.data, source.TeamPolicy(team))
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE abuse_trusted_identities SET revoked_at=now() WHERE domain='corporate.example'`); err != nil {
		t.Fatal(err)
	}
	policy, err := abuse.ResolveTeamPolicy(ctx, tx, team)
	if err != nil || policy.Trusted || !policy.Restricted {
		t.Fatalf("revoked association: %+v %v", policy, err)
	}
}

func TestAuthoritativeAbuseIdentityRestrictions(t *testing.T) {
	ctx := context.Background()
	owner := seedRBACProfile(t)
	otherOwner := seedRBACProfile(t)
	owned := mustCreateTeam(t, ctx, "owned-"+uuid.NewString()[:8])
	other := mustCreateTeam(t, ctx, "other-"+uuid.NewString()[:8])
	for team, user := range map[uuid.UUID]uuid.UUID{owned: owner, other: otherOwner} {
		seedMembership(t, ctx, team, user)
		seedTeamRoleAssignment(t, ctx, user, mustRoleID(t, ctx, "team_owner"), team)
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	domain := uuid.NewString() + ".example"
	if _, err := tx.Exec(ctx, `UPDATE profile SET email=$1 WHERE id=$2`, "owner@"+domain, owner); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"user", "domain"} {
		var restriction uuid.UUID
		if subject == "user" {
			err = tx.QueryRow(ctx, `INSERT INTO abuse_restrictions(subject_type,subject_value,subject_user_id,action,source,reason) VALUES('user',$1,$2,'create','test','synthetic') RETURNING id`, owner.String(), owner).Scan(&restriction)
		} else {
			err = tx.QueryRow(ctx, `INSERT INTO abuse_restrictions(subject_type,subject_value,action,source,reason) VALUES('domain',$1,'resume','test','synthetic') RETURNING id`, domain).Scan(&restriction)
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, released := range []bool{false, true} {
			if released {
				if _, err := tx.Exec(ctx, `UPDATE abuse_restrictions SET released_at=now() WHERE id=$1`, restriction); err != nil {
					t.Fatal(err)
				}
			}
			source := abuse.NewAuthoritativeSource(tx, abuse.AuthoritativeOptions{})
			source.Refresh(ctx)
			if !source.Stats().Ready || source.TeamPolicy(owned).Restricted == released || source.TeamPolicy(other).Restricted {
				t.Fatalf("%s released=%v: owned=%+v other=%+v", subject, released, source.TeamPolicy(owned), source.TeamPolicy(other))
			}
			current, err := abuse.ResolveTeamPolicy(ctx, tx, owned)
			if err != nil || current.Restricted == released {
				t.Fatalf("%s released=%v: current=%+v err=%v", subject, released, current, err)
			}
		}
	}
}
