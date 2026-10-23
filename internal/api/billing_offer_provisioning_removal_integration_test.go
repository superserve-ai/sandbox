//go:build integration

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

func TestOfferCompositionRemovalGuard(t *testing.T) {
	for _, mode := range []string{"current_requester", "lost_shared_ack", "rollback", "successor_revoked", "shared_revoked"} {
		t.Run(mode, func(t *testing.T) {
			a, service, r, o := offerCompositionFixture(t)
			ctx := t.Context()
			if err := service.Reconcile(ctx, o.TeamID, o.AssignmentID); err != nil {
				t.Fatal(err)
			}
			requester, successor := uuid.New(), uuid.New()
			for _, stmt := range []struct {
				query string
				args  []any
			}{
				{`INSERT INTO profile(id,email) VALUES($1,($1::uuid)::text||'@example.test')`, []any{requester}},
				{`INSERT INTO team_memberships(user_id,team_id) VALUES($1,$2)`, []any{requester, r.TeamID}},
				{`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, []any{requester, r.TeamID}},
			} {
				if _, err := a.h.Pool.Exec(ctx, stmt.query, stmt.args...); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.h.Pool.Exec(ctx, `DELETE FROM user_role_assignments WHERE user_id=$1 AND team_id=$2`, r.UserID, r.TeamID); err != nil {
				t.Fatal(err)
			}
			a.admission.Service.Authorize = func(ctx context.Context, user, team uuid.UUID) error {
				return authz.New(a.h.Pool).RequireTeamPermission(ctx, user, team, "billing:write")
			}
			var sharedPID int32
			if mode == "lost_shared_ack" {
				cfg := a.h.Pool.Config().Copy()
				cfg.MaxConns, cfg.MinConns = 1, 0
				shared, err := pgxpool.NewWithConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(shared.Close)
				a.admission.Service.Shared = shared
				if err = shared.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&sharedPID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "successor_revoked" {
				tx, err := a.h.Pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if err = lockOfferFinancialAccount(ctx, tx, r.TeamID); err != nil {
					t.Fatal(err)
				}
				target := provisioning.FinancialTarget{TeamID: r.TeamID, AssignmentID: *r.AssignmentID, Phase: "successor", TargetID: successor}
				if err = provisioning.RevokeFinancialTarget(ctx, tx, target, uuid.New(), nil); err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
			revoke := func() {
				t.Helper()
				if _, err := a.h.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "shared_revoked" {
				revoke()
			}
			called := 0
			apply := func(ctx context.Context, tx pgx.Tx) error {
				called++
				if _, err := tx.Exec(ctx, `UPDATE billing_offer_provisioning_operation SET last_error='removal-confirmed' WHERE id=$1 AND last_error IS DISTINCT FROM 'removal-confirmed'`, o.ID); err != nil {
					return err
				}
				if mode == "rollback" {
					return errors.New("synthetic removal failure")
				}
				if sharedPID != 0 {
					_, err := tx.Exec(ctx, `SELECT pg_terminate_backend($1)`, sharedPID)
					sharedPID = 0
					return err
				}
				return nil
			}
			err := a.h.WithAcceptedOfferRemoval(ctx, r, requester, successor, apply)
			wantError := mode != "current_requester"
			if (err != nil) != wantError {
				t.Fatal("unexpected removal result", mode, err)
			}
			var saved bool
			if err = a.h.Pool.QueryRow(ctx, `SELECT COALESCE(last_error='removal-confirmed',false) FROM billing_offer_provisioning_operation WHERE id=$1`, o.ID).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			if saved != (mode == "current_requester" || mode == "lost_shared_ack") {
				t.Fatal("removal commit/readback mismatch", mode, saved)
			}
			if mode == "successor_revoked" || mode == "shared_revoked" {
				if called != 0 {
					t.Fatal("revocation allowed removal callback")
				}
				return
			}
			if mode == "rollback" {
				return
			}
			if err = a.h.WithAcceptedOfferRemoval(ctx, r, requester, successor, apply); err != nil {
				t.Fatal("removal replay failed", err)
			}
			var benefits int
			if err = a.h.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_offer_financial_fence WHERE team_id=$1 AND phase='successor' AND (finalized_at IS NOT NULL OR authorization_receipt IS NOT NULL)`, r.TeamID).Scan(&benefits); err != nil || benefits != 0 {
				t.Fatal("removal created financial benefit authority", benefits, err)
			}
			revoke()
			if _, err = a.drainFinancialInvalidations(ctx); err != nil {
				t.Fatal("existing finalized target could not drain after removal", err)
			}
			requireFinancialState(t, a.admission.Service, r, "revoked", 0)
		})
	}
}
