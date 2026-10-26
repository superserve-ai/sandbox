//go:build integration

package integration

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestIntegration_PrepaidOperationProductionRole(t *testing.T) {
	owner := teamCreationDatabase(t, func(pool *pgxpool.Pool) {
		rolloutExec(t, pool, `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon,authenticated,service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO anon,authenticated,service_role`)
	})
	service := teamCreationServiceRolePool(t, owner)
	var role string
	var super, bypass bool
	if err := service.QueryRow(t.Context(), `SELECT current_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&role, &super, &bypass); err != nil || role != "service_role" || super || !bypass {
		t.Fatalf("production service role=%s super=%v bypass=%v: %v", role, super, bypass, err)
	}
	team, err := db.New(owner).CreateTeam(t.Context(), "operation-role-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	id, actor := uuid.New(), uuid.New()
	insert := `INSERT INTO billing_prepaid_checkout_operation(id,team_id,actor_id,amount_cents,success_url,cancel_url) VALUES($1,$2,$3,500,'https://example.com/ok','https://example.com/cancel') ON CONFLICT(id) DO NOTHING`
	for range 2 {
		if _, err := service.Exec(t.Context(), insert, id, team.ID, actor); err != nil {
			t.Fatal("service insert/replay", err)
		}
	}
	var bound bool
	if err := service.QueryRow(t.Context(), `SELECT team_id=$2 AND actor_id=$3 AND amount_cents=500 FROM billing_prepaid_checkout_operation WHERE id=$1`, id, team.ID, actor).Scan(&bound); err != nil || !bound {
		t.Fatalf("service read original binding: %v %v", bound, err)
	}
	mutations := []string{`UPDATE billing_prepaid_checkout_operation SET amount_cents=1000 WHERE id=$1`, `DELETE FROM billing_prepaid_checkout_operation WHERE id=$1`, `TRUNCATE billing_prepaid_checkout_operation`}
	expectCode := func(pool *pgxpool.Pool, statement, code string) {
		t.Helper()
		var err error
		if statement == mutations[2] {
			_, err = pool.Exec(t.Context(), statement)
		} else {
			_, err = pool.Exec(t.Context(), statement, id)
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Fatalf("%s: expected %s, got %v", statement, code, err)
		}
	}
	for _, statement := range mutations {
		expectCode(service, statement, "42501")
	}
	for _, clientRole := range []string{"anon", "authenticated"} {
		tx, err := owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err = tx.Exec(t.Context(), "SET LOCAL ROLE "+clientRole); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `SELECT * FROM billing_prepaid_checkout_operation`)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("%s retained default access: %v", clientRole, err)
		}
		_ = tx.Rollback(t.Context())
	}
	// The trigger fence survives a later accidental broad grant, even for RLS bypass.
	rolloutExec(t, owner, `GRANT ALL ON billing_prepaid_checkout_operation TO anon,authenticated,service_role`)
	for _, statement := range mutations {
		expectCode(service, statement, "55000")
	}
	for _, clientRole := range []string{"anon", "authenticated"} {
		tx, err := owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err = tx.Exec(t.Context(), "SET LOCAL ROLE "+clientRole); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = tx.QueryRow(t.Context(), `SELECT count(*) FROM billing_prepaid_checkout_operation`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s bypassed operation RLS: %d %v", clientRole, count, err)
		}
		_, err = tx.Exec(t.Context(), insert, uuid.New(), team.ID, actor)
		var pgErr *pgconn.PgError
		// The team lookup can encounter its RLS fence before the operation's
		// WITH CHECK fence; neither role may create the binding.
		if !errors.As(err, &pgErr) || (pgErr.Code != "42501" && pgErr.Code != "23503") {
			t.Fatalf("%s inserted an operation: %v", clientRole, err)
		}
		_ = tx.Rollback(t.Context())
	}
	if err := db.New(owner).DeleteTeam(t.Context(), team.ID); err != nil {
		t.Fatal("operation history blocked team deletion", err)
	}
	if err := service.QueryRow(t.Context(), `SELECT team_id=$2 AND actor_id=$3 AND amount_cents=500 FROM billing_prepaid_checkout_operation WHERE id=$1`, id, team.ID, actor).Scan(&bound); err != nil || !bound {
		t.Fatalf("team deletion lost operation binding: %v %v", bound, err)
	}
	if _, err := service.Exec(t.Context(), insert, uuid.New(), team.ID, actor); err == nil {
		t.Fatal("new operation accepted for deleted team")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("deleted-team insert failed outside team guard: %v", err)
		}
	}
	other, err := db.New(owner).CreateTeam(t.Context(), "operation-other-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Exec(t.Context(), insert, id, other.ID, uuid.New()); err != nil {
		t.Fatal("conflicting insert must preserve original binding", err)
	}
	if err := service.QueryRow(t.Context(), `SELECT team_id=$2 AND actor_id=$3 FROM billing_prepaid_checkout_operation WHERE id=$1`, id, team.ID, actor).Scan(&bound); err != nil || !bound {
		t.Fatalf("deleted-team operation was rebound: %v %v", bound, err)
	}
}
