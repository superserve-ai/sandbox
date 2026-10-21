//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This fixture tests only journal persistence in its own disposable schema. It
// does not stand in for production authority, catalog or payment guard adapters.
func newRenewalPostgresFixture(t *testing.T, initialize ...bool) (*renewalChoiceService, *fixtureRenewalAuthority, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("RENEWAL_JOURNAL_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated renewal journal database not configured")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.Host != "127.0.0.1" || (cfg.ConnConfig.Database != "renewal_choice_test" && cfg.ConnConfig.Database != "sandbox_test") {
		t.Fatal("requires loopback renewal_choice_test or CI sandbox_test database")
	}
	admin, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	schema := "renewal_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(t.Context(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); admin.Close() })
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err = pool.Exec(t.Context(), `CREATE TABLE team(id uuid PRIMARY KEY); CREATE TABLE team_billing_account(team_id uuid PRIMARY KEY REFERENCES team(id))`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../supabase/migrations/20261021135341_billing_renewal_choice.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), string(migration)); err != nil {
		t.Fatal(err)
	}
	_, _, a := newRenewalFixture(t)
	a.now = time.Now().UTC().Add(-time.Second)
	a.key.Boundary = a.now.AddDate(0, 1, 0).Truncate(time.Second)
	a.authority.Binding.Anchor = a.key.Boundary.AddDate(-1, 0, 0)
	if _, err = pool.Exec(t.Context(), `INSERT INTO team(id) VALUES($1)`, a.key.Team); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO team_billing_account(team_id) VALUES($1)`, a.key.Team); err != nil {
		t.Fatal(err)
	}
	s := &renewalChoiceService{Enabled: true, Store: postgresRenewalChoiceStore{Pool: pool}, Authority: a}
	if len(initialize) == 0 || initialize[0] {
		if err = s.initialize(t.Context(), a.key, a.actor); err != nil {
			t.Fatal(err)
		}
	}
	return s, a, pool
}

func TestRenewalChoicePostgresReplayConcurrencyAndRollback(t *testing.T) {
	s, a, pool := newRenewalPostgresFixture(t)
	j := submitRenewal(t, s, a, "free")
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.submit(t.Context(), a.key, a.actor, renewalChoiceRequest{ID: uuid.New(), Choice: "annual", Acceptance: a.authority.Acceptance, ApprovalRevision: 7, ChoiceRevision: j.Revision})
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, errRenewalConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("lost database revision fence", accepted.Load())
	}
	// Reconstruct the service to exercise persisted identities rather than memory.
	resumed := &renewalChoiceService{Enabled: true, Store: postgresRenewalChoiceStore{Pool: pool}, Authority: a}
	replay, err := resumed.submit(t.Context(), a.key, a.actor, j.Requested.Request)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Successor != j.Successor || replay.Revision != j.Revision+1 || replay.Confirmed.Request.Choice != "annual" {
		t.Fatal(replay)
	}
	marker := errors.New("rollback after save")
	err = resumed.Store.Transact(t.Context(), a.key, func(tx renewalChoiceTransaction) error {
		tx.Journal().SuccessorState = "active"
		if e := tx.Save("must_rollback"); e != nil {
			return e
		}
		return marker
	})
	if !errors.Is(err, marker) {
		t.Fatal(err)
	}
	current, err := resumed.status(t.Context(), a.key, a.actor)
	if err != nil || current.SuccessorState != "scheduled" || current.Revision != replay.Revision {
		t.Fatal(current, err)
	}
	var requests, events int
	if err = pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM billing_renewal_choice_request),(SELECT count(*) FROM billing_renewal_choice_event)`).Scan(&requests, &events); err != nil {
		t.Fatal(err)
	}
	if requests != 3 || events != 3 {
		t.Fatal("request/event transaction diverged", requests, events)
	}
	if _, err = pool.Exec(t.Context(), `UPDATE billing_renewal_choice_request SET request='{}'`); err == nil {
		t.Fatal("request history mutable")
	}
	if _, err = pool.Exec(t.Context(), `DELETE FROM billing_renewal_choice_event`); err == nil {
		t.Fatal("event history mutable")
	}
}

func TestRenewalChoicePostgresDispatchSurvivesRestart(t *testing.T) {
	s, a, pool := newRenewalPostgresFixture(t)
	j := submitRenewal(t, s, a, "free")
	// Crash after persisted intent and before the external response. Recovery is
	// observation-only even if it cannot tell whether the write was ever sent.
	if err := s.Store.Transact(t.Context(), a.key, func(tx renewalChoiceTransaction) error {
		op := tx.Journal().Requested
		now := tx.Now()
		op.State = "dispatched"
		op.DispatchedAt = &now
		return tx.Save("dispatch_intent")
	}); err != nil {
		t.Fatal(err)
	}
	p := &fixtureRenewalProvider{dispatch: func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
		t.Fatal("replayed uncertain write")
		return renewalChoiceProof{}, nil
	}, observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		if op.ID != j.Requested.ID {
			t.Fatal("operation replaced")
		}
		return fixtureRenewalProof(k, op, a.now), nil
	}}
	resumed := &renewalChoiceService{Enabled: true, Store: postgresRenewalChoiceStore{Pool: pool}, Authority: a, Provider: p}
	if err := resumed.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	got, err := resumed.status(t.Context(), a.key, a.actor)
	if err != nil || got.Confirmed.Request.Choice != "free" || p.writes.Load() != 0 {
		t.Fatal(got, err)
	}
}

func TestRenewalChoiceMonthlyPublicationRejectsConflictingVersion(t *testing.T) {
	_, _, pool := newRenewalPostgresFixture(t)
	// Use the upstream published catalog's columns and immutable key semantics.
	_, err := pool.Exec(t.Context(), `CREATE TABLE billing_commercial_offer_version(offer_key text,version int,rate_card_key text,plan_tier text,currency text,term_months int,charge_amount_cents bigint,charge_interval_months int,initial_fee_waived bool,payment_requirement text,default_successor_family text,allowance_source text,monthly_allowance_cents bigint[],rollover bool,proration bool,PRIMARY KEY(offer_key,version))`)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile("../../supabase/migrations/20261021140415_pro_monthly_offer_version.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), string(seed)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `UPDATE billing_commercial_offer_version SET charge_amount_cents=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), string(seed)); err == nil {
		t.Fatal("conflicting publication silently adopted")
	}
	var amount int64
	if err = pool.QueryRow(t.Context(), `SELECT charge_amount_cents FROM billing_commercial_offer_version`).Scan(&amount); err != nil || amount != 1 {
		t.Fatal(amount, err)
	}
}

func TestRenewalChoiceHTTPCurrentPermissionAndReplay(t *testing.T) {
	s, a, pool := newRenewalPostgresFixture(t, false)
	_, err := pool.Exec(t.Context(), `CREATE TABLE roles(id uuid,scope_type text); CREATE TABLE permissions(id uuid,name text); CREATE TABLE role_permissions(role_id uuid,permission_id uuid); CREATE TABLE team_memberships(team_id uuid,user_id uuid,status text); CREATE TABLE user_role_assignments(user_id uuid,team_id uuid,role_id uuid,scope_type text,revoked_at timestamptz)`)
	if err != nil {
		t.Fatal(err)
	}
	role, read, write := uuid.New(), uuid.New(), uuid.New()
	for _, entry := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO roles VALUES($1,'team')`, []any{role}},
		{`INSERT INTO permissions VALUES($1,'billing:read'),($2,'billing:write')`, []any{read, write}},
		{`INSERT INTO role_permissions VALUES($1,$2),($1,$3)`, []any{role, read, write}},
		{`INSERT INTO team_memberships VALUES($1,$2,'active')`, []any{a.key.Team, a.actor}},
		{`INSERT INTO user_role_assignments VALUES($1,$2,$3,'team',NULL)`, []any{a.actor, a.key.Team, role}},
	} {
		if _, err = pool.Exec(t.Context(), entry.sql, entry.args...); err != nil {
			t.Fatal(err)
		}
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("PROMOTION_ACCOUNT_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	h := &Handlers{Pool: pool, RenewalChoices: s}
	r := gin.New()
	statusPath := "/internal/yc/account/renewals/status"
	submitPath := "/internal/yc/account/renewals/submit"
	r.POST(statusPath, YCRenewalAuth("status"), h.RenewalChoiceStatus)
	r.POST(submitPath, YCRenewalAuth("submit"), h.SubmitRenewalChoice)
	send := func(path string, body []byte, actor uuid.UUID) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("X-YC-Renewal-Assertion", renewalHTTPAssertion(t, key, actor, path, string(body), func(c *renewalChoiceClaims) {
			if path == submitPath {
				c.Operation = "submit"
			}
		}))
		out := httptest.NewRecorder()
		r.ServeHTTP(out, req)
		return out
	}
	statusBody, _ := json.Marshal(map[string]any{"team_id": a.key.Team, "assignment_id": a.key.Assignment})
	var initial renewalChoiceView
	for range 2 {
		out := send(statusPath, statusBody, a.actor)
		if out.Code != 200 {
			t.Fatal(out.Code, out.Body.String())
		}
		if err = json.Unmarshal(out.Body.Bytes(), &initial); err != nil {
			t.Fatal(err)
		}
		if initial.Revision != 1 || initial.Confirmed == nil || initial.Confirmed.Choice != "annual" {
			t.Fatal("status did not bootstrap a single confirmed default", initial)
		}
	}
	req := struct {
		renewalChoiceKey
		renewalChoiceRequest
	}{a.key, renewalChoiceRequest{Acceptance: a.authority.Acceptance, ID: uuid.New(), Choice: "free", ApprovalRevision: a.authority.Revision, ChoiceRevision: 1}}
	body, _ := json.Marshal(req)
	for range 2 {
		out := send(submitPath, body, a.actor)
		if out.Code != 200 {
			t.Fatal(out.Code, out.Body.String())
		}
	}
	if out := send(statusPath, statusBody, uuid.New()); out.Code != 403 {
		t.Fatal("cross actor", out.Code, out.Body.String())
	}
	if _, err = pool.Exec(t.Context(), `UPDATE user_role_assignments SET revoked_at=now()`); err != nil {
		t.Fatal(err)
	}
	if out := send(statusPath, statusBody, a.actor); out.Code != 403 {
		t.Fatal("stale read authority", out.Code, out.Body.String())
	}
	if out := send(submitPath, body, a.actor); out.Code != 403 {
		t.Fatal("revoked replay", out.Code, out.Body.String())
	}
}

func TestRenewalChoicePostgresStagedRestart(t *testing.T) {
	s, a, pool := newRenewalPostgresFixture(t)
	submitRenewal(t, s, a, "free")
	p := &fixtureRenewalSteps{fixtureRenewalProvider: &fixtureRenewalProvider{}, loseCreate: true, observed: true, now: func() renewalChoiceProof {
		var at time.Time
		if err := pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return renewalChoiceProof{VerifiedAt: at}
	}}
	s.Provider = p
	for range 2 {
		if err := s.reconcile(t.Context(), a.key); err != nil {
			t.Fatal(err)
		}
	}
	restart := &renewalChoiceService{Enabled: true, Store: postgresRenewalChoiceStore{Pool: pool}, Authority: a, Provider: p}
	for range 3 {
		if err := restart.reconcile(t.Context(), a.key); err != nil {
			t.Fatal(err)
		}
	}
	j, err := restart.status(t.Context(), a.key, a.actor)
	if err != nil {
		t.Fatal(err)
	}
	if p.calls.Load() != 2 || j.Confirmed.Request.Choice != "free" || len(j.Confirmed.Steps) != 2 || j.Confirmed.Steps[0].Request.Kind != "create_schedule" || j.Confirmed.Steps[1].Request.Kind != "update_schedule" {
		t.Fatal("restart lost stage identity", j)
	}
	if j.OwnedSchedule == nil || j.OwnedSchedule.Operation != j.Confirmed.ID || j.OwnedSchedule.Proof.Schedule != "sub_sched_owned" {
		t.Fatal("restart lost durable creation ownership", j)
	}
	owned := renewalHash(j.OwnedSchedule)
	if _, err = restart.submit(t.Context(), a.key, a.actor, renewalChoiceRequest{ID: uuid.New(), Choice: "annual", Acceptance: a.authority.Acceptance, ApprovalRevision: a.authority.Revision, ChoiceRevision: j.Revision}); err != nil {
		t.Fatal(err)
	}
	j, err = restart.status(t.Context(), a.key, a.actor)
	if err != nil || renewalHash(j.OwnedSchedule) != owned {
		t.Fatal("new generation replaced schedule ownership", j, err)
	}
}
