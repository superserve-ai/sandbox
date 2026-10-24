//go:build integration

package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testAuthority struct {
	pool            *pgxpool.Pool
	offer           AcceptedOffer
	reject          bool
	beforeGuard     func()
	guardErrorAfter bool
	callbackContext func(context.Context) context.Context
}

func (a *testAuthority) WithDispatchGuard(ctx context.Context, team, assignment uuid.UUID, f func(context.Context, AcceptedOffer) error) error {
	if a.callbackContext != nil {
		ctx = a.callbackContext(ctx)
	}
	if a.beforeGuard != nil {
		a.beforeGuard()
	}
	if a.reject {
		return ErrRevoked
	}
	err := f(ctx, a.offer)
	if a.guardErrorAfter && err == nil {
		return ErrUnknown
	}
	return err
}

func (a *testAuthority) WithAcceptedOffer(ctx context.Context, team, assignment uuid.UUID, f func(context.Context, pgx.Tx, AcceptedOffer) error) error {
	if a.callbackContext != nil {
		ctx = a.callbackContext(ctx)
	}
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM team WHERE id=$1 FOR NO KEY UPDATE`, team); err != nil {
		return err
	}
	if a.reject {
		return ErrRevoked
	}
	if err = f(ctx, tx, a.offer); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (a *testAuthority) WithFinalization(ctx context.Context, o Operation, f func(context.Context, pgx.Tx, AcceptedOffer) error) error {
	return a.WithAcceptedOffer(ctx, o.TeamID, o.AssignmentID, f)
}
func (a *testAuthority) Finalize(ctx context.Context, tx pgx.Tx, o Operation, e Verification) error {
	_, err := tx.Exec(ctx, `INSERT INTO test_finalization(id) VALUES($1)`, o.ID)
	return err
}
func (a *testAuthority) Readiness(context.Context, Operation) (Readiness, error) {
	return Readiness{}, nil
}

type testProvider struct {
	mu             sync.Mutex
	effects        map[string]json.RawMessage
	creates        map[Step]int
	lost           Step
	recoverUnknown bool
	enter, release chan struct{}
	afterCreate    func(SavedRequest)
	preflightError error
	createContext  func(context.Context) error
}

func (p *testProvider) Prepare(_ context.Context, o Operation, step Step) (Request, error) {
	return NewRequest("/v1/"+string(step), "assignment="+o.AssignmentID.String()), nil
}
func (p *testProvider) Preflight(context.Context, SavedRequest) error { return p.preflightError }
func (p *testProvider) Create(ctx context.Context, r SavedRequest) (json.RawMessage, error) {
	if p.createContext != nil {
		if err := p.createContext(ctx); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	p.creates[r.Step]++
	raw := json.RawMessage(fmt.Sprintf(`{"id":%q}`, r.Key))
	p.effects[r.Key] = raw
	p.mu.Unlock()
	if p.enter != nil && r.Step == Customer {
		close(p.enter)
		<-p.release
	}
	if p.afterCreate != nil {
		p.afterCreate(r)
	}
	if p.lost == r.Step {
		return nil, errors.New("lost response")
	}
	return raw, nil
}
func (p *testProvider) Recover(_ context.Context, r SavedRequest) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recoverUnknown {
		return nil, ErrUnknown
	}
	if v, ok := p.effects[r.Key]; ok {
		return v, nil
	}
	return nil, ErrUnknown
}
func (p *testProvider) Verify(context.Context, Operation) (Verification, error) {
	return Verification{Evidence: json.RawMessage(`{"verified":true}`)}, nil
}

type fixture struct {
	s                    *Service
	a                    *testAuthority
	p                    *testProvider
	team, assignment, id uuid.UUID
}

func newFixture(t *testing.T, snapshot ...json.RawMessage) *fixture {
	t.Helper()
	dsn := os.Getenv("PROVISIONING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("PROVISIONING_TEST_DATABASE_URL must name an isolated local test database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if (cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") || (cfg.ConnConfig.Database != "provisioning_test" && cfg.ConnConfig.Database != "sandbox_test") {
		t.Fatal("refusing non-local/non-test database")
	}
	admin, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	schema := "provision_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(t.Context(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	if _, err = pool.Exec(t.Context(), `CREATE TABLE team(id uuid PRIMARY KEY); CREATE TABLE test_finalization(id uuid PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "supabase", "migrations", "20261021135339_offer_provisioning_journal.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), string(migration)); err != nil {
		t.Fatal(err)
	}
	f := &fixture{team: uuid.New(), assignment: uuid.New()}
	if _, err = pool.Exec(t.Context(), `INSERT INTO team VALUES($1)`, f.team); err != nil {
		t.Fatal(err)
	}
	f.a = &testAuthority{pool: pool, offer: AcceptedOffer{AcceptanceID: uuid.New(), TermsDigest: strings.Repeat("a", 64), Merchant: "acct_example", APIVersion: "verified-fixture-version", Snapshot: json.RawMessage(`{"version":1}`)}}
	if len(snapshot) > 0 {
		f.a.offer.Snapshot = snapshot[0]
	}
	f.p = &testProvider{effects: make(map[string]json.RawMessage), creates: make(map[Step]int)}
	f.s = &Service{Pool: pool, Authority: f.a, Provider: f.p}
	f.id, err = f.s.Enqueue(t.Context(), f.team, f.assignment)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) reconcile(t *testing.T) error {
	t.Helper()
	return f.s.Reconcile(t.Context(), f.team, f.assignment)
}
func (f *fixture) assertOnce(t *testing.T) {
	t.Helper()
	for _, step := range steps {
		if f.p.creates[step] != 1 {
			t.Fatalf("%s creates=%d", step, f.p.creates[step])
		}
	}
	var n int
	if err := f.s.Pool.QueryRow(t.Context(), `SELECT count(*) FROM test_finalization`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}

func TestJournalRecoversEveryCreateBoundaryWithoutReplacement(t *testing.T) {
	for _, step := range steps {
		t.Run(string(step), func(t *testing.T) {
			f := newFixture(t)
			f.p.lost = step
			if err := f.reconcile(t); !errors.Is(err, ErrUnknown) {
				t.Fatal(err)
			}
			var finalized int
			if err := f.s.Pool.QueryRow(t.Context(), `SELECT count(*) FROM test_finalization`).Scan(&finalized); err != nil || finalized != 0 {
				t.Fatal("unknown provider write authorized activation", finalized, err)
			}
			f.p.lost = ""
			// Even after provider idempotency retention, only a read is allowed.
			if _, err := f.s.Pool.Exec(t.Context(), `UPDATE billing_offer_provisioning_operation SET next_check_at=clock_timestamp()-interval '2 days'`); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				if err := f.reconcile(t); err != nil {
					t.Fatal(err)
				}
			}
			f.assertOnce(t)
			got, err := f.s.Status(t.Context(), f.team, f.assignment)
			if err != nil || got.Ready {
				t.Fatal(got, err)
			}
		})
	}
}

func TestJournalProviderSuccessLocalWriteFailure(t *testing.T) {
	for _, step := range steps {
		t.Run(string(step), func(t *testing.T) {
			f := newFixture(t)
			_, err := f.s.Pool.Exec(t.Context(), `CREATE FUNCTION fail_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.receipt IS NOT NULL THEN RAISE EXCEPTION 'simulated storage failure'; END IF; RETURN NEW; END $$;`)
			if err != nil {
				t.Fatal(err)
			}
			f.p.afterCreate = func(r SavedRequest) {
				if r.Step == step {
					_, e := f.s.Pool.Exec(t.Context(), `CREATE TRIGGER receipt_failure BEFORE UPDATE ON billing_offer_provisioning_request FOR EACH ROW EXECUTE FUNCTION fail_receipt()`)
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			if err = f.reconcile(t); err == nil {
				t.Fatal("expected failed receipt persistence")
			}
			if _, err = f.s.Pool.Exec(t.Context(), `DROP TRIGGER receipt_failure ON billing_offer_provisioning_request`); err != nil {
				t.Fatal(err)
			}
			f.p.afterCreate = nil
			if err = f.reconcile(t); err != nil {
				t.Fatal(err)
			}
			f.assertOnce(t)
		})
	}
}

func TestJournalConcurrentAdmissionAndManualRecovery(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := f.s.Enqueue(t.Context(), f.team, f.assignment)
			if err == nil && id != f.id {
				err = ErrConflict
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f.p.enter = make(chan struct{})
	f.p.release = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- f.reconcile(t) }()
	select {
	case <-f.p.enter:
	case <-time.After(5 * time.Second):
		t.Fatal("create did not start")
	}
	if err := f.reconcile(t); err != nil {
		t.Fatal("concurrent read-only recovery", err)
	}
	close(f.p.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f.assertOnce(t)
	f.a.offer.TermsDigest = strings.Repeat("b", 64)
	if _, err := f.s.Enqueue(t.Context(), f.team, f.assignment); !errors.Is(err, ErrConflict) {
		t.Fatal("changed acceptance replay", err)
	}
	if _, err := f.s.Enqueue(t.Context(), f.team, uuid.New()); !errors.Is(err, ErrConflict) {
		t.Fatal("second assignment", err)
	}
}

func TestJournalRevokedUnknownRecoversEvidenceOnly(t *testing.T) {
	f := newFixture(t)
	f.p.lost = Customer
	if err := f.reconcile(t); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	if err := f.s.Control(t.Context(), f.team, f.assignment, uuid.New(), "revoke", "operator test"); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	f.a.reject = true
	if err := f.reconcile(t); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	o, err := load(t.Context(), f.s.Pool, f.team, f.assignment)
	if err != nil {
		t.Fatal(err)
	}
	if o.Requests[Customer].State != "confirmed" || len(f.p.creates) != 1 || o.FinalizedAt != nil {
		t.Fatal(o, f.p.creates)
	}
	if err = f.s.Control(t.Context(), f.team, f.assignment, uuid.New(), "release", "attempt revive"); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
}

func TestJournalUnknownInventoryNeverRecreates(t *testing.T) {
	f := newFixture(t)
	f.p.lost = Customer
	f.p.recoverUnknown = true
	for i := 0; i < 4; i++ {
		if err := f.reconcile(t); !errors.Is(err, ErrUnknown) {
			t.Fatal(err)
		}
	}
	if f.p.creates[Customer] != 1 || len(f.p.creates) != 1 {
		t.Fatal(f.p.creates)
	}
}

func TestJournalDatabaseRejectsIdentityAndHistoryRewrite(t *testing.T) {
	f := newFixture(t)
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE billing_offer_provisioning_operation SET accepted_offer='{}'`,
		`UPDATE billing_offer_provisioning_operation SET finalized_at=NULL,verification=NULL,state='provisioning'`,
		`UPDATE billing_offer_provisioning_request SET request='{}'`,
		`UPDATE billing_offer_provisioning_request SET state='prepared',dispatched_at=NULL,receipt=NULL`,
		`UPDATE billing_offer_provisioning_request SET receipt='{}'`,
		`DELETE FROM billing_offer_provisioning_request`,
	} {
		if _, err := f.s.Pool.Exec(t.Context(), q); err == nil {
			t.Fatal("allowed history rewrite", q)
		}
	}
}

func TestJournalRevocationBeforeAndAfterDispatchMarker(t *testing.T) {
	for _, gap := range []bool{false, true} {
		t.Run(fmt.Sprint(gap), func(t *testing.T) {
			f := newFixture(t)
			if gap {
				f.a.beforeGuard = func() { f.a.reject = true }
			} else {
				f.a.reject = true
			}
			if err := f.reconcile(t); !errors.Is(err, ErrRevoked) {
				t.Fatal(err)
			}
			if len(f.p.creates) != 0 {
				t.Fatal("revocation allowed POST", f.p.creates)
			}
			o, err := load(t.Context(), f.s.Pool, f.team, f.assignment)
			if err != nil {
				t.Fatal(err)
			}
			if gap && o.Requests[Customer].State != "dispatched" {
				t.Fatal("lost unknown dispatch history", o)
			}
		})
	}
}

func TestJournalHoldReportsPendingAttemptAndStopsNextCreate(t *testing.T) {
	f := newFixture(t)
	f.p.enter = make(chan struct{})
	f.p.release = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- f.reconcile(t) }()
	select {
	case <-f.p.enter:
	case <-time.After(5 * time.Second):
		t.Fatal("create did not start")
	}
	if err := f.s.Control(t.Context(), f.team, f.assignment, uuid.New(), "hold", "operator test"); !errors.Is(err, ErrUnknown) {
		t.Fatal("in-flight control falsely acknowledged settled outcome", err)
	}
	status, err := f.s.Status(t.Context(), f.team, f.assignment)
	if err != nil || !status.Held || !status.ControlPending || status.Ready {
		t.Fatal(status, err)
	}
	close(f.p.release)
	if err := <-done; !errors.Is(err, ErrHeld) {
		t.Fatal(err)
	}
	if len(f.p.creates) != 1 || f.p.creates[Customer] != 1 {
		t.Fatal("hold allowed later create", f.p.creates)
	}
}

func TestJournalNumericTermsSurviveJSONB(t *testing.T) {
	f := newFixture(t, json.RawMessage(`{"rate":1e-7,"units":9007199254740993}`))
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.assertOnce(t)
}

func TestJournalMarkedAttemptCannotAcknowledgeCompletedRevocation(t *testing.T) {
	f := newFixture(t)
	f.a.beforeGuard = func() {
		if err := f.s.Control(t.Context(), f.team, f.assignment, uuid.New(), "revoke", "dispatch outcome pending"); !errors.Is(err, ErrUnknown) {
			t.Fatal("uncertain dispatch acknowledged as settled", err)
		}
		status, err := f.s.Status(t.Context(), f.team, f.assignment)
		if err != nil || status.Ready || !status.Revoked || !status.ControlPending || status.State != "outcome_unknown" {
			t.Fatal(status, err)
		}
	}
	if err := f.reconcile(t); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	f.a.beforeGuard = nil
	// A new service instance resumes the same durable operation read-only.
	f.s = &Service{Pool: f.s.Pool, Authority: f.a, Provider: f.p}
	if err := f.reconcile(t); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	status, err := f.s.Status(t.Context(), f.team, f.assignment)
	if err != nil || status.Ready || !status.Revoked || status.ControlPending || status.State != "revoked" {
		t.Fatal(status, err)
	}
	if len(f.p.creates) != 1 || f.p.creates[Customer] != 1 {
		t.Fatal("revocation allowed new step", f.p.creates)
	}
}

func TestJournalRestrictedBackendAndUntrustedRoles(t *testing.T) {
	f := newFixture(t)
	var present bool
	if err := f.s.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role')`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Skip("optional application roles not installed in isolated fixture")
	}
	var schema string
	if err := f.s.Pool.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Pool.Exec(t.Context(), `GRANT USAGE ON SCHEMA `+pgx.Identifier{schema}.Sanitize()+` TO service_role,anon,authenticated`); err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `SET LOCAL ROLE service_role`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE billing_offer_provisioning_operation SET next_check_at=clock_timestamp() WHERE id=$1`, f.id); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `INSERT INTO billing_offer_provisioning_audit(operation_id,actor_id,action,reason) VALUES($1,$2,'hold','test')`, f.id, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"anon", "authenticated"} {
		tx, err := f.s.Pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(t.Context(), `SET LOCAL ROLE `+role); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(t.Context(), `SELECT * FROM billing_offer_provisioning_operation`); err == nil {
			t.Fatal("untrusted role can read private provider journal", role)
		}
		_ = tx.Rollback(t.Context())
	}
}

func TestJournalConfirmationAndControlSerializePendingOutcome(t *testing.T) {
	f := newFixture(t)
	f.p.lost = Customer
	if err := f.reconcile(t); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	barrier, err := f.s.Pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Release()
	if _, err = barrier.Exec(t.Context(), `SELECT pg_advisory_lock(19698966,1)`); err != nil {
		t.Fatal(err)
	}
	defer barrier.Exec(context.Background(), `SELECT pg_advisory_unlock(19698966,1)`)
	_, err = f.s.Pool.Exec(t.Context(), `CREATE FUNCTION delay_confirmation_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(19698966,1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER delay_confirmation_commit AFTER UPDATE ON billing_offer_provisioning_request DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delay_confirmation_commit()`)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := make(chan error, 1)
	go func() { confirmed <- f.s.confirm(t.Context(), f.id, Customer, f.p.effects[key(f.id, Customer)]) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err = f.s.Pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=19698966 AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("confirmation did not reach commit barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}
	controlled := make(chan error, 1)
	go func() {
		controlled <- f.s.Control(t.Context(), f.team, f.assignment, uuid.New(), "revoke", "concurrent confirmation")
	}()
	// With the operation-row fence, control must wait for confirmation's commit.
	select {
	case err = <-controlled:
		t.Fatalf("control bypassed uncommitted confirmation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err = barrier.Exec(t.Context(), `SELECT pg_advisory_unlock(19698966,1)`); err != nil {
		t.Fatal(err)
	}
	if err = <-confirmed; err != nil {
		t.Fatal(err)
	}
	if err = <-controlled; err != nil {
		t.Fatal(err)
	}
	o, err := load(t.Context(), f.s.Pool, f.team, f.assignment)
	if err != nil || o.ControlPending || o.RevokedAt == nil || o.Requests[Customer].State != "confirmed" {
		t.Fatal(o, err)
	}
}

func TestJournalGuardFailureAfterAcceptedPOSTRemainsRecoverable(t *testing.T) {
	f := newFixture(t)
	f.a.guardErrorAfter = true
	if err := f.reconcile(t); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	f.a.guardErrorAfter = false
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.assertOnce(t)
}

func TestJournalFinalizationRollbackPreservesProviderIdentities(t *testing.T) {
	f := newFixture(t)
	_, err := f.s.Pool.Exec(t.Context(), `CREATE FUNCTION fail_finalization() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.finalized_at IS NOT NULL THEN RAISE EXCEPTION 'simulated commit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER finalization_failure BEFORE UPDATE ON billing_offer_provisioning_operation FOR EACH ROW EXECUTE FUNCTION fail_finalization()`)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.reconcile(t); err == nil {
		t.Fatal("expected finalization failure")
	}
	var count int
	if err = f.s.Pool.QueryRow(t.Context(), `SELECT count(*) FROM test_finalization`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial authority escaped rollback", count, err)
	}
	if _, err = f.s.Pool.Exec(t.Context(), `DROP TRIGGER finalization_failure ON billing_offer_provisioning_operation`); err != nil {
		t.Fatal(err)
	}
	if err = f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.assertOnce(t)
}

func singleConnectionPool(t *testing.T, f *fixture) {
	t.Helper()
	cfg := f.s.Pool.Config()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.s.Pool, f.a.pool = pool, pool
}

func TestJournalSingleConnectionPool(t *testing.T) {
	f := newFixture(t)
	singleConnectionPool(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := f.s.Reconcile(ctx, f.team, f.assignment); err != nil {
		t.Fatal(err)
	}
	f.assertOnce(t)
}

func TestJournalSingleConnectionControlCannotStarveDispatch(t *testing.T) {
	f := newFixture(t)
	singleConnectionPool(t, f)
	f.p.enter, f.p.release = make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	reconciled := make(chan error, 1)
	go func() { reconciled <- f.s.Reconcile(ctx, f.team, f.assignment) }()
	select {
	case <-f.p.enter:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Control must use the sole pool slot while the provider request is in flight.
	err := f.s.Control(ctx, f.team, f.assignment, uuid.New(), "hold", "test control")
	close(f.p.release)
	if !errors.Is(err, ErrUnknown) {
		t.Fatal("control must persist pending outcome", err)
	}
	if err := <-reconciled; !errors.Is(err, ErrHeld) {
		t.Fatal(err)
	}
	if len(f.p.creates) != 1 || f.p.creates[Customer] != 1 {
		t.Fatal("control allowed later dispatch", f.p.creates)
	}
}

func TestJournalConcurrentReconcilersClaimEachDispatchOnce(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- f.s.Reconcile(ctx, f.team, f.assignment)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrUnknown) {
			t.Fatal(err)
		}
	}
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.assertOnce(t)
}

func TestJournalProviderTermsPinnedApartFromAcceptance(t *testing.T) {
	f := newFixture(t)
	// The first fixture operation intentionally has no provider terms. Replaying
	// it with newly resolved ambient prices must conflict, not silently enrich it.
	f.a.offer.ProviderTerms = json.RawMessage(`{"fee_price_id":"price_other"}`)
	if _, err := f.s.Enqueue(t.Context(), f.team, f.assignment); !errors.Is(err, ErrConflict) {
		t.Fatal("replay replaced pinned provider mapping", err)
	}
	if err := f.reconcile(t); !errors.Is(err, ErrConflict) {
		t.Fatal("changed provider terms authorized dispatch", err)
	}
	if len(f.p.creates) != 0 {
		t.Fatal("changed provider terms reached provider")
	}
}

func TestJournalPreflightFailureRemainsRetryable(t *testing.T) {
	f := newFixture(t)
	f.p.preflightError = errors.New("temporary preflight read failure")
	if err := f.reconcile(t); err == nil {
		t.Fatal("expected read failure")
	}
	o, err := load(t.Context(), f.s.Pool, f.team, f.assignment)
	if err != nil || o.Requests[Customer].State != "prepared" || o.Requests[Customer].DispatchedAt != nil || len(f.p.creates) != 0 {
		t.Fatal(o, err)
	}
	f.p.preflightError = nil
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.assertOnce(t)
}

func TestJournalProviderUsesDispatchGuardContext(t *testing.T) {
	f := newFixture(t)
	type guardKey struct{}
	f.a.callbackContext = func(ctx context.Context) context.Context { return context.WithValue(ctx, guardKey{}, true) }
	f.p.createContext = func(ctx context.Context) error {
		if ctx.Value(guardKey{}) != true {
			t.Fatal("provider received outer context")
		}
		return nil
	}
	if err := f.reconcile(t); err != nil {
		t.Fatal(err)
	}
	f.assertOnce(t)
}

func TestJournalDispatchGuardCancellationReachesProvider(t *testing.T) {
	f := newFixture(t)
	guard, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.a.callbackContext = func(context.Context) context.Context { return guard }
	f.a.beforeGuard = cancel
	f.p.createContext = func(ctx context.Context) error { return ctx.Err() }
	if err := f.reconcile(t); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	if len(f.p.creates) != 0 {
		t.Fatal("provider ignored guard cancellation")
	}
	o, err := load(t.Context(), f.s.Pool, f.team, f.assignment)
	if err != nil || o.Requests[Customer].State != "dispatched" || o.FinalizedAt != nil {
		t.Fatal(o, err)
	}
}
