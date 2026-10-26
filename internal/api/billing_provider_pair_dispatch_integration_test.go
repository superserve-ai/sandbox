//go:build integration

package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

type pairDispatchTransport func(*http.Request) (*http.Response, error)

func (f pairDispatchTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProviderPairDispatchWaitsForPausedSender(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		name := "before_post"
		if accepted {
			name = "accepted_before_response"
		}
		t.Run(name, func(t *testing.T) {
			f := newPairWorkerFixture(t)
			client := f.h.Stripe.(*stripeHTTPClient)
			transport := client.httpClient.Transport
			if transport == nil {
				transport = http.DefaultTransport
			}
			paused, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			client.httpClient.Transport = pairDispatchTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/billing/credit_grants" {
					return transport.RoundTrip(r)
				}
				var response *http.Response
				var err error
				if accepted {
					response, err = transport.RoundTrip(r)
				}
				close(paused)
				<-release
				if accepted {
					return response, err
				}
				return transport.RoundTrip(r)
			})
			done := make(chan error, 1)
			go func() { _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); done <- err }()
			select {
			case <-paused:
			case <-time.After(5 * time.Second):
				t.Fatal("sender did not pause")
			}
			f.revoke(t)
			// A reclaimed work lease cannot discharge the durable external admission.
			if _, err := f.h.Pool.Exec(t.Context(), `UPDATE billing_entitlement_work SET lease_until=clock_timestamp()-interval '1 second' WHERE contract_id=$1`, f.b.ContractID); err != nil {
				t.Fatal(err)
			}
			if err := CheckProviderPairDispatchesResolved(t.Context(), f.h.Pool, f.b); !errors.Is(err, errProviderPairDispatchPending) {
				t.Fatal("paused sender allowed ACK", err)
			}
			e, err := f.h.DB.GetCurrentUsageEntitlement(t.Context(), db.GetCurrentUsageEntitlementParams{TeamID: f.b.Identity.TeamID, Kind: "metered_usage"})
			if err != nil {
				t.Fatal(err)
			}
			c, err := f.h.DB.GetCommercialContract(t.Context(), db.GetCommercialContractParams{TeamID: f.b.Identity.TeamID, ContractID: f.b.ContractID})
			if err != nil {
				t.Fatal(err)
			}
			err = f.h.discoverUsageEntitlement(t.Context(), c, e, client)
			if accepted && !errors.Is(err, errProviderPairDispatchPending) {
				t.Fatal("positive GET replaced sender-finished evidence", err)
			}
			if !accepted && !errors.Is(err, errEntitlementNotFound) {
				t.Fatal("missing grant recovery", err)
			}
			if err := CheckProviderPairDispatchesResolved(t.Context(), f.h.Pool, f.b); !errors.Is(err, errProviderPairDispatchPending) {
				t.Fatal("read recovery released sender", err)
			}
			once.Do(func() { close(release) })
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if err = CheckProviderPairDispatchesResolved(t.Context(), f.h.Pool, f.b); err != nil {
				t.Fatal("finished exact grant blocked ACK", err)
			}
			if _, err = f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); err != nil {
				t.Fatal(err)
			}
			if f.posts.Load() != 1 {
				t.Fatal("late worker duplicated grant", f.posts.Load())
			}
			altered := f.b
			altered.Identity.ApprovalSemanticRevision++
			if CheckProviderPairDispatchesResolved(t.Context(), f.h.Pool, altered) == nil {
				t.Fatal("mismatched binding allowed ACK")
			}
		})
	}
}

type lostPairAdmissionCommit struct {
	inner ProviderPairEntitlementAuthority
	h     *Handlers
}

func (a lostPairAdmissionCommit) WithProviderPairAuthority(ctx context.Context, b ContractProviderBinding, action func(context.Context, pgx.Tx) error) error {
	if err := a.inner.WithProviderPairAuthority(ctx, b, action); err != nil {
		return err
	}
	var admitted bool
	if err := a.h.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_provider_pair_dispatch WHERE contract_id=$1)`, b.ContractID).Scan(&admitted); err != nil {
		return err
	}
	if admitted {
		return errors.New("injected lost admission commit response")
	}
	return nil
}

func TestProviderPairDispatchLostAdmissionNeverTransfersSendPermission(t *testing.T) {
	f := newPairWorkerFixture(t)
	f.h.ProviderPairEntitlementAuthority = lostPairAdmissionCommit{f.authority, f.h}
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); err == nil {
		t.Fatal("missing commit failure")
	}
	f.h.ProviderPairEntitlementAuthority = f.authority
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); !errors.Is(err, errProviderPairDispatchPending) {
		t.Fatal("retry inherited send permit", err)
	}
	if f.posts.Load() != 0 {
		t.Fatal("unconfirmed admission sent", f.posts.Load())
	}
	f.revoke(t)
	if err := CheckProviderPairDispatchesResolved(t.Context(), f.h.Pool, f.b); !errors.Is(err, errProviderPairDispatchPending) {
		t.Fatal("unknown admission released ACK", err)
	}
	var count int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT count(*) FROM billing_provider_pair_dispatch WHERE contract_id=$1`, f.b.ContractID).Scan(&count); err != nil || count != 1 {
		t.Fatal("attempt replaced", count, err)
	}
}

func TestProviderPairDispatchLostResponseRequiresPositiveRecovery(t *testing.T) {
	f := newPairWorkerFixture(t)
	f.lost.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); err == nil {
		t.Fatal("missing response failure")
	}
	var finished bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT sender_finished_at IS NOT NULL FROM billing_provider_pair_dispatch WHERE contract_id=$1`, f.b.ContractID).Scan(&finished); err != nil || !finished {
		t.Fatal("sender return not persisted", err)
	}
	f.revoke(t)
	if err := CheckProviderPairDispatchesResolved(t.Context(), f.h.Pool, f.b); !errors.Is(err, errProviderPairDispatchPending) {
		t.Fatal("unknown response allowed ACK", err)
	}
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); err != nil {
		t.Fatal(err)
	}
	if err := CheckProviderPairDispatchesResolved(t.Context(), f.h.Pool, f.b); err != nil {
		t.Fatal(err)
	}
	if f.posts.Load() != 1 {
		t.Fatal("recovery sent replacement", f.posts.Load())
	}
}

func TestProviderPairDispatchBackendRolePermissions(t *testing.T) {
	f := newPairWorkerFixture(t)
	var privileged bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname='service_role'`).Scan(&privileged); err != nil || privileged {
		t.Fatal("backend permission test requires an unprivileged role", privileged, err)
	}
	f.lost.Store(true)
	if _, err := f.h.reconcileUsageEntitlement(t.Context(), f.b.ContractID); err == nil {
		t.Fatal("expected lost response")
	}
	// Roll back the test-only delete so the role must perform a real admission insert.
	tx, err := f.h.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `CREATE TEMP TABLE dispatch_copy AS SELECT * FROM billing_provider_pair_dispatch WHERE contract_id=$1`, f.b.ContractID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `ALTER TABLE billing_provider_pair_dispatch DISABLE TRIGGER billing_provider_pair_dispatch_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `DELETE FROM billing_provider_pair_dispatch WHERE contract_id=$1`, f.b.ContractID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `ALTER TABLE billing_provider_pair_dispatch ENABLE TRIGGER billing_provider_pair_dispatch_guard; GRANT SELECT ON dispatch_copy TO service_role; SET LOCAL ROLE service_role`); err != nil {
		t.Fatal(err)
	}
	var canDelete bool
	if err = tx.QueryRow(t.Context(), `SELECT has_table_privilege(current_user,'billing_provider_pair_dispatch','DELETE')`).Scan(&canDelete); err != nil || canDelete {
		t.Fatal("backend DELETE permitted", err)
	}
	if _, err = tx.Exec(t.Context(), `INSERT INTO billing_provider_pair_dispatch(id,entitlement_id,contract_id,team_id,binding,request_payload,request_form,idempotency_key) SELECT id,entitlement_id,contract_id,team_id,binding,request_payload,request_form,idempotency_key FROM dispatch_copy`); err != nil {
		t.Fatal("backend admission", err)
	}
	if _, err = tx.Exec(t.Context(), `UPDATE billing_provider_pair_dispatch SET sender_finished_at=clock_timestamp() WHERE contract_id=$1`, f.b.ContractID); err != nil {
		t.Fatal("backend sender completion", err)
	}
	if err = CheckProviderPairDispatchesResolved(t.Context(), tx, f.b); !errors.Is(err, errProviderPairDispatchPending) {
		t.Fatal("backend resolution read", err)
	}
}
