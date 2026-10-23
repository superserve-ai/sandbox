//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

// Only provider configuration and execution are fixtures; admission, acceptance,
// assignment, the durable consumer and provisioning journal use real adapters.
type acceptedJournalAuthority struct {
	admission *YCAcceptedProvisioningAdmission
}

func (a acceptedJournalAuthority) WithAcceptedOffer(ctx context.Context, team, assignment uuid.UUID, f func(context.Context, pgx.Tx, provisioning.AcceptedOffer) error) error {
	return a.admission.WithAcceptedOffer(ctx, team, assignment, func(guardCtx context.Context, tx pgx.Tx, o provisioning.AcceptedOffer) error {
		return f(guardCtx, tx, acceptedJournalMapping(o))
	})
}
func (a acceptedJournalAuthority) WithDispatchGuard(ctx context.Context, team, assignment uuid.UUID, f func(context.Context, provisioning.AcceptedOffer) error) error {
	return a.admission.WithDispatchGuard(ctx, team, assignment, func(guardCtx context.Context, o provisioning.AcceptedOffer) error {
		return f(guardCtx, acceptedJournalMapping(o))
	})
}
func acceptedJournalMapping(o provisioning.AcceptedOffer) provisioning.AcceptedOffer {
	o.Merchant = "acct_synthetic"
	o.APIVersion = "synthetic-version"
	o.ProviderTerms = json.RawMessage(`{"fixture":true}`)
	return o
}
func (acceptedJournalAuthority) Finalize(context.Context, pgx.Tx, provisioning.Operation, provisioning.Verification) error {
	return provisioning.ErrUnavailable
}
func (acceptedJournalAuthority) Readiness(context.Context, provisioning.Operation) (provisioning.Readiness, error) {
	return provisioning.Readiness{}, nil
}

type acceptanceNoProvider struct{ calls int }

func (*acceptanceNoProvider) Preflight(context.Context, provisioning.SavedRequest) error {
	return provisioning.ErrUnavailable
}

func (*acceptanceNoProvider) Prepare(context.Context, provisioning.Operation, provisioning.Step) (provisioning.Request, error) {
	return provisioning.Request{}, provisioning.ErrUnavailable
}
func (p *acceptanceNoProvider) Create(context.Context, provisioning.SavedRequest) (json.RawMessage, error) {
	p.calls++
	return nil, provisioning.ErrUnavailable
}
func (*acceptanceNoProvider) Recover(context.Context, provisioning.SavedRequest) (json.RawMessage, error) {
	return nil, provisioning.ErrUnavailable
}
func (*acceptanceNoProvider) Verify(context.Context, provisioning.Operation) (provisioning.Verification, error) {
	return provisioning.Verification{}, provisioning.ErrUnavailable
}

type acceptanceLostJournalAck struct {
	ycAcceptanceProvisioner
	lose bool
}

func (p *acceptanceLostJournalAck) Enqueue(ctx context.Context, team, assignment uuid.UUID) (uuid.UUID, error) {
	id, err := p.ycAcceptanceProvisioner.Enqueue(ctx, team, assignment)
	if err == nil && p.lose {
		p.lose = false
		return uuid.Nil, errors.New("synthetic lost journal acknowledgement")
	}
	return id, err
}

func TestYCAcceptanceRealConsumerReachesProvisioningJournal(t *testing.T) {
	s, r := acceptedCatalogFixture(t)
	ctx := t.Context()
	h := s.Catalog.(ycAcceptedCatalog).h
	admission := &YCAcceptedProvisioningAdmission{Service: s, Handlers: h}
	provider := &acceptanceNoProvider{}
	journal := &provisioning.Service{Pool: s.Pool, Authority: acceptedJournalAuthority{admission: admission}, Provider: provider}
	port := &acceptanceLostJournalAck{ycAcceptanceProvisioner: ycAcceptanceProvisioner{service: journal}, lose: true}
	s.Provisioning = port
	if work, err := s.RunOnce(ctx); !work || err == nil {
		t.Fatal("lost durable enqueue acknowledgement not surfaced", work, err)
	}
	var operation, assignment uuid.UUID
	var frozen provisioning.AcceptedOffer
	var raw []byte
	if err := s.Pool.QueryRow(ctx, `SELECT id,assignment_id,accepted_offer FROM billing_offer_provisioning_operation WHERE team_id=$1`, r.TeamID).Scan(&operation, &assignment, &raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &frozen); err != nil || frozen.AcceptanceID != r.ID || frozen.TermsDigest != r.TermsDigest {
		t.Fatal("journal lost accepted identity", frozen, err)
	}
	// Even while the local acknowledgement is missing, controls must route to the
	// provisioner rather than claim a competing acceptance-level hold succeeded.
	if err := s.control(ctx, uuid.New(), ycAcceptanceControl{RequestID: uuid.New(), AcceptanceID: r.ID, Action: "hold", Reason: "Synthetic hold after handoff"}); err == nil {
		t.Fatal("acceptance hold overtook provisioner journal")
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET next_attempt_at=now() WHERE id=$1`, r.ID); err != nil {
		t.Fatal(err)
	}
	restarted := *s
	if work, err := restarted.RunOnce(ctx); !work || err != nil {
		t.Fatal("restart failed to replay actual journal", work, err)
	}
	current, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
	if err != nil || current.OperationID == nil || *current.OperationID != operation || current.AssignmentID == nil || *current.AssignmentID != assignment || current.State != "dispatched" {
		t.Fatal("handoff identities diverged", current, err)
	}
	status, err := s.Status(ctx, r.UserID, r.TeamID, r.ClaimID)
	if err != nil || status.State != "provisioning" || status.Ready || provider.calls != 0 {
		t.Fatal("journal metadata implied provider readiness", status, err)
	}
	if _, err = s.Shared.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	called := false
	if err = admission.WithDispatchGuard(ctx, r.TeamID, assignment, func(context.Context, provisioning.AcceptedOffer) error { called = true; return nil }); err == nil || called {
		t.Fatal("pending journal authorized revoked dispatch", err)
	}
}

func TestYCAcceptanceAdmissionLostSharedSessionNeverAuthorizesDispatch(t *testing.T) {
	s, r := acceptedCatalogFixture(t)
	ctx := t.Context()
	h := s.Catalog.(ycAcceptedCatalog).h
	admission := &YCAcceptedProvisioningAdmission{Service: s, Handlers: h}
	journal := &provisioning.Service{Pool: s.Pool, Authority: acceptedJournalAuthority{admission: admission}, Provider: &acceptanceNoProvider{}}
	s.Provisioning = ycAcceptanceProvisioner{service: journal}
	if _, err := s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	config := s.Shared.Config()
	name := "acceptance-guard-loss-" + uuid.NewString()
	config.ConnConfig.RuntimeParams["application_name"] = name
	shared, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	s.Shared = shared
	var before, after int
	count := func(out *int) {
		t.Helper()
		if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_commercial_offer_audit WHERE team_id=$1`, r.TeamID).Scan(out); err != nil {
			t.Fatal(err)
		}
	}
	count(&before)
	err = admission.WithAcceptedOffer(ctx, r.TeamID, *current.AssignmentID, func(guardCtx context.Context, tx pgx.Tx, _ provisioning.AcceptedOffer) error {
		if _, e := tx.Exec(guardCtx, `INSERT INTO billing_commercial_offer_audit(team_id,actor_id,action,assignment_id) VALUES($1,$2,'preflight',$3)`, r.TeamID, r.UserID, *current.AssignmentID); e != nil {
			return e
		}
		var terminated bool
		return s.Pool.QueryRow(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1 AND state='idle in transaction'`, name).Scan(&terminated)
	})
	if err == nil {
		t.Fatal("lost shared session reported success")
	}
	count(&after)
	if after != before+1 {
		t.Fatal("fixture did not exercise regional commit before lost shared acknowledgement", before, after)
	}
	if _, err = s.Pool.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	called := false
	err = admission.WithDispatchGuard(ctx, r.TeamID, *current.AssignmentID, func(context.Context, provisioning.AcceptedOffer) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("pending regional commit substituted for fresh dispatch authority", err)
	}
}

func TestYCAcceptanceDispatchPropagatesGuardCancellation(t *testing.T) {
	s, r := acceptedCatalogFixture(t)
	ctx := t.Context()
	h := s.Catalog.(ycAcceptedCatalog).h
	admission := &YCAcceptedProvisioningAdmission{Service: s, Handlers: h}
	journal := &provisioning.Service{Pool: s.Pool, Authority: acceptedJournalAuthority{admission: admission}, Provider: &acceptanceNoProvider{}}
	s.Provisioning = ycAcceptanceProvisioner{service: journal}
	if _, err := s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(ctx)
	defer cancel()
	called := false
	err = admission.WithDispatchGuard(parent, r.TeamID, *current.AssignmentID, func(guardCtx context.Context, _ provisioning.AcceptedOffer) error {
		called = true
		if deadline, ok := guardCtx.Deadline(); !ok || time.Until(deadline) > 20*time.Second {
			t.Error("dispatch context lost bounded guard deadline")
		}
		cancel()
		return guardCtx.Err()
	})
	if !called || !errors.Is(err, context.Canceled) {
		t.Fatal("guard cancellation did not reach dispatch", called, err)
	}
}

func TestYCAcceptanceExhaustedHandoffRecoversExactJournal(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(fmt.Sprintf("crash_%v", crash), func(t *testing.T) {
			s, r := acceptedCatalogFixture(t)
			ctx := t.Context()
			h := s.Catalog.(ycAcceptedCatalog).h
			admission := &YCAcceptedProvisioningAdmission{Service: s, Handlers: h}
			journal := &provisioning.Service{Pool: s.Pool, Authority: acceptedJournalAuthority{admission: admission}, Provider: &acceptanceNoProvider{}}
			port := &acceptanceLostJournalAck{ycAcceptanceProvisioner: ycAcceptanceProvisioner{service: journal}, lose: true}
			s.Provisioning = port
			if _, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET attempts=7 WHERE id=$1`, r.ID); err != nil {
				t.Fatal(err)
			}
			if work, err := s.RunOnce(ctx); !work || err == nil {
				t.Fatal("last acknowledgement failure not injected", work, err)
			}
			var original uuid.UUID
			if err := s.Pool.QueryRow(ctx, `SELECT id FROM billing_offer_provisioning_operation WHERE team_id=$1`, r.TeamID).Scan(&original); err != nil {
				t.Fatal(err)
			}
			if crash {
				if _, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET state='assignment_linked',lease_id=$2,lease_until=now()-interval '1 second' WHERE id=$1`, r.ID, uuid.New()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Pool.Exec(ctx, `UPDATE yc_offer_acceptance SET next_attempt_at=now() WHERE id=$1`, r.ID); err != nil {
				t.Fatal(err)
			}
			// Revocation must not prevent recording an already-existing operation; it
			// still blocks all future dispatch and fresh readiness.
			if _, err := s.Shared.Exec(ctx, `SELECT public.revoke_yc_activation_authority($1,$2,$3)`, r.ApprovalID, r.TeamID, uuid.New()); err != nil {
				t.Fatal(err)
			}
			if work, err := s.RunOnce(ctx); !work || err != nil {
				t.Fatal("exhausted acknowledgement did not recover", work, err)
			}
			current, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
			if err != nil || current.OperationID == nil || *current.OperationID != original || current.State != "dispatched" {
				t.Fatal("recovery did not link original journal", current, err)
			}
			var count int
			if err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM billing_offer_provisioning_operation WHERE team_id=$1`, r.TeamID).Scan(&count); err != nil || count != 1 {
				t.Fatal("recovery duplicated journal", count, err)
			}
		})
	}
}

func TestYCAcceptancePendingAdmissionRejectsBenefitFinalization(t *testing.T) {
	s, r := acceptedCatalogFixture(t)
	ctx := t.Context()
	h := s.Catalog.(ycAcceptedCatalog).h
	admission := &YCAcceptedProvisioningAdmission{Service: s, Handlers: h}
	journal := &provisioning.Service{Pool: s.Pool, Authority: acceptedJournalAuthority{admission: admission}, Provider: &acceptanceNoProvider{}}
	s.Provisioning = ycAcceptanceProvisioner{service: journal}
	if _, err := s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	err = admission.WithAcceptedOffer(ctx, r.TeamID, *current.AssignmentID, func(guardCtx context.Context, tx pgx.Tx, _ provisioning.AcceptedOffer) error {
		_, e := tx.Exec(guardCtx, `UPDATE billing_offer_provisioning_operation SET finalized_at=clock_timestamp(),verification='{}',state='grant_pending' WHERE id=$1`, *current.OperationID)
		return e
	})
	if !errors.Is(err, provisioning.ErrUnavailable) {
		t.Fatal("pending admission accepted finalization", err)
	}
	var finalized bool
	if err = s.Pool.QueryRow(ctx, `SELECT finalized_at IS NOT NULL FROM billing_offer_provisioning_operation WHERE id=$1`, *current.OperationID).Scan(&finalized); err != nil || finalized {
		t.Fatal("finalization escaped pending-only transaction", finalized, err)
	}
}

func TestYCAcceptanceFinancialValidatorUsesCallerTransaction(t *testing.T) {
	s, r := acceptedCatalogFixture(t)
	ctx := t.Context()
	h := s.Catalog.(ycAcceptedCatalog).h
	admission := &YCAcceptedProvisioningAdmission{Service: s, Handlers: h}
	journal := &provisioning.Service{Pool: s.Pool, Authority: acceptedJournalAuthority{admission: admission}, Provider: &acceptanceNoProvider{}}
	s.Provisioning = ycAcceptanceProvisioner{service: journal}
	if _, err := s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO profile(id,email) VALUES($1,$2)`, []any{r.UserID, r.UserID.String() + "@example.test"}},
		{`INSERT INTO team_memberships(team_id,user_id) VALUES($1,$2)`, []any{r.TeamID, r.UserID}},
		{`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, []any{r.UserID, r.TeamID}},
	} {
		if _, err = s.Pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	receipt, err := s.IssueFinancialAuthorization(ctx, r, "initial", *r.OperationID, r.TermsDigest)
	if err != nil {
		t.Fatal(err)
	}
	var frozen provisioning.AcceptedOffer
	var raw []byte
	if err = s.Pool.QueryRow(ctx, `SELECT accepted_offer FROM billing_offer_provisioning_operation WHERE id=$1`, *r.OperationID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	operation := provisioning.Operation{ID: *r.OperationID, TeamID: r.TeamID, AssignmentID: *r.AssignmentID, Offer: frozen}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackYCAcceptance(ctx, tx)
	// Taking every remaining pool connection proves the validator never needs one.
	held := []*pgxpool.Conn{}
	for s.Pool.Stat().AcquiredConns() < s.Pool.Stat().MaxConns() {
		c, e := s.Pool.Acquire(ctx)
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Release()
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	offer, err := admission.ValidateFinancialAcceptance(bounded, tx, operation, receipt)
	if err != nil || offer.AcceptanceID != r.ID || string(offer.Snapshot) == "" {
		t.Fatal("SQL-only validator", err)
	}
	changed := receipt
	changed.TargetTermsDigest = r.RenewalTermsDigest
	if _, err = admission.ValidateFinancialAcceptance(bounded, tx, operation, changed); err == nil {
		t.Fatal("changed target accepted")
	}
	changed = receipt
	changed.InvalidatedAt = &receipt.AuthorizedAt
	if _, err = admission.ValidateFinancialAcceptance(bounded, tx, operation, changed); err == nil {
		t.Fatal("historical invalid receipt accepted")
	}
	if _, err = tx.Exec(ctx, `UPDATE user_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND team_id=$2`, r.UserID, r.TeamID); err != nil {
		t.Fatal(err)
	}
	if _, err = admission.ValidateFinancialAcceptance(bounded, tx, operation, receipt); err == nil {
		t.Fatal("used cached permission or another transaction")
	}
	// The method never committed: rollback restores this permission mutation.
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range held {
		c.Release()
	}
	held = nil
	var active bool
	if err = s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_role_assignments WHERE user_id=$1 AND team_id=$2 AND revoked_at IS NULL)`, r.UserID, r.TeamID).Scan(&active); err != nil || !active {
		t.Fatal("validator committed caller transaction", active, err)
	}
}

func (acceptedJournalAuthority) WithFinalization(context.Context, provisioning.Operation, func(context.Context, pgx.Tx, provisioning.AcceptedOffer) error) error {
	return provisioning.ErrUnavailable
}
