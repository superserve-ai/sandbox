//go:build integration

package api

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/authz"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

func newRenewalAcceptedPairFixture(t *testing.T, anchor time.Time) (*acceptedRenewalAuthority, *Handlers, YCAcceptanceRecord, *pairFixture, *stripeHTTPClient, uuid.UUID) {
	t.Helper()
	s, r := acceptedCatalogFixture(t)
	h := s.Catalog.(ycAcceptedCatalog).h
	admission := &YCAcceptedProvisioningAdmission{Service: s, Handlers: h}
	journal := &provisioning.Service{Pool: s.Pool, Authority: acceptedJournalAuthority{admission: admission}, Provider: &acceptanceNoProvider{}}
	s.Provisioning = ycAcceptanceProvisioner{service: journal}
	if _, err := s.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := loadYCAcceptance(t.Context(), s.Pool, r.TeamID, r.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	if r.AssignmentID == nil || r.OperationID == nil {
		t.Fatal("real accepted assignment missing")
	}
	requester := uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO profile(id,email) VALUES($1,$2)`, []any{requester, requester.String() + "@example.test"}},
		{`INSERT INTO team_memberships(team_id,user_id) VALUES($1,$2)`, []any{r.TeamID, requester}},
		{`INSERT INTO user_role_assignments(user_id,role_id,scope_type,team_id) SELECT $1,id,'team',$2 FROM roles WHERE name='team_owner'`, []any{requester, r.TeamID}},
	} {
		if _, err = s.Pool.Exec(t.Context(), q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	s.Authorize = func(ctx context.Context, user, team uuid.UUID) error {
		return authz.New(s.Pool).RequireTeamPermission(ctx, user, team, "billing:write")
	}
	if err = s.Authorize(t.Context(), r.UserID, r.TeamID); err == nil {
		t.Fatal("original user unexpectedly has regional billing permission")
	}
	f := newPairFixture(t)
	f.p.Identity.OperationID, f.p.Identity.TeamID, f.p.Identity.AssignmentID, f.p.Identity.AcceptanceID = *r.OperationID, r.TeamID, *r.AssignmentID, r.ID
	f.p.Identity.ApprovalSemanticRevision, f.p.Identity.TermsDigest = r.ApprovalRevision, r.TermsDigest
	f.p.Anchor = anchor
	f.fee.StartDate, f.fee.BillingCycleAnchor = f.p.Anchor.Unix(), f.p.Anchor.Unix()
	f.fee.Items.Data[0].Start, f.fee.Items.Data[0].End = f.p.Anchor.Unix(), annualBoundary(f.p.Anchor, 12).Unix()
	f.usage.StartDate, f.usage.BillingCycleAnchor = f.p.Anchor.Unix(), f.p.Anchor.Unix()
	for i := range f.usage.Items.Data {
		f.usage.Items.Data[i].Start, f.usage.Items.Data[i].End = f.p.Anchor.Unix(), annualBoundary(f.p.Anchor, 1).Unix()
		if i < 3 {
			var amount string
			if err = s.Pool.QueryRow(t.Context(), `SELECT ((x->>'price_usd')::numeric*360000)::text FROM billing_commercial_offer_assignment a CROSS JOIN LATERAL jsonb_array_elements(a.resource_rates) x WHERE a.id=$1 AND x->>'resource'=$2`, *r.AssignmentID, f.p.Terms.Resources[i].ResourceKey).Scan(&amount); err != nil {
				t.Fatal(err)
			}
			f.p.Terms.Resources[i].UnitAmountDecimal = amount
			f.usage.Items.Data[i].Price.UnitAmountDecimal = amount
		}
	}
	f.fee.Metadata, f.usage.Metadata = pairMetadata(f.p.Identity, "fee"), pairMetadata(f.p.Identity, "usage")
	f.invoice.Lines.Data[0].Period.Start, f.invoice.Lines.Data[0].Period.End = f.p.Anchor.Unix(), annualBoundary(f.p.Anchor, 12).Unix()
	f.p.Identity.ProviderTermsDigest, _ = f.p.Terms.Digest()
	client := f.client(t)
	verified, err := client.verifyInitialProviderPair(t.Context(), f.p)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), `UPDATE team_billing_account SET stripe_customer_id=$2,stripe_subscription_id=$3,commercial_billing_anchor=$4 WHERE team_id=$1`, r.TeamID, f.p.CustomerID, f.p.UsageSubscriptionID, f.p.Anchor); err != nil {
		t.Fatal(err)
	}
	// This fixture establishes the real immutable pair for authority/read tests;
	// financial-finalization orchestration is tested separately by its owner.
	if _, err = ActivateInitialProviderPair(t.Context(), tx, uuid.New(), verified); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	authority := &acceptedRenewalAuthority{Admission: admission, Verifier: &stripeRenewalScheduleVerifier{Pool: s.Pool, Client: client}}
	return authority, h, r, f, client, requester
}

func TestRenewalChoiceAcceptedAuthorityUsesCurrentRequester(t *testing.T) {
	authority, _, r, _, _, requester := newRenewalAcceptedPairFixture(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	s := authority.Admission.Service
	renewal := &renewalChoiceService{Enabled: true, Store: postgresRenewalChoiceStore{Pool: s.Pool}, Authority: authority, Provider: &renewalScheduleProvider{Verifier: authority.Verifier}}
	view, err := renewal.currentView(t.Context(), r.TeamID, *r.AssignmentID, requester)
	if err != nil || view.Confirmed == nil || view.Confirmed.Choice != "annual" {
		t.Fatal("authorized successor requester denied", view, err)
	}
	var k renewalChoiceKey
	k, err = authority.Locate(t.Context(), r.TeamID, *r.AssignmentID, requester)
	if err != nil {
		t.Fatal(err)
	}
	state, err := renewal.status(t.Context(), k, requester)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err = authority.DispatchGuard(t.Context(), k, *state.Confirmed, func(context.Context) error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatal("current requester guard failed", err, calls)
	}
	if _, err = s.Pool.Exec(t.Context(), `DELETE FROM user_role_assignments WHERE user_id=$1 AND team_id=$2`, requester, r.TeamID); err != nil {
		t.Fatal(err)
	}
	if err = authority.DispatchGuard(t.Context(), k, *state.Confirmed, func(context.Context) error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatal("revoked requester dispatched", err, calls)
	}
	if _, err = renewal.view(t.Context(), k, requester); err == nil {
		t.Fatal("revoked requester read billing choices")
	}
}
