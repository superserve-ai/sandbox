//go:build integration

package api

import (
	"testing"
	"time"
)

func TestRenewalChoiceRuntimeScopeRejectsOtherBindings(t *testing.T) {
	a, _, r, f, _, actor := newRenewalAcceptedPairFixture(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	live := f.p.Identity.Live
	a.Merchant, a.Live = f.p.Identity.Merchant, &live
	if _, err := a.Locate(t.Context(), r.TeamID, *r.AssignmentID, actor); err != nil {
		t.Fatal(err)
	}
	a.Merchant = "acct_other"
	if _, err := a.Locate(t.Context(), r.TeamID, *r.AssignmentID, actor); err == nil {
		t.Fatal("another merchant admitted")
	}
	a.Merchant, live = f.p.Identity.Merchant, !live
	if _, err := a.Locate(t.Context(), r.TeamID, *r.AssignmentID, actor); err == nil {
		t.Fatal("another provider mode admitted")
	}
}
