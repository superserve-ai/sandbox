package api

import "testing"

func TestPlanChangeRule(t *testing.T) {
	for _, c := range []struct{ from, to, timing string }{
		{planKindFree, planKindPrepaid, planChangeAfterPurchase},
		{planKindFree, planKindSubscription, planChangeAfterPurchase},
		{planKindPrepaid, planKindSubscription, planChangeAfterPurchase},
		{planKindSubscription, planKindPrepaid, planChangeEndOfPeriod},
		{planKindSubscription, planKindFree, planChangeEndOfPeriod},
		{planKindCustom, planKindFree, planChangeEndOfPeriod},
		{planKindPrepaid, planKindFree, planChangeNow},
		{planKindFree, planKindFree, ""},
		{planKindLegacyPAYG, planKindFree, ""},
		{planKindCustom, planKindPrepaid, ""},
	} {
		timing, blocked := planChangeRule(c.from, c.to)
		if timing != c.timing || (timing == "") != (blocked != "") {
			t.Errorf("%s -> %s: got %q %q, want %q", c.from, c.to, timing, blocked, c.timing)
		}
	}
}
