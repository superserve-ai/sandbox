package api

import (
	"math/big"
	"testing"
)

func int32p(v int32) *int32 { return &v }
func int64p(v int64) *int64 { return &v }

func TestExpandPlanScheduleTimedGrants(t *testing.T) {
	yc := []planGrant{
		{StartMonths: 0, Repeat: int32p(3), EveryMonths: 1, AmountCents: 3000000, ExpiresAfterMonths: 1},
		{StartMonths: 3, Repeat: int32p(9), EveryMonths: 1, AmountCents: 100000, ExpiresAfterMonths: 1},
	}
	issues := expandPlanSchedule(yc, 24)
	if len(issues) != 12 {
		t.Fatalf("issues=%d", len(issues))
	}
	for i, issue := range issues {
		want := int64(100000)
		if i < 3 {
			want = 3000000
		}
		if issue.MonthOffset != int32(i) || issue.AmountCents != want || issue.ExpiresAfterMonths != 1 {
			t.Fatalf("issue %d = %+v", i, issue)
		}
	}
	legacy := []planGrant{
		{StartMonths: 0, Repeat: int32p(1), EveryMonths: 1, AmountCents: 1000000, ExpiresAfterMonths: 3},
		{StartMonths: 0, EveryMonths: 1, AmountCents: 100000, ExpiresAfterMonths: 1},
	}
	issues = expandPlanSchedule(legacy, 4)
	if len(issues) != 5 || issues[0].AmountCents != 1000000 || issues[0].ExpiresAfterMonths != 3 || issues[4].MonthOffset != 3 {
		t.Fatalf("legacy issues=%+v", issues)
	}
	quarterly := expandPlanSchedule([]planGrant{{StartMonths: 1, EveryMonths: 3, AmountCents: 1, ExpiresAfterMonths: 3}}, 12)
	if len(quarterly) != 4 || quarterly[3].MonthOffset != 10 {
		t.Fatalf("quarterly=%+v", quarterly)
	}
}

func TestPlanCreditSummary(t *testing.T) {
	for _, tc := range []struct {
		grants []planGrant
		want   string
	}{
		{nil, "No included credit"},
		{[]planGrant{{EveryMonths: 1, AmountCents: 100000, ExpiresAfterMonths: 1}}, "$1,000 every month"},
		{[]planGrant{
			{Repeat: int32p(3), EveryMonths: 1, AmountCents: 3000000, ExpiresAfterMonths: 1},
			{StartMonths: 3, Repeat: int32p(9), EveryMonths: 1, AmountCents: 100000, ExpiresAfterMonths: 1},
		}, "3 × $30,000 every month, then 9 × $1,000 every month from month 4"},
		{[]planGrant{
			{Repeat: int32p(1), EveryMonths: 1, AmountCents: 1000000, ExpiresAfterMonths: 3},
			{EveryMonths: 1, AmountCents: 100000, ExpiresAfterMonths: 1},
		}, "$10,000 once, each expiring after 3 months, then $1,000 every month"},
		{[]planGrant{{EveryMonths: 1, AmountCents: 12345, ExpiresAfterMonths: 1}}, "$123.45 every month"},
	} {
		if got := planCreditSummary(tc.grants); got != tc.want {
			t.Errorf("summary=%q want %q", got, tc.want)
		}
	}
}

func TestUniformMonthlyCredit(t *testing.T) {
	if c, ok := uniformMonthlyCredit([]planGrant{{EveryMonths: 1, AmountCents: 100000, ExpiresAfterMonths: 1}}); !ok || c != 100000 {
		t.Fatalf("uniform=%d %v", c, ok)
	}
	for _, g := range [][]planGrant{
		nil,
		{{Repeat: int32p(12), EveryMonths: 1, AmountCents: 1, ExpiresAfterMonths: 1}},
		{{StartMonths: 1, EveryMonths: 1, AmountCents: 1, ExpiresAfterMonths: 1}},
		{{EveryMonths: 1, AmountCents: 1, ExpiresAfterMonths: 2}},
		{{EveryMonths: 1, AmountCents: 1, ExpiresAfterMonths: 1}, {EveryMonths: 1, AmountCents: 1, ExpiresAfterMonths: 1}},
	} {
		if _, ok := uniformMonthlyCredit(g); ok {
			t.Fatalf("non-uniform schedule accepted: %+v", g)
		}
	}
}

func TestPlanVersionValidate(t *testing.T) {
	valid := planVersion{PricingVersion: "v2", Family: "pro", Kind: "subscription", DisplayName: "Pro", MonthlyFeeCents: int64p(25000),
		Limits:         planLimits{MaxConcurrent: int32p(1000), MaxVCPU: int32p(8), MaxMemoryMiB: int32p(256), MaxDiskMiB: int32p(1024), MaxTemplates: int32p(10)},
		CreditSchedule: []planGrant{{EveryMonths: 1, AmountCents: 25000, ExpiresAfterMonths: 1}},
		Allowance:      &planAllowance{AmountCents: 25000, Period: "month", OnExhausted: "payg"}}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*planVersion){
		"family":               func(v *planVersion) { v.Family = "Pro_1" },
		"pricing version":      func(v *planVersion) { v.PricingVersion = "v3" },
		"kind":                 func(v *planVersion) { v.Kind = "trial" },
		"name":                 func(v *planVersion) { v.DisplayName = " " },
		"subscription no fee":  func(v *planVersion) { v.MonthlyFeeCents = nil },
		"fee on prepaid":       func(v *planVersion) { v.Kind = "prepaid" },
		"fee with underscore":  func(v *planVersion) { v.Family = "custom_example" },
		"zero fee":             func(v *planVersion) { v.MonthlyFeeCents = int64p(0) },
		"limits":               func(v *planVersion) { v.Limits.MaxConcurrent = nil },
		"zero templates":       func(v *planVersion) { v.Limits.MaxTemplates = int32p(0) },
		"memory below minimum": func(v *planVersion) { v.Limits.MaxMemoryMiB = int32p(255) },
		"disk below minimum":   func(v *planVersion) { v.Limits.MaxDiskMiB = int32p(1023) },
		"payg without caps": func(v *planVersion) {
			v.Kind, v.Family, v.PricingVersion, v.MonthlyFeeCents, v.CreditSchedule, v.Allowance = "legacy_payg", "payg", "legacy", nil, nil, nil
			v.Limits.MaxMemoryMiB = nil
		},
		"grant every":        func(v *planVersion) { v.CreditSchedule[0].EveryMonths = 0 },
		"grant repeat":       func(v *planVersion) { v.CreditSchedule[0].Repeat = int32p(0) },
		"display-only terms": func(v *planVersion) { v.DisplayOnly = true },
		"blank feature":      func(v *planVersion) { v.Features = []string{""} },
		"allowance period":   func(v *planVersion) { v.Allowance.Period = "week" },
		"allowance both":     func(v *planVersion) { v.Allowance.Compute = &planCompute{Seconds: 1, VCPU: 1, MemoryGiB: 1} },
		"allowance neither":  func(v *planVersion) { v.Allowance.AmountCents = 0 },
		"matching bps":       func(v *planVersion) { v.Matching = &planMatching{MatchingBps: 10001, CapCents: 1} },
		"unsellable self-serve": func(v *planVersion) {
			v.SelfServe, v.Public, v.Matching = true, true, &planMatching{MatchingBps: 1, CapCents: 1}
		},
		"NUL in name": func(v *planVersion) { v.DisplayName = "Pr\x00o" },
	} {
		v := valid
		v.CreditSchedule = append([]planGrant{}, valid.CreditSchedule...)
		a := *valid.Allowance
		v.Allowance = &a
		mutate(&v)
		if err := v.validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, v)
		}
	}
	for name, v := range map[string]planVersion{
		"enterprise": {PricingVersion: "v2", Family: "enterprise", Kind: "custom", DisplayName: "Enterprise", DisplayOnly: true},
		"free": {PricingVersion: "v2", Family: "free", Kind: "free", Public: true, DisplayName: "Free", Limits: planLimits{MaxConcurrent: int32p(1)},
			Allowance: &planAllowance{Period: "day_window", OnExhausted: "pause", Compute: &planCompute{Seconds: 7200, VCPU: 1, MemoryGiB: 1}}},
		"starter":       {PricingVersion: "v2", Family: "starter", Kind: "prepaid", Public: true, DisplayName: "Starter", Limits: planLimits{MaxConcurrent: int32p(100)}},
		"matching deal": {PricingVersion: "v2", Family: "custom_example", Kind: "custom", DisplayName: "Example", Matching: &planMatching{MatchingBps: 10000, CapCents: 8000000}},
	} {
		if err := v.validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	sellable := valid
	sellable.SelfServe, sellable.Public = true, true
	if err := sellable.validate(); err != nil || !sellable.sellable() {
		t.Fatalf("public self-serve plan: %v", err)
	}
	sellable.Public = false
	if sellable.sellable() {
		t.Fatal("non-public plan sellable")
	}
}

func TestAllowanceSummary(t *testing.T) {
	if got := allowanceSummary(&planAllowance{AmountCents: 25000, Period: "month", OnExhausted: "payg"}); got != "$250 of usage included every month" {
		t.Errorf("pro summary %q", got)
	}
	if got := allowanceSummary(&planAllowance{AmountCents: 1440, Period: "day_window", OnExhausted: "pause", Compute: &planCompute{Seconds: 7200, VCPU: 1, MemoryGiB: 1}}); got != "$14.40 of compute every 24 hours" {
		t.Errorf("free summary %q", got)
	}
}

func TestPlanOfferInterval(t *testing.T) {
	for key, want := range map[string]int32{"pro_monthly": 1, "starter_annual": 12, "custom_example_annual": 12, "pro": 0, "pro_weekly": 0, "Pro_monthly": 0, "_monthly": 0, "pro__monthly": 0} {
		_, months, ok := planOfferInterval(key)
		if months != want || ok != (want != 0) {
			t.Errorf("%s: months=%d ok=%v", key, months, ok)
		}
	}
}

func TestDecimalString(t *testing.T) {
	for in, want := range map[[2]int64]string{{1332, 10000}: "0.1332", {25000, 100}: "250", {5, 1}: "5", {1, 3}: "0.333333333333"} {
		if got := decimalString(big.NewRat(in[0], in[1])); got != want {
			t.Errorf("decimalString(%d/%d) = %s, want %s", in[0], in[1], got, want)
		}
	}
}

func TestPlanPricedNeedsStripe(t *testing.T) {
	terms := planTerms{PricingVersion: "v2", Version: 1}
	h := &Handlers{}
	if h.planPriced(terms) {
		t.Fatal("v2 plan advertised without Stripe")
	}
	h.Stripe = &stripeHTTPClient{}
	if !h.planPriced(terms) {
		t.Fatal("v2 plan not available with Stripe")
	}
}
