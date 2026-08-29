package api

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/abuse"
)

func TestAbuseEnforcementCacheModesPrecedenceAndMatrix(t *testing.T) {
	team := uuid.New()
	user := uuid.New()

	var empty abuseEnforcementCache
	if allowed, matched := empty.Evaluate(abuseEnforcementRequest{TeamID: team, Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("zero-value cache must fail open")
	}

	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeOff)
	c.Replace(team, false, abuseEnforcementRestriction{
		SubjectType: "team",
		Actions:     []abuse.Action{abuse.ActionCreate},
	})
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("off mode must allow without consulting matches")
	}

	c.SetMode(abuseEnforcementModeEnforce)
	c.Replace(team, false,
		abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}},
		abuseEnforcementRestriction{SubjectType: "user", SubjectID: user, Actions: []abuse.Action{abuse.ActionResume}},
		abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.10", Actions: []abuse.Action{abuse.ActionCreate}},
		abuseEnforcementRestriction{SubjectType: "domain", Value: "PILOT-TEAM.EXAMPLE.", Actions: []abuse.Action{abuse.ActionResume}},
	)

	cases := []struct {
		name      string
		req       abuseEnforcementRequest
		wantAllow bool
	}{
		{
			name:      "team matches create",
			req:       abuseEnforcementRequest{TeamID: team, Action: abuse.ActionCreate},
			wantAllow: false,
		},
		{
			name:      "user matches resume",
			req:       abuseEnforcementRequest{TeamID: team, UserID: user, Action: abuse.ActionResume},
			wantAllow: false,
		},
		{
			name:      "ip matches create",
			req:       abuseEnforcementRequest{TeamID: team, IP: "192.0.2.10", Action: abuse.ActionCreate},
			wantAllow: false,
		},
		{
			name:      "domain matches resume",
			req:       abuseEnforcementRequest{TeamID: team, Domain: "pilot-team.example", Action: abuse.ActionResume},
			wantAllow: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, matched := c.Evaluate(tc.req)
			if allowed != tc.wantAllow {
				t.Fatalf("allowed = %v, want %v", allowed, tc.wantAllow)
			}
			if tc.wantAllow && matched {
				t.Fatal("allowing requests must not report a deny match")
			}
			if !tc.wantAllow && !matched {
				t.Fatal("matched deny was not reported")
			}
		})
	}

	trusted := uuid.New()
	c.Replace(trusted, true,
		abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}},
		abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.10", Actions: []abuse.Action{abuse.ActionCreate}},
	)
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: trusted, IP: "192.0.2.10", Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("trusted team must override every deny")
	}
}

func TestAbuseEnforcementCacheUpdateInvalidateAndFailOpen(t *testing.T) {
	team := uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)

	c.Replace(team, false, abuseEnforcementRestriction{
		SubjectType: "team",
		Actions:     []abuse.Action{abuse.ActionCreate},
	})
	if allowed, _ := c.Evaluate(abuseEnforcementRequest{TeamID: team, Action: abuse.ActionCreate}); allowed {
		t.Fatal("initial team restriction should deny")
	}

	c.Update(team, nil, abuseEnforcementRestriction{
		SubjectType: "domain",
		Value:       "stale.example.",
		Actions:     []abuse.Action{abuse.ActionResume},
	})
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, Domain: "stale.example", Action: abuse.ActionResume}); allowed || !matched {
		t.Fatal("update should add the new domain restriction")
	}

	c.Invalidate(team)
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, Domain: "stale.example", Action: abuse.ActionResume}); !allowed || matched {
		t.Fatal("invalidate should drop the stale entry and fail open")
	}

	var missing abuseEnforcementCache
	missing.SetMode(abuseEnforcementModeEnforce)
	if allowed, matched := missing.Evaluate(abuseEnforcementRequest{TeamID: uuid.New(), Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("missing cache state must fail open")
	}
}

func TestAbuseEnforcementCacheTTLAndIPNormalization(t *testing.T) {
	team := uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.Replace(team, false, abuseEnforcementRestriction{
		SubjectType: "ip",
		Value:       "2001:db8::1",
		Actions:     []abuse.Action{abuse.ActionCreate},
	})

	if allowed, _ := c.Evaluate(abuseEnforcementRequest{TeamID: team, IP: "2001:0db8:0:0:0:0:0:1", Action: abuse.ActionCreate}); allowed {
		t.Fatal("canonical IP should match the cached deny")
	}
	if allowed, _ := c.Evaluate(abuseEnforcementRequest{TeamID: team, IP: "192.0.2.99", Action: abuse.ActionCreate}); !allowed {
		t.Fatal("current-IP movement should stop the deny from matching")
	}

	c.mu.Lock()
	e := c.entries[team]
	e.lastUsed = time.Now().Add(-abuseEnforcementTTL - time.Second)
	c.entries[team] = e
	c.globalLastUsed[team] = time.Now().Add(-abuseEnforcementTTL - time.Second)
	c.mu.Unlock()

	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, IP: "2001:db8::1", Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("expired entries must evict and fail open")
	}
}

func TestAbuseEnforcementCacheGlobalIPMatchesUnseenTeam(t *testing.T) {
	owner, requestTeam := uuid.New(), uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.Replace(owner, false, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.10", Actions: []abuse.Action{abuse.ActionCreate}})
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: requestTeam, IP: "192.0.2.10", Action: abuse.ActionCreate}); allowed || !matched {
		t.Fatal("global IP restriction should apply to an unseen team")
	}
}

func TestAbuseEnforcementCacheReplaceAtCapacityKeepsExistingTeams(t *testing.T) {
	var c abuseEnforcementCache
	team := uuid.New()
	ids := make([]uuid.UUID, 0, abuseEnforcementMaxEntries)
	c.Replace(team, false, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}})
	ids = append(ids, team)
	for i := 1; i < abuseEnforcementMaxEntries; i++ {
		id := uuid.New()
		c.Replace(id, false, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}})
		ids = append(ids, id)
	}
	if len(c.entries) != abuseEnforcementMaxEntries {
		t.Fatalf("cache size after insertion at capacity = %d, want %d", len(c.entries), abuseEnforcementMaxEntries)
	}

	c.Replace(team, true)
	if len(c.entries) != abuseEnforcementMaxEntries {
		t.Fatalf("cache size after replacing at capacity = %d, want %d", len(c.entries), abuseEnforcementMaxEntries)
	}
	if !c.entries[team].trusted {
		t.Fatal("replacement should retain the refreshed team's state")
	}
	for _, id := range ids[1:] {
		if _, ok := c.entries[id]; !ok {
			t.Fatalf("refresh evicted unrelated team %s", id)
		}
	}
}

func TestAbuseEnforcementCacheExpiredTrustedEntryFailsOpenBeforeGlobalDeny(t *testing.T) {
	trusted, owner := uuid.New(), uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.Replace(trusted, true)
	c.Replace(owner, false, abuseEnforcementRestriction{
		SubjectType: "ip",
		Value:       "192.0.2.10",
		Actions:     []abuse.Action{abuse.ActionCreate},
	})

	c.mu.Lock()
	e := c.entries[trusted]
	e.lastUsed = time.Now().Add(-abuseEnforcementTTL - time.Second)
	c.entries[trusted] = e
	c.mu.Unlock()

	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: trusted, IP: "192.0.2.10", Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("expired trusted state must fail open instead of applying a global deny")
	}
}

func TestAbuseEnforcementCacheUpdatePreservesTrustedStateAfterSnapshotEviction(t *testing.T) {
	trusted, owner := uuid.New(), uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.SetCapacity(1)
	c.Replace(trusted, true, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.10", Actions: []abuse.Action{abuse.ActionCreate}})
	c.Replace(owner, false, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.11", Actions: []abuse.Action{abuse.ActionCreate}})
	if _, ok := c.entries[trusted]; !ok {
		t.Fatal("trusted deny snapshot must not be evicted under pressure")
	}
	if _, ok := c.trustedTeams[trusted]; !ok {
		t.Fatal("trusted allowlist state must survive snapshot eviction")
	}

	c.Update(trusted, nil)
	if _, ok := c.trustedTeams[trusted]; !ok {
		t.Fatal("trusted=nil update must preserve sticky trust")
	}
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: trusted, IP: "192.0.2.11", Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("sticky trust must continue to override global deny after refresh")
	}
}

func TestAbuseEnforcementCacheTrustRevocationIgnoresDenyCapacity(t *testing.T) {
	trusted, owner := uuid.New(), uuid.New()
	var c abuseEnforcementCache
	c.SetCapacity(1)
	c.Replace(trusted, true, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.10", Actions: []abuse.Action{abuse.ActionCreate}})
	c.Replace(owner, false, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.11", Actions: []abuse.Action{abuse.ActionCreate}})
	notTrusted := false
	c.Update(trusted, &notTrusted, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate, abuse.ActionResume}})
	if _, ok := c.trustedTeams[trusted]; ok {
		t.Fatal("explicit trust revocation must apply even when deny admission fails")
	}
}

func TestAbuseEnforcementCacheAdmissionOverflowIsCounted(t *testing.T) {
	var c abuseEnforcementCache
	c.SetCapacity(1)
	c.Replace(uuid.New(), false, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate, abuse.ActionResume}})
	stats := c.Stats()
	if stats.DenyEntries != 0 || stats.AdmissionRejections != 1 {
		t.Fatalf("overflow stats = %+v, want zero entries and one rejection", stats)
	}
}

func TestAbuseEnforcementCacheFiltersNonLifecycleActions(t *testing.T) {
	var c abuseEnforcementCache
	c.SetCapacity(1)
	team := uuid.New()
	c.Replace(team, false, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate, abuse.ActionSignup}})
	if got := c.Stats().DenyEntries; got != 1 {
		t.Fatalf("deny entries = %d, want 1", got)
	}
	if _, ok := c.entries[team].team[team.String()+"|"+string(abuse.ActionSignup)]; ok {
		t.Fatal("non-lifecycle action should not be cached")
	}
}

func TestAbuseEnforcementCacheGlobalActionsMatchLocalAccounting(t *testing.T) {
	var c abuseEnforcementCache
	c.SetCapacity(2)
	owner := uuid.New()
	c.Replace(owner, false, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.10", Actions: []abuse.Action{abuse.ActionCreate, abuse.ActionSignup}})
	if got := len(c.users["192.0.2.10"]); got != 0 {
		t.Fatalf("unexpected user index entries = %d", got)
	}
	if got := len(c.ips["192.0.2.10"][owner]); got != 1 {
		t.Fatalf("global action entries = %d, want 1", got)
	}
	c.Replace(uuid.New(), false, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.11", Actions: []abuse.Action{abuse.ActionSignup}})
	if got := c.Stats().DenyEntries; got != 1 {
		t.Fatalf("unsupported-only restriction should not consume capacity, got %d entries", got)
	}
}

func TestAbuseEnforcementCacheOversizedReplaceDoesNotEvict(t *testing.T) {
	var c abuseEnforcementCache
	c.SetCapacity(1)
	owner := uuid.New()
	c.Replace(owner, false, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}})
	c.Replace(uuid.New(), false, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate, abuse.ActionResume}})
	if _, ok := c.entries[owner]; !ok {
		t.Fatal("oversized replacement must not evict existing deny state")
	}
	if got := c.Stats().AdmissionRejections; got != 1 {
		t.Fatalf("admission rejections = %d, want 1", got)
	}
}

func TestAbuseEnforcementCacheUpdateEvictsUntilCapacity(t *testing.T) {
	var c abuseEnforcementCache
	c.SetCapacity(2)
	c.Replace(uuid.New(), false)
	c.Replace(uuid.New(), false, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}})
	c.Replace(uuid.New(), false, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}})
	team := uuid.New()
	c.Update(team, nil, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}})
	if _, ok := c.entries[team]; !ok {
		t.Fatal("update should evict enough stale state to admit the new restriction")
	}
}

func TestAbuseEnforcementCacheOversizedUpdateDoesNotEvict(t *testing.T) {
	var c abuseEnforcementCache
	c.SetCapacity(2)
	team := uuid.New()
	c.Replace(team, false,
		abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}},
		abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.20", Actions: []abuse.Action{abuse.ActionCreate}},
	)
	before := c.Stats()
	c.Update(team, nil, abuseEnforcementRestriction{SubjectType: "domain", Value: "oversized.example", Actions: []abuse.Action{abuse.ActionCreate}})
	if got := c.Stats().DenyEntries; got != before.DenyEntries {
		t.Fatal("oversized update must preserve existing deny state")
	}
	if got := c.Stats().AdmissionRejections; got != before.AdmissionRejections+1 {
		t.Fatalf("admission rejections = %d, want %d", got, before.AdmissionRejections+1)
	}
}

func TestAbuseEnforcementCacheOversizedReplaceTrustSemantics(t *testing.T) {
	oversized := []abuseEnforcementRestriction{
		{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}},
		{SubjectType: "ip", Value: "192.0.2.40", Actions: []abuse.Action{abuse.ActionCreate}},
	}

	t.Run("trusted payload rejected but trust retained", func(t *testing.T) {
		team := uuid.New()
		var c abuseEnforcementCache
		c.SetCapacity(1)
		c.Replace(team, true, oversized...)
		if _, ok := c.trustedTeams[team]; !ok {
			t.Fatal("trusted replacement must retain trust when deny payload is oversized")
		}
		if _, ok := c.entries[team]; ok {
			t.Fatal("oversized trusted payload must not be stored")
		}
		if got := c.Stats().AdmissionRejections; got != 1 {
			t.Fatalf("admission rejections = %d, want 1", got)
		}
	})

	t.Run("untrusted payload rejected and trust revoked", func(t *testing.T) {
		team := uuid.New()
		var c abuseEnforcementCache
		c.SetCapacity(1)
		c.Replace(team, true, abuseEnforcementRestriction{SubjectType: "team", Actions: []abuse.Action{abuse.ActionCreate}})
		c.Replace(team, false, oversized...)
		if _, ok := c.trustedTeams[team]; ok {
			t.Fatal("untrusted replacement must revoke trust even when deny payload is oversized")
		}
		if got := c.Stats().AdmissionRejections; got != 1 {
			t.Fatalf("admission rejections = %d, want 1", got)
		}
	})
}

func TestAbuseEnforcementCacheGlobalMatchRefreshesOwnerTTL(t *testing.T) {
	owner, requestTeam := uuid.New(), uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.Replace(owner, false, abuseEnforcementRestriction{
		SubjectType: "ip",
		Value:       "192.0.2.10",
		Actions:     []abuse.Action{abuse.ActionCreate},
	})

	c.mu.Lock()
	e := c.entries[owner]
	e.lastUsed = time.Now().Add(-abuseEnforcementTTL - time.Second)
	c.entries[owner] = e
	c.mu.Unlock()

	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: requestTeam, IP: "192.0.2.10", Action: abuse.ActionCreate}); allowed || !matched {
		t.Fatal("global restriction should deny and refresh the owner's global usage")
	}

	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: owner, IP: "192.0.2.10", Action: abuse.ActionCreate}); allowed || !matched {
		t.Fatal("recently matched global restriction must keep the owner entry alive")
	}
}

func TestAbuseEnforcementCacheGlobalActivityIsGenerationScoped(t *testing.T) {
	owner := uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.Replace(owner, false, abuseEnforcementRestriction{
		SubjectType: "ip",
		Value:       "192.0.2.30",
		Actions:     []abuse.Action{abuse.ActionCreate},
	})

	first := c.published.Load()
	firstActivity := first.globalAggregated["i|192.0.2.30"].activity
	firstActivity.Store(time.Now().Add(-abuseEnforcementTTL - time.Second).UnixNano())

	c.Replace(owner, false, abuseEnforcementRestriction{
		SubjectType: "ip",
		Value:       "192.0.2.30",
		Actions:     []abuse.Action{abuse.ActionCreate},
	})
	second := c.published.Load()
	secondActivity := second.globalAggregated["i|192.0.2.30"].activity
	if secondActivity != firstActivity {
		t.Fatal("unchanged aggregate should retain its activity pointer across publication")
	}
	if age := time.Since(time.Unix(0, secondActivity.Load())); age < 0 || age >= abuseEnforcementTTL {
		t.Fatalf("refreshed global restriction activity age = %s, want fresh activity", age)
	}
	c.Replace(owner, false, abuseEnforcementRestriction{
		SubjectType: "ip",
		Value:       "192.0.2.30",
		Actions:     []abuse.Action{abuse.ActionCreate, abuse.ActionResume},
	})
	third := c.published.Load()
	if third.globalAggregated["i|192.0.2.30"].activity == secondActivity {
		t.Fatal("changed aggregate must receive a new activity pointer")
	}

	secondActivity.Store(time.Now().Add(-abuseEnforcementTTL - time.Second).UnixNano())
	if age := time.Since(time.Unix(0, third.globalAggregated["i|192.0.2.30"].activity.Load())); age >= abuseEnforcementTTL {
		t.Fatalf("unchanged generation activity changed new generation age to %s", age)
	}
}

func TestAbuseEnforcementCacheRestrictionExpiry(t *testing.T) {
	team := uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.Replace(team, false, abuseEnforcementRestriction{
		SubjectType: "team",
		Actions:     []abuse.Action{abuse.ActionCreate},
		ExpiresAt:   time.Now().Add(20 * time.Millisecond),
	})
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, Action: abuse.ActionCreate}); allowed || !matched {
		t.Fatal("active restriction should deny")
	}
	time.Sleep(30 * time.Millisecond)
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("expired restriction must allow without waiting for cache eviction")
	}
}

func TestAbuseEnforcementCacheActionWildcard(t *testing.T) {
	team := uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.Replace(team, false, abuseEnforcementRestriction{
		SubjectType: "team",
	})

	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, Action: abuse.ActionCreate}); allowed || !matched {
		t.Fatal("action-agnostic restriction should deny create")
	}
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, Action: abuse.ActionResume}); allowed || !matched {
		t.Fatal("action-agnostic restriction should deny resume")
	}
}

func TestAbuseEnforcementCacheStickyStatsAndExpiryMerge(t *testing.T) {
	team, owner := uuid.New(), uuid.New()
	var c abuseEnforcementCache
	c.SetMode(abuseEnforcementModeEnforce)
	c.SetCapacity(2)
	c.Replace(team, true)
	c.Replace(owner, false, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.1", Actions: []abuse.Action{abuse.ActionCreate}})
	c.Update(owner, nil, abuseEnforcementRestriction{SubjectType: "ip", Value: "192.0.2.1", Actions: []abuse.Action{abuse.ActionCreate}, ExpiresAt: time.Now().Add(time.Minute)})
	if allowed, _ := c.Evaluate(abuseEnforcementRequest{TeamID: owner, IP: "192.0.2.1", Action: abuse.ActionCreate}); allowed {
		t.Fatal("indefinite restriction must not be shortened")
	}
	if allowed, matched := c.Evaluate(abuseEnforcementRequest{TeamID: team, IP: "192.0.2.1", Action: abuse.ActionCreate}); !allowed || matched {
		t.Fatal("trusted team must override deny")
	}
	stats := c.Stats()
	if stats.DenyCapacity != 2 || stats.TrustedTeams != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
