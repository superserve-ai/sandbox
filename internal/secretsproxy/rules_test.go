package secretsproxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubRules struct {
	rules EgressRules
	err   error
	calls int
}

func (s *stubRules) FetchRules(_ context.Context, _ string) (EgressRules, error) {
	s.calls++
	if s.err != nil {
		return EgressRules{}, s.err
	}
	return s.rules, nil
}

func TestCachedRules_FreshHitAvoidsRefetch(t *testing.T) {
	up := &stubRules{rules: EgressRules{Allow: []string{"a.com"}}}
	c := NewCachedRules(up, RulesCacheOptions{TTL: time.Minute})
	for i := 0; i < 3; i++ {
		if r, err := c.FetchRules(context.Background(), "sb-1"); err != nil || len(r.Allow) != 1 {
			t.Fatalf("fetch %d: %v %+v", i, err, r)
		}
	}
	if up.calls != 1 {
		t.Errorf("want 1 upstream call (cached), got %d", up.calls)
	}
}

func TestCachedRules_LastKnownGoodOnError(t *testing.T) {
	up := &stubRules{rules: EgressRules{Deny: []string{"bad.com"}}}
	now := time.Now()
	c := NewCachedRules(up, RulesCacheOptions{TTL: time.Second})
	c.now = func() time.Time { return now }

	if _, err := c.FetchRules(context.Background(), "sb-1"); err != nil {
		t.Fatal(err)
	}
	// Expire the entry and make the control plane fail.
	now = now.Add(2 * time.Second)
	up.err = errors.New("control plane down")

	r, err := c.FetchRules(context.Background(), "sb-1")
	if err != nil {
		t.Fatalf("should serve last-known-good, got err %v", err)
	}
	if len(r.Deny) != 1 || r.Deny[0] != "bad.com" {
		t.Errorf("last-known-good not served: %+v", r)
	}
}

func TestCachedRules_ColdCacheErrorPropagates(t *testing.T) {
	up := &stubRules{err: errors.New("down")}
	c := NewCachedRules(up, RulesCacheOptions{})
	if _, err := c.FetchRules(context.Background(), "sb-1"); err == nil {
		t.Error("cold cache + fetch error must return an error so the caller fails closed")
	}
}

func TestCachedRules_WarmPopulatesCache(t *testing.T) {
	up := &stubRules{rules: EgressRules{Allow: []string{"a.com"}}}
	c := NewCachedRules(up, RulesCacheOptions{TTL: time.Minute})

	c.Warm(context.Background(), "sb-1")
	if up.calls != 1 {
		t.Fatalf("Warm should fetch once; calls=%d", up.calls)
	}
	// A subsequent request is now a cache hit — no live fetch needed.
	if _, err := c.FetchRules(context.Background(), "sb-1"); err != nil {
		t.Fatal(err)
	}
	if up.calls != 1 {
		t.Errorf("Warm should have populated the cache; calls=%d", up.calls)
	}
}

func TestCachedRules_InvalidateForcesRefetch(t *testing.T) {
	up := &stubRules{rules: EgressRules{Allow: []string{"a.com"}}}
	c := NewCachedRules(up, RulesCacheOptions{TTL: time.Minute})
	_, _ = c.FetchRules(context.Background(), "sb-1")
	c.Invalidate("sb-1")
	_, _ = c.FetchRules(context.Background(), "sb-1")
	if up.calls != 2 {
		t.Errorf("invalidate should force a refetch; calls=%d", up.calls)
	}
}
