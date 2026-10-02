package proxy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOwnershipCacheSharesBurstAndSurvivesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	want := SandboxRoute{HostID: "owner", ProxyAddr: "192.0.2.1:5009", Generation: 7}
	cache := NewCachedOwnershipResolver(ctx, RouteLookupFunc(func(ctx context.Context, _ string) (SandboxRoute, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return want, nil
		case <-ctx.Done():
			return SandboxRoute{}, ctx.Err()
		}
	}))
	id := uuid.NewString()
	first, stop := context.WithCancel(ctx)
	firstResult := make(chan error, 1)
	go func() { _, err := cache.ResolveSandbox(first, id); firstResult <- err }()
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := cache.ResolveSandbox(ctx, id)
			if err != nil || got != want {
				t.Errorf("got %+v, %v", got, err)
			}
		}()
	}
	stop()
	if err := <-firstResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller: %v", err)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("burst issued %d queries", calls.Load())
	}
}

func TestOwnershipCacheFreshnessMovementDeletionAndOutage(t *testing.T) {
	var clock atomic.Int64
	var calls int
	want := SandboxRoute{HostID: "old", ProxyAddr: "192.0.2.1:5009", Generation: 1}
	var lookupErr error
	cache := NewCachedOwnershipResolver(context.Background(), RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) { calls++; return want, lookupErr }))
	cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	id := uuid.NewString()
	resolve := func(wantHost string, wantErr error) {
		t.Helper()
		got, err := cache.ResolveSandbox(context.Background(), id)
		if got.HostID != wantHost || !errors.Is(err, wantErr) {
			t.Fatalf("route=%+v err=%v", got, err)
		}
	}
	resolve("old", nil)
	want = SandboxRoute{HostID: "new", ProxyAddr: "192.0.2.2:5009", Generation: 2}
	clock.Store(int64(time.Second - time.Nanosecond))
	resolve("old", nil)
	if calls != 1 {
		t.Fatal("fresh entry queried database")
	}
	clock.Store(int64(time.Second))
	resolve("new", nil)
	want = SandboxRoute{}
	lookupErr = ErrInstanceNotFound
	clock.Store(int64(2 * time.Second))
	resolve("", ErrInstanceNotFound)
	lookupErr = errors.New("database unavailable")
	clock.Store(int64(2200 * time.Millisecond))
	resolve("", lookupErr)
	if calls != 4 {
		t.Fatalf("lookups=%d", calls)
	}
}

func TestOwnershipCacheBoundsDistinctLookupsAndEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, ownershipMaxLookups)
	release := make(chan struct{})
	cache := NewCachedOwnershipResolver(ctx, RouteLookupFunc(func(ctx context.Context, _ string) (SandboxRoute, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return SandboxRoute{HostID: "owner"}, nil
		case <-ctx.Done():
			return SandboxRoute{}, ctx.Err()
		}
	}))
	var wg sync.WaitGroup
	for i := 0; i < ownershipMaxLookups; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); cache.ResolveSandbox(ctx, uuid.NewString()) }()
	}
	for i := 0; i < ownershipMaxLookups; i++ {
		<-entered
	}
	if _, err := cache.ResolveSandbox(ctx, uuid.NewString()); err == nil {
		t.Fatal("unbounded distinct lookups")
	}
	close(release)
	wg.Wait()
	cache = NewCachedOwnershipResolver(ctx, RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) { return SandboxRoute{HostID: "owner"}, nil }))
	cache.now = func() time.Time { return time.Unix(0, 0) }
	first := uuid.NewString()
	cache.ResolveSandbox(ctx, first)
	for i := 0; i < ownershipCacheSize; i++ {
		cache.ResolveSandbox(ctx, uuid.NewString())
	}
	if len(cache.entries) != ownershipCacheSize || cache.lru.Len() != ownershipCacheSize {
		t.Fatal("cache exceeded bound")
	}
	if cache.entries[first] != nil {
		t.Fatal("least recent entry was not evicted")
	}
}

func TestOwnershipCacheDoesNotExtendFreshnessByQueryTime(t *testing.T) {
	var clock atomic.Int64
	calls := 0
	cache := NewCachedOwnershipResolver(context.Background(), RouteLookupFunc(func(context.Context, string) (SandboxRoute, error) {
		calls++
		clock.Add(int64(ownershipCacheTTL))
		return SandboxRoute{HostID: "owner"}, nil
	}))
	cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	id := uuid.NewString()
	cache.ResolveSandbox(context.Background(), id)
	cache.ResolveSandbox(context.Background(), id)
	if calls != 2 {
		t.Fatal("query duration extended cache freshness")
	}
}
