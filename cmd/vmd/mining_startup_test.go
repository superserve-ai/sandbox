package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/blocklist"
)

func TestMiningInitializationWaitsForReadinessAndQueuesReload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ready := make(chan struct{})
		entered := make(chan struct{})
		finishInit := make(chan struct{})
		reloaded := make(chan struct{})
		lc := newLifecycle(zerolog.Nop())
		reload := startBackgroundMiningProtection(ctx, ready, lc, nil, func(ctx context.Context, reloads <-chan struct{}) error {
			close(entered)
			<-finishInit
			select {
			case <-reloads:
				close(reloaded)
			case <-ctx.Done():
				return ctx.Err()
			}
			<-ctx.Done()
			return nil
		})
		// Registration and reload must not wait for kernel/spool initialization.
		for i := 0; i < 100; i++ {
			reload()
		}
		synctest.Wait()
		select {
		case <-entered:
			t.Fatal("mining initialization started before readiness")
		default:
		}
		close(ready)
		<-entered
		synctest.Wait()
		select {
		case <-lc.done:
			t.Fatal("initialization changed daemon lifetime")
		default:
		}
		close(finishInit)
		<-reloaded
		cancel()
		lc.shutdown(context.Background())
		if lc.closerErr != nil {
			t.Fatalf("shutdown: %v", lc.closerErr)
		}
	})
}

func TestMiningShutdownWaitsForInitializationBeforeDependencies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ready := make(chan struct{})
		close(ready)
		entered := make(chan struct{})
		cancelled := make(chan struct{})
		finishInit := make(chan struct{})
		shutdownDone := make(chan struct{})
		lc := newLifecycle(zerolog.Nop())
		var dependencyClosed atomic.Bool
		lc.addCloser("database", func(context.Context) error { dependencyClosed.Store(true); return nil })
		startBackgroundMiningProtection(context.Background(), ready, lc, nil, func(ctx context.Context, _ <-chan struct{}) error {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			// Simulate a constructor finishing its non-cancellable recovery after
			// shutdown begins; its cleanup remains ahead of the database closer.
			<-finishInit
			return nil
		})
		<-entered
		go func() { lc.shutdown(context.Background()); close(shutdownDone) }()
		<-cancelled
		synctest.Wait()
		if dependencyClosed.Load() {
			t.Fatal("closed dependency while initialization still owned it")
		}
		close(finishInit)
		<-shutdownDone
		if !dependencyClosed.Load() || lc.closerErr != nil {
			t.Fatalf("dependency shutdown did not complete: %v", lc.closerErr)
		}
	})
}

func TestMiningDisabledInitializationDoesNotStopDaemon(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ready := make(chan struct{})
		close(ready)
		returned := make(chan struct{})
		lc := newLifecycle(zerolog.Nop())
		startBackgroundMiningProtection(context.Background(), ready, lc, nil, func(context.Context, <-chan struct{}) error { close(returned); return nil })
		<-returned
		synctest.Wait()
		select {
		case <-lc.done:
			t.Fatal("optional initialization failure stopped daemon")
		default:
		}
		lc.shutdown(context.Background())
		if lc.closerErr != nil {
			t.Fatal(lc.closerErr)
		}
	})
}

func TestMiningShutdownBeforeReadySkipsInitialization(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lc := newLifecycle(zerolog.Nop())
		var called atomic.Bool
		startBackgroundMiningProtection(context.Background(), make(chan struct{}), lc, nil, func(context.Context, <-chan struct{}) error { called.Store(true); return nil })
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		lc.shutdown(closeCtx)
		if called.Load() || lc.closerErr != nil {
			t.Fatalf("unready mining work started or shutdown blocked: called=%v err=%v", called.Load(), lc.closerErr)
		}
	})
}

func TestMiningShutdownDeadlinePreservesLiveInitializerDependencies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ready := make(chan struct{})
		close(ready)
		entered := make(chan struct{})
		finishInit := make(chan struct{})
		lc := newLifecycle(zerolog.Nop())
		var dependencyClosed atomic.Bool
		lc.addCloser("database", func(context.Context) error { dependencyClosed.Store(true); return nil })
		startBackgroundMiningProtection(context.Background(), ready, lc, nil, func(context.Context, <-chan struct{}) error {
			close(entered)
			<-finishInit
			return nil
		})
		<-entered
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		lc.shutdown(closeCtx)
		if dependencyClosed.Load() || lc.closerErr == nil {
			t.Fatal("shutdown continued past a live initializer")
		}
		close(finishInit)
		<-lc.done
	})
}

func TestMiningStaleCleanupWaitsForReadyAndPrecedesInitialization(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ready := make(chan struct{})
				cleanupEntered := make(chan struct{})
				finishCleanup := make(chan struct{})
				initialized := make(chan struct{})
				lc := newLifecycle(zerolog.Nop())
				var initialize func(context.Context, <-chan struct{}) error
				if enabled {
					initialize = func(context.Context, <-chan struct{}) error { close(initialized); return nil }
				}
				startBackgroundMiningProtection(context.Background(), ready, lc, func() error { close(cleanupEntered); <-finishCleanup; return nil }, initialize)
				synctest.Wait()
				select {
				case <-cleanupEntered:
					t.Fatal("kernel cleanup ran before readiness")
				default:
				}
				close(ready)
				<-cleanupEntered
				synctest.Wait()
				select {
				case <-initialized:
					t.Fatal("new mining gate raced stale cleanup")
				default:
				}
				close(finishCleanup)
				if enabled {
					<-initialized
				}
				lc.shutdown(context.Background())
				if lc.closerErr != nil {
					t.Fatal(lc.closerErr)
				}
			})
		})
	}
}

func TestMiningStaleCleanupFailureKeepsEnforcementDisabled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ready := make(chan struct{})
		close(ready)
		cleaned := make(chan struct{})
		var initialized atomic.Bool
		lc := newLifecycle(zerolog.Nop())
		startBackgroundMiningProtection(context.Background(), ready, lc, func() error { close(cleaned); return errors.New("kernel unavailable") }, func(context.Context, <-chan struct{}) error { initialized.Store(true); return nil })
		<-cleaned
		synctest.Wait()
		if initialized.Load() {
			t.Fatal("initialized despite stale kernel cleanup failure")
		}
		select {
		case <-lc.done:
			t.Fatal("optional cleanup failure stopped daemon")
		default:
		}
		lc.shutdown(context.Background())
	})
}

type startupTestMiningGate struct {
	miningPacketGate
	mu      sync.Mutex
	cidrs   []string
	updates int
	closed  bool
	seedErr error
}

func (g *startupTestMiningGate) UpdateCIDRs(cidrs []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.updates++
	g.cidrs = slices.Clone(cidrs)
	return g.seedErr
}
func (g *startupTestMiningGate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return nil
}

func TestMiningGateSeedsPinnedAndPersistedCIDRsBeforeSlowFeed(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	configPath := filepath.Join(dir, "mining.yaml")
	state := filepath.Join(dir, "mining.state")
	if err := os.WriteFile(feed, []byte("203.0.113.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("domain_feeds: [%q]\ncustom_cidrs: [192.0.2.0/24]\nstate_path: %q\n", feed, state)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := blocklist.LoadMiningConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	// Write persisted state through the actual private-policy writer.
	blocklist.New(cfg, zerolog.Nop()).Refresh(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		fmt.Fprint(w, "198.51.100.0/24\n")
	}))
	defer server.Close()
	defer close(release)
	cfg.DomainFeeds = []string{server.URL}
	policy := blocklist.New(cfg, zerolog.Nop())
	gate := &startupTestMiningGate{}
	readyGate, err := newSeededMiningGate(context.Background(), policy, func() (miningPacketGate, error) { return gate, nil })
	if err != nil || readyGate == nil {
		t.Fatalf("local bootstrap failed: %v", err)
	}
	policy.SetCIDRSink(func(cidrs []string) { _ = gate.UpdateCIDRs(cidrs) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = policy.Start(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("feed refresh did not start")
	}
	gate.mu.Lock()
	seeded := gate.updates == 1 && slices.Contains(gate.cidrs, "192.0.2.0/24") && slices.Contains(gate.cidrs, "203.0.113.0/24")
	gate.mu.Unlock()
	if !seeded {
		t.Fatal("known direct destinations were unavailable while remote feed blocked")
	}
	cancel()
	<-done
}

func TestMiningGateSeedFailureClosesBeforePublication(t *testing.T) {
	policy := blocklist.New(&blocklist.Config{CustomCIDRs: []string{"192.0.2.0/24"}, StatePath: filepath.Join(t.TempDir(), "state")}, zerolog.Nop())
	gate := &startupTestMiningGate{seedErr: errors.New("kernel update failed")}
	readyGate, err := newSeededMiningGate(context.Background(), policy, func() (miningPacketGate, error) { return gate, nil })
	if readyGate != nil || err == nil || !gate.closed {
		t.Fatalf("failed seed could be published or leaked gate: gate=%v err=%v closed=%v", readyGate, err, gate.closed)
	}
}

func TestMiningStateTargetDirectoryAliases(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	linkDir := filepath.Join(dir, "link")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"state", "missing/nested/state"} {
		t.Run(suffix, func(t *testing.T) {
			realTarget, err := miningStateTarget(filepath.Join(realDir, suffix))
			if err != nil {
				t.Fatal(err)
			}
			linkTarget, err := miningStateTarget(filepath.Join(linkDir, suffix))
			if err != nil {
				t.Fatal(err)
			}
			if realTarget != linkTarget {
				t.Fatalf("directory aliases escaped collision detection: %q != %q", realTarget, linkTarget)
			}
			otherTarget, err := miningStateTarget(filepath.Join(linkDir, suffix+"-other"))
			if err != nil || otherTarget == realTarget {
				t.Fatalf("distinct file rejected: %q, %v", otherTarget, err)
			}
		})
	}
	// Existing regular files have the same identity as absent destinations.
	path := filepath.Join(realDir, "state")
	before, err := miningStateTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("synthetic state"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := miningStateTarget(filepath.Join(linkDir, "state"))
	if err != nil || after != before {
		t.Fatalf("regular file identity changed: %q != %q, %v", after, before, err)
	}
}

func TestMiningStateTargetRejectsUnverifiablePaths(t *testing.T) {
	dir := t.TempDir()
	loop := filepath.Join(dir, "loop")
	dangling := filepath.Join(dir, "dangling")
	finalLink := filepath.Join(dir, "state-link")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.WriteFile(state, []byte("synthetic state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, finalLink); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"directory symlink loop":     filepath.Join(loop, "state"),
		"dangling directory symlink": filepath.Join(dangling, "nested", "state"),
		"final file symlink":         finalLink,
		"regular parent file":        filepath.Join(state, "nested"),
		"parent traversal":           dir + "/loop/../state",
	} {
		t.Run(name, func(t *testing.T) {
			if target, err := miningStateTarget(path); err == nil || target != "" {
				t.Fatalf("unverifiable target accepted: %q, %v", target, err)
			}
		})
	}
}
