package main

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rs/zerolog"
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
		reload := startBackgroundMiningProtection(ctx, ready, lc, func(ctx context.Context, reloads <-chan struct{}) error {
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
		startBackgroundMiningProtection(context.Background(), ready, lc, func(ctx context.Context, _ <-chan struct{}) error {
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
		startBackgroundMiningProtection(context.Background(), ready, lc, func(context.Context, <-chan struct{}) error { close(returned); return nil })
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
		startBackgroundMiningProtection(context.Background(), make(chan struct{}), lc, func(context.Context, <-chan struct{}) error { called.Store(true); return nil })
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
		startBackgroundMiningProtection(context.Background(), ready, lc, func(context.Context, <-chan struct{}) error {
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
