package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/blocklist"
	"github.com/superserve-ai/sandbox/internal/mining"
	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/telemetry"
	"github.com/superserve-ai/sandbox/internal/vm"
)

func startMiningProtection(ctx context.Context, ready <-chan struct{}, cfg Config, pool *pgxpool.Pool, proxy *network.EgressProxy, lc *lifecycle, log zerolog.Logger, recorder telemetry.Recorder, manager *vm.Manager) func() {
	path := os.Getenv("VMD_MINING_POLICY_CONFIG")
	if path == "" {
		return nil
	}
	return startBackgroundMiningProtection(ctx, ready, lc, func(ctx context.Context, reloads <-chan struct{}) error {
		return runMiningProtection(ctx, reloads, path, cfg, pool, proxy, log, recorder, manager)
	})
}

// Register cleanup before starting initialization: lifecycle shutdown snapshots
// closers, so a background initializer must never register a late closer.
func startBackgroundMiningProtection(ctx context.Context, ready <-chan struct{}, lc *lifecycle, run func(context.Context, <-chan struct{}) error) func() {
	miningCtx, cancel := context.WithCancel(ctx)
	reloads := make(chan struct{}, 1)
	done := make(chan struct{})
	var cleanupErr error
	lc.addCloser("mining protection", func(closeCtx context.Context) error {
		cancel()
		select {
		case <-done:
			return cleanupErr
		case <-closeCtx.Done():
			return closeCtx.Err()
		}
	})
	lc.start("mining protection", func() error {
		defer close(done)
		defer cancel()
		select {
		case <-miningCtx.Done():
			return nil
		case <-ready:
		}
		if miningCtx.Err() != nil {
			return nil
		}
		cleanupErr = run(miningCtx, reloads)
		// Disabled/failed optional initialization must not stop the daemon. The
		// registered closer still owns cancellation and any cleanup failure.
		<-miningCtx.Done()
		return nil
	})
	return func() {
		select {
		case reloads <- struct{}{}:
		default:
		}
	}
}

func runMiningProtection(ctx context.Context, reloads <-chan struct{}, path string, cfg Config, pool *pgxpool.Pool, proxy *network.EgressProxy, log zerolog.Logger, recorder telemetry.Recorder, manager *vm.Manager) (cleanupErr error) {
	policyConfig, err := blocklist.LoadMiningConfig(path)
	if err != nil {
		log.Error().Err(err).Msg("mining policy unavailable; escalation disabled")
		return nil
	}
	if genericPath := os.Getenv("VMD_EGRESS_BLOCKLIST_CONFIG"); genericPath != "" {
		generic, err := blocklist.LoadConfig(genericPath)
		if err != nil {
			log.Error().Err(err).Msg("cannot verify mining state separation; escalation disabled")
			return nil
		}
		miningState, _ := filepath.Abs(policyConfig.StatePath)
		genericState, _ := filepath.Abs(generic.StatePath)
		if miningState == genericState {
			log.Error().Msg("mining and generic policy must use separate state files; escalation disabled")
			return nil
		}
	}
	policy := blocklist.New(policyConfig, log)
	if ctx.Err() != nil {
		return nil
	}
	gate, err := network.NewMiningPacketGate(log)
	if err != nil {
		log.Error().Err(err).Msg("mining packet gate unavailable; escalation disabled")
		return nil
	}
	if ctx.Err() != nil {
		return gate.Close()
	}
	source := abuse.NewAuthoritativeSource(pool, abuse.AuthoritativeOptions{Report: telemetry.NewAbusePolicyReporter(ctx, log, recorder)})
	assignments := network.NewHostMiningSource(pool, source, proxy, cfg.HostID, cfg.IncarnationID)
	assignments.SetIncarnationResolver(func(id uuid.UUID) (string, bool) {
		info, ok := manager.LookupInstance(id.String())
		if !ok || info.CreatedAt.IsZero() {
			return "", false
		}
		return info.CreatedAt.UTC().Format(time.RFC3339Nano), true
	})
	store := abuse.NewIncidentStore(pool, cfg.HostID, assignments)
	var controller *network.MiningContainment
	delivery, err := mining.NewDelivery(filepath.Join(filepath.Dir(cfg.RunDir), "mining-incidents"), network.MaxSlots, store, func(ctx context.Context, i abuse.MiningIncident, r abuse.IncidentReceipt) error {
		return controller.Receipt(ctx, i, r)
	})
	if err != nil {
		cleanupErr = gate.Close()
		log.Error().Err(err).Msg("mining incident spool unavailable; escalation disabled")
		return cleanupErr
	}
	var workers sync.WaitGroup
	start := func(fn func()) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			fn()
		}()
	}
	defer func() {
		proxy.SetMiningPolicy(nil, nil)
		assignments.Disable()
		workers.Wait()
		if err := gate.Close(); err != nil {
			cleanupErr = err
		}
	}()
	// Cancellation can arrive during non-cancellable kernel/spool recovery.
	// Never publish enforcement or start dependent workers after it does.
	if ctx.Err() != nil {
		return nil
	}
	controller = network.NewMiningContainment(assignments, gate, delivery, log)
	proxy.SetMiningPolicy(policy, controller)
	policy.SetCIDRSink(func(cidrs []string) {
		if err := gate.UpdateCIDRs(cidrs); err != nil {
			log.Error().Err(err).Msg("mining destination synchronization failed; retaining previous kernel policy")
		}
	})
	start(func() { _ = policy.Start(ctx) })
	start(func() { source.Run(ctx) })
	start(func() {
		if err := gate.Run(ctx, policy, controller); err != nil && ctx.Err() == nil {
			// Closing the listener makes queue bypass immediate. Other daemon services
			// remain healthy; a packet observer failure must not stop sandbox compute.
			proxy.SetMiningPolicy(nil, nil)
			assignments.Disable()
			_ = gate.Close()
			log.Error().Err(err).Msg("mining packet observer failed open")
			<-ctx.Done()
		}
	})
	start(func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		degraded := false
		deliveryStarted := false
		for {
			refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := assignments.Refresh(refreshCtx)
			cancel()
			if err == nil {
				err = gate.SyncAssignments(assignments)
			}
			if err == nil {
				err = controller.Reconcile()
			}
			if err != nil && !degraded {
				log.Warn().Err(err).Msg("host mining assignment synchronization degraded; retaining known state")
			}
			if err == nil && degraded {
				log.Info().Msg("host mining assignment synchronization recovered")
			}
			degraded = err != nil
			if err == nil && source.Stats().Ready && !deliveryStarted {
				deliveryStarted = true
				start(func() { delivery.Run(ctx) })
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-reloads:
			policy.Reload(path)
		}
	}
}
