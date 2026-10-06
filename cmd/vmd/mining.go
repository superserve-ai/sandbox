package main

import (
	"context"
	"os"
	"path/filepath"
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

func startMiningProtection(ctx context.Context, cfg Config, pool *pgxpool.Pool, proxy *network.EgressProxy, lc *lifecycle, log zerolog.Logger, recorder telemetry.Recorder, manager *vm.Manager) func() {
	path := os.Getenv("VMD_MINING_POLICY_CONFIG")
	if path == "" {
		return nil
	}
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
	gate, err := network.NewMiningPacketGate(log)
	if err != nil {
		log.Error().Err(err).Msg("mining packet gate unavailable; escalation disabled")
		return nil
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
		_ = gate.Close()
		log.Error().Err(err).Msg("mining incident spool unavailable; escalation disabled")
		return nil
	}
	controller = network.NewMiningContainment(assignments, gate, delivery, log)
	proxy.SetMiningPolicy(policy, controller)
	lc.addCloser("mining packet gate", func(context.Context) error { return gate.Close() })
	policy.SetCIDRSink(func(cidrs []string) {
		if err := gate.UpdateCIDRs(cidrs); err != nil {
			log.Error().Err(err).Msg("mining destination synchronization failed; retaining previous kernel policy")
		}
	})
	lc.start("mining policy", func() error { return policy.Start(ctx) })
	lc.start("mining team policy", func() error { source.Run(ctx); return nil })
	lc.start("mining packet observer", func() error {
		if err := gate.Run(ctx, policy, controller); err != nil && ctx.Err() == nil {
			// Closing the listener makes queue bypass immediate. Other daemon services
			// remain healthy; a packet observer failure must not stop sandbox compute.
			proxy.SetMiningPolicy(nil, nil)
			assignments.Disable()
			_ = gate.Close()
			log.Error().Err(err).Msg("mining packet observer failed open")
			<-ctx.Done()
		}
		return nil
	})
	lc.start("mining assignments", func() error {
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
				lc.start("mining incident delivery", func() error { delivery.Run(ctx); return nil })
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	})
	return func() { policy.Reload(path) }
}
