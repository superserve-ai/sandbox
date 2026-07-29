package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
)

// applyCapturedNetworkPatch serializes live firewall changes with saved
// snapshot admission. Capture takes the same advisory lock before recording
// policy and then updates the sandbox row; taking advisory -> row lock in that
// order avoids both configuration drift and a lock-order deadlock.
func (h *Handlers) applyCapturedNetworkPatch(
	ctx context.Context,
	vmd VMDClient,
	sandboxID, teamID uuid.UUID,
	allowedCIDRs, deniedCIDRs, allowedDomains []string,
	networkConfig []byte,
) (db.Sandbox, error) {
	var live db.Sandbox
	var livePolicyApplied bool

	mutate := func(q *db.Queries, takeAdvisoryLock bool) error {
		if takeAdvisoryLock {
			if err := q.LockSandboxForSecretWrites(ctx, sandboxID.String()); err != nil {
				return fmt.Errorf("lock captured sandbox configuration: %w", err)
			}
		}
		var err error
		live, err = q.LockSandboxForCapturedMutation(ctx, db.LockSandboxForCapturedMutationParams{
			ID: sandboxID, TeamID: teamID,
		})
		if err != nil {
			return err
		}
		if live.SnapshotOperationID.Valid {
			return errSandboxSnapshotInFlight
		}
		if live.Status != db.SandboxStatusActive {
			return errSandboxMidTransition
		}

		vmdCtx, cancel := context.WithTimeout(ctx, vmdTimeout)
		err = vmd.UpdateSandboxNetwork(vmdCtx, sandboxID.String(), allowedCIDRs, deniedCIDRs, allowedDomains)
		cancel()
		if err != nil {
			return fmt.Errorf("apply live sandbox network: %w", err)
		}
		livePolicyApplied = true

		rows, err := q.UpdateSandboxNetworkConfig(ctx, db.UpdateSandboxNetworkConfigParams{
			ID: sandboxID, NetworkConfig: networkConfig, TeamID: teamID,
		})
		if err != nil {
			return fmt.Errorf("persist sandbox network: %w", err)
		}
		if rows != 1 {
			return fmt.Errorf("persist sandbox network affected %d rows", rows)
		}
		return nil
	}

	if h.Pool == nil {
		if err := mutate(h.DB, false); err != nil {
			if livePolicyApplied {
				h.rollbackSandboxNetwork(ctx, vmd, live)
			}
			return db.Sandbox{}, err
		}
		return live, nil
	}

	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return db.Sandbox{}, err
	}
	defer tx.Rollback(ctx)
	if err := mutate(h.DB.WithTx(tx), true); err != nil {
		if livePolicyApplied {
			h.rollbackSandboxNetwork(ctx, vmd, live)
		}
		return db.Sandbox{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		h.rollbackSandboxNetwork(ctx, vmd, live)
		return db.Sandbox{}, fmt.Errorf("commit sandbox network policy: %w", err)
	}
	return live, nil
}

func (h *Handlers) rollbackSandboxNetwork(reqCtx context.Context, vmd VMDClient, sandbox db.Sandbox) {
	allowedCIDRs, deniedCIDRs, allowedDomains, err := sandboxNetworkArgs(sandbox.NetworkConfig)
	if err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("cannot decode previous network policy for rollback")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), vmdTimeout)
	defer cancel()
	if err := vmd.UpdateSandboxNetwork(ctx, sandbox.ID.String(), allowedCIDRs, deniedCIDRs, allowedDomains); err != nil {
		log.Error().Err(err).Str("sandbox_id", sandbox.ID.String()).Msg("rollback live network policy after DB failure")
	}
}

func sandboxNetworkArgs(raw []byte) (allowedCIDRs, deniedCIDRs, allowedDomains []string, err error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil, nil, nil
	}
	var config persistedEgressConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, nil, nil, err
	}
	return config.Egress.AllowedCIDRs, config.Egress.DeniedCIDRs, config.Egress.AllowedDomains, nil
}
