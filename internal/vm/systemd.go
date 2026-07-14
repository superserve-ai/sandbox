package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// systemdUnitName returns the systemd unit name for a sandbox.
func systemdUnitName(vmID string) string {
	return "firecracker@" + vmID + ".service"
}

// restartUnit (re)starts a systemd unit. For an inactive unit this is
// exactly `start`; an already-active unit — a stale firecracker left by an
// interrupted stop — is replaced rather than silently no-op'd, which would
// strand the launch waiting on a socket the old process never re-binds.
// Returns after the job is queued; readiness is signalled by the unit's own
// side effect (e.g., API socket appearing).
func restartUnit(ctx context.Context, unit string) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "--no-block", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// unitFailureSummary returns a one-line summary of a unit's
// Result/SubState for embedding in error messages. Best-effort —
// returns "unknown" on any error.
func unitFailureSummary(ctx context.Context, unit string) string {
	cmd := exec.CommandContext(ctx, "systemctl", "show", "--property=Result,SubState", "--value", unit)
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	s := strings.TrimSpace(string(out))
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "unknown"
	}
	return s
}

// stopUnit stops a systemd unit. Idempotent — stopping an already-stopped
// unit is a no-op.
func stopUnit(ctx context.Context, unit string) error {
	cmd := exec.CommandContext(ctx, "systemctl", "stop", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// stopUnitBudget covers `systemctl stop` blocking up to TimeoutStopSec plus
// margin for host I/O contention. The pause path caps its whole stop phase
// at this OR the caller's remaining deadline, whichever is shorter.
const stopUnitBudget = 15 * time.Second

// stopUnitWithBudget stops a unit on a detached context with its own budget,
// so the caller's possibly-spent deadline can't starve a stop that must
// happen (e.g. after a pause's snapshot already landed).
func stopUnitWithBudget(ctx context.Context, unit string) error {
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopUnitBudget)
	defer cancel()
	return stopUnit(c, unit)
}

// unitLingering reports whether the unit has a live or winding-down process
// (active, activating, or deactivating) — i.e. a restart must wait out a
// stop phase before the fresh process can bind its socket.
func unitLingering(ctx context.Context, unit string) bool {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--value", unit).Output()
	if err != nil {
		return false
	}
	switch strings.TrimSpace(string(out)) {
	case "active", "activating", "deactivating":
		return true
	}
	return false
}

// isUnitActive checks if a systemd unit is currently active (running).
func isUnitActive(ctx context.Context, unit string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit)
	return cmd.Run() == nil
}

// unitDefinitelyDead reports whether systemd definitively reports the unit
// not-active. Unlike !isUnitActive it returns false on an inconclusive result
// (ctx cancelled, systemctl timeout/error), so an overloaded or shutting-down
// host never mistakes a live VM for a dead one. Only a clean non-zero exit counts.
func unitDefinitelyDead(ctx context.Context, unit string) bool {
	if ctx.Err() != nil {
		return false
	}
	err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run()
	if err == nil {
		return false // active
	}
	if ctx.Err() != nil {
		return false // cancelled or timed out mid-call, not a real answer
	}
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr)
}

// listActiveFirecrackerUnits returns the sandbox IDs of all running
// firecracker@ units. Used during startup reattach.
func listActiveFirecrackerUnits(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "list-units",
		"firecracker@*.service", "--state=active", "--no-legend", "--plain")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list firecracker units: %w", err)
	}

	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		// Each line: "firecracker@<id>.service loaded active running ..."
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		// Extract ID from "firecracker@<id>.service"
		unit = strings.TrimPrefix(unit, "firecracker@")
		unit = strings.TrimSuffix(unit, ".service")
		if unit != "" {
			ids = append(ids, unit)
		}
	}
	return ids, nil
}

// removeUnitDropIn removes the drop-in directory for a firecracker@ unit.
func removeUnitDropIn(vmID string) {
	dropInDir := fmt.Sprintf("/etc/systemd/system/firecracker@%s.service.d", vmID)
	os.RemoveAll(dropInDir)
}
