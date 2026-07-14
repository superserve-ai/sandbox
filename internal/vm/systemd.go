package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
)

// systemdUnitName returns the systemd unit name for a sandbox.
func systemdUnitName(vmID string) string {
	return "firecracker@" + vmID + ".service"
}

// startUnit starts a systemd unit. Idempotent — starting an already-running
// unit is a no-op. Returns after the start job is queued; readiness is
// signalled by the unit's own side effect (e.g., API socket appearing).
func startUnit(ctx context.Context, unit string) error {
	// mode "replace" + nil result channel == `systemctl start --no-block`:
	// the call returns at job-enqueue. nil also skips the library's
	// job-tracking lock, so concurrent launches pipeline on the socket.
	if err, ok := sdbusDo(ctx, func(c *sddbus.Conn) error {
		_, e := c.StartUnitContext(ctx, unit, "replace", nil)
		return e
	}); ok {
		if err != nil {
			return fmt.Errorf("start unit %s: %w", unit, err)
		}
		return nil
	}
	cmd := exec.CommandContext(ctx, "systemctl", "start", "--no-block", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl start %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// unitFailureSummary returns a one-line summary of a unit's
// Result/SubState for embedding in error messages. Best-effort —
// returns "unknown" on any error.
func unitFailureSummary(ctx context.Context, unit string) string {
	// Result lives on the Service interface, SubState on Unit.
	if res, err, ok := sdbusUnitProperty(ctx, unit, "Service", "Result"); ok && err == nil {
		if sub, serr, sok := sdbusUnitProperty(ctx, unit, "", "SubState"); sok && serr == nil {
			r, _ := res.(string)
			s, _ := sub.(string)
			if r != "" || s != "" {
				return strings.TrimSpace(r + " " + s)
			}
		}
	}
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
// unit is a no-op. Blocks until the stop job completes.
func stopUnit(ctx context.Context, unit string) error {
	if err, ok := sdbusDo(ctx, func(c *sddbus.Conn) error {
		// Buffered channel: the library's job dispatcher does one blocking
		// send; buffer 1 keeps an abandoned wait (ctx expiry) from wedging
		// every job on the connection.
		ch := make(chan string, 1)
		if _, e := c.StopUnitContext(ctx, unit, "replace", ch); e != nil {
			return e
		}
		select {
		case res := <-ch:
			if res != "done" && res != "skipped" {
				return fmt.Errorf("stop job result %q", res)
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}); ok {
		if err != nil {
			return fmt.Errorf("stop unit %s: %w", unit, err)
		}
		return nil
	}
	cmd := exec.CommandContext(ctx, "systemctl", "stop", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// unitActiveState returns the unit's ActiveState over D-Bus.
// handled=false → answer unavailable, use the exec path.
func unitActiveState(ctx context.Context, unit string) (state string, handled bool) {
	val, err, ok := sdbusUnitProperty(ctx, unit, "", "ActiveState")
	if !ok || err != nil {
		return "", false
	}
	s, _ := val.(string)
	return s, s != ""
}

// isUnitActive checks if a systemd unit is currently active (running).
func isUnitActive(ctx context.Context, unit string) bool {
	if state, ok := unitActiveState(ctx, unit); ok {
		return state == "active"
	}
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit)
	return cmd.Run() == nil
}

// unitDefinitelyDead reports whether systemd definitively reports the unit
// not-active. Unlike !isUnitActive it returns false on an inconclusive result
// (ctx cancelled, transport failure), so an overloaded or shutting-down host
// never mistakes a live VM for a dead one. Only a real answer counts.
func unitDefinitelyDead(ctx context.Context, unit string) bool {
	if ctx.Err() != nil {
		return false
	}
	if state, ok := unitActiveState(ctx, unit); ok {
		return state != "active"
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
	var units []sddbus.UnitStatus
	if err, ok := sdbusDo(ctx, func(c *sddbus.Conn) error {
		var e error
		units, e = c.ListUnitsByPatternsContext(ctx, []string{"active"}, []string{"firecracker@*.service"})
		return e
	}); ok {
		if err != nil {
			return nil, fmt.Errorf("list firecracker units: %w", err)
		}
		ids := make([]string, 0, len(units))
		for _, u := range units {
			id := strings.TrimSuffix(strings.TrimPrefix(u.Name, "firecracker@"), ".service")
			if id != "" {
				ids = append(ids, id)
			}
		}
		return ids, nil
	}

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
