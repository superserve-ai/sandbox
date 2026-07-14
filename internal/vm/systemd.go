package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

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
	if err, ok := sdbusDo(func(c *sddbus.Conn) error {
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

// stopJobWaitCap bounds the wait for a stop job's completion signal. Above
// the unit's TimeoutStopSec (10s) + kill margin: past this the signal is
// considered lost (dead signal socket), not the job slow.
const stopJobWaitCap = 15 * time.Second

// stopUnit stops a systemd unit. Idempotent — stopping an already-stopped
// unit is a no-op. Blocks until the stop job completes.
func stopUnit(ctx context.Context, unit string) error {
	// Buffered channel: the library's dispatcher does one blocking send;
	// buffer 1 keeps an abandoned wait from wedging every job on the
	// connection.
	ch := make(chan string, 1)
	err, enqueued := sdbusDo(func(c *sddbus.Conn) error {
		_, e := c.StopUnitContext(ctx, unit, "replace", ch)
		return e
	})
	if enqueued {
		if err != nil {
			if sdbusNotLoaded(err) {
				return nil // not loaded == already stopped
			}
			return fmt.Errorf("stop unit %s: %w", unit, err)
		}
		// systemd accepted the job — from here we only report the outcome,
		// never re-drive the stop via exec (that would double-execute).
		timer := time.NewTimer(stopJobWaitCap)
		defer timer.Stop()
		select {
		case res := <-ch:
			if res != "done" && res != "skipped" {
				return fmt.Errorf("stop unit %s: job result %q", unit, res)
			}
			return nil
		case <-ctx.Done():
			return fmt.Errorf("stop unit %s: %w", unit, ctx.Err())
		case <-timer.C:
			// Completion signal lost (e.g. signal socket died mid-wait).
			return fmt.Errorf("stop unit %s: no job completion within %s", unit, stopJobWaitCap)
		}
	}

	cmd := exec.CommandContext(ctx, "systemctl", "stop", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// unitFailureSummary returns a one-line summary of a unit's
// Result/SubState for embedding in error messages. Best-effort —
// returns "unknown" on any error.
func unitFailureSummary(ctx context.Context, unit string) string {
	// Result lives on the Service interface, SubState on Unit.
	if res, notLoaded, ok := sdbusUnitProperty(ctx, unit, "Service", "Result"); ok {
		if notLoaded {
			return "not-loaded"
		}
		if sub, _, sok := sdbusUnitProperty(ctx, unit, "", "SubState"); sok {
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

// unitActiveState answers whether the unit counts as active, matching
// `systemctl is-active` (which accepts both "active" and "reloading").
// handled=false → no D-Bus answer, use the exec path.
func unitActiveState(ctx context.Context, unit string) (activeNow, handled bool) {
	val, notLoaded, ok := sdbusUnitProperty(ctx, unit, "", "ActiveState")
	if !ok {
		return false, false
	}
	if notLoaded {
		return false, true // not loaded == not active, definitively
	}
	s, _ := val.(string)
	if s == "" {
		return false, false
	}
	return s == "active" || s == "reloading", true
}

// isUnitActive checks if a systemd unit is currently active (running).
func isUnitActive(ctx context.Context, unit string) bool {
	if active, ok := unitActiveState(ctx, unit); ok {
		return active
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
	if active, ok := unitActiveState(ctx, unit); ok {
		return !active
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
	if err, ok := sdbusDo(func(c *sddbus.Conn) error {
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
