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

// restartUnit (re)starts a systemd unit. For an inactive unit this is
// exactly `start`; an already-active unit — a stale firecracker left by an
// interrupted stop — is replaced rather than silently no-op'd, which would
// strand the launch waiting on a socket the old process never re-binds.
// Returns after the job is queued; readiness is signalled by the unit's own
// side effect (e.g., API socket appearing).
func restartUnit(ctx context.Context, unit string) error {
	// mode "replace" + nil result channel == `systemctl restart --no-block`:
	// the call returns at job-enqueue. nil also skips the library's
	// job-tracking lock, so concurrent launches pipeline on the socket.
	if err, ok := sdbusDo(func(c *sddbus.Conn) error {
		_, e := c.RestartUnitContext(ctx, unit, "replace", nil)
		return e
	}); ok {
		if err != nil {
			return fmt.Errorf("restart unit %s: %w", unit, err)
		}
		return nil
	}
	// At-least-once: a reply lost mid-call reads as unhandled and re-drives
	// here, possibly replace-restarting the job the lost call already
	// enqueued. Accepted — the ambiguity is irreducible without job
	// tracking, and the replace converges to one fresh process.
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "--no-block", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// stopJobWaitCap bounds the wait for a stop job's completion signal when the
// caller's ctx allows more. A legitimate stop can take two full TimeoutStopSec
// windows (SIGTERM phase, then a second window after SIGKILL) plus ExecStopPost,
// so this sits above that worst case. Distinct from stopUnitBudget below, which
// is the pause path's deliberately tighter policy.
const stopJobWaitCap = 35 * time.Second

// stopEnqueueCap bounds the StopUnit enqueue round trip. The library holds its
// job lock across this call, so one slow enqueue against a wedged PID1 would
// otherwise queue every other stop on the host behind it indefinitely.
const stopEnqueueCap = 5 * time.Second

// stopUnit stops a systemd unit. Idempotent — stopping an already-stopped
// unit is a no-op. Blocks until the stop job completes.
func stopUnit(ctx context.Context, unit string) error {
	// Buffered channel: the library's dispatcher does one blocking send;
	// buffer 1 keeps an abandoned wait from wedging every job on the
	// connection. Non-nil ch also serializes concurrent stops on the
	// library's job lock — enqueue round trip only, not the stop itself.
	// Concurrent stops of the SAME unit merge into one systemd job, whose
	// single registered channel goes to the last caller; an earlier caller
	// waits out its budget and converges via settleExpiredStopWait.
	ch := make(chan string, 1)
	err, enqueued := sdbusDo(func(c *sddbus.Conn) error {
		ectx, cancel := context.WithTimeout(ctx, stopEnqueueCap)
		defer cancel()
		_, e := c.StopUnitContext(ectx, unit, "replace", ch)
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
			return stopJobResult(unit, res)
		case <-ctx.Done():
			return settleExpiredStopWait(ctx, unit, ch,
				fmt.Errorf("stop unit %s: %w", unit, ctx.Err()))
		case <-timer.C:
			return settleExpiredStopWait(ctx, unit, ch,
				fmt.Errorf("stop unit %s: no job completion within %s", unit, stopJobWaitCap))
		}
	}

	cmd := exec.CommandContext(ctx, "systemctl", "stop", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func stopJobResult(unit, res string) error {
	if res != "done" && res != "skipped" {
		return fmt.Errorf("stop unit %s: job result %q", unit, res)
	}
	return nil
}

// settleExpiredStopWait decides the outcome of a stop whose wait expired. The
// result may have landed together with the deadline (select picks randomly
// among ready cases), and a completed job's signal may have been lost with the
// connection — check both before reporting failure, so a stop that actually
// finished never reads as failed. The probe is detached and bounded: at most
// 2s past a spent caller deadline, buying one truthful answer; it changes only
// the reported outcome, never any persisted state.
func settleExpiredStopWait(ctx context.Context, unit string, ch <-chan string, waitErr error) error {
	select {
	case res := <-ch:
		return stopJobResult(unit, res)
	default:
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if unitDefinitelyDead(cctx, unit) {
		return nil
	}
	return waitErr
}

// unitFailureSummary returns a one-line summary of a unit's
// Result/SubState for embedding in error messages. Best-effort —
// returns "unknown" on any error.
func unitFailureSummary(ctx context.Context, unit string) string {
	// Result lives on the Service interface, SubState on Unit — two reads,
	// not atomic; fine for a log-only string.
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
	if val, notLoaded, ok := sdbusUnitProperty(ctx, unit, "", "ActiveState"); ok {
		if notLoaded {
			return false
		}
		// Unexpected value shape falls through to exec, like unitActiveState.
		if s, isStr := val.(string); isStr && s != "" {
			return lingeringState(s)
		}
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--value", unit).Output()
	if err != nil {
		return false
	}
	return lingeringState(strings.TrimSpace(string(out)))
}

// lingeringState reports whether an ActiveState means a live or winding-down
// process (a restart must wait out a stop phase before the socket can rebind).
func lingeringState(s string) bool {
	switch s {
	case "active", "activating", "deactivating":
		return true
	}
	return false
}

// isUnitActive checks if a systemd unit is currently active (running).
// Inconclusive (ctx spent, transport failure) reports active — the caller
// treats "not active" as a dead VM, so only a definitive answer may say no.
func isUnitActive(ctx context.Context, unit string) bool {
	return !unitDefinitelyDead(ctx, unit)
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
