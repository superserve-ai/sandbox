package vm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// systemdUnitName returns the systemd unit name for a sandbox.
func systemdUnitName(vmID string) string {
	return "firecracker@" + vmID + ".service"
}

// startUnit starts a systemd unit. Idempotent — starting an already-running
// unit is a no-op.
func startUnit(ctx context.Context, unit string) error {
	cmd := exec.CommandContext(ctx, "systemctl", "start", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl start %s: %s: %w", unit, strings.TrimSpace(string(out)), err)
	}
	return nil
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

// isUnitActive checks if a systemd unit is currently active (running).
func isUnitActive(ctx context.Context, unit string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit)
	return cmd.Run() == nil
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

// writeUnitDropIn writes a systemd drop-in config file for a firecracker@ unit.
// This sets per-sandbox resource limits and environment variables that the
// unit's ExecStart consumes.
func writeUnitDropIn(vmID string, memoryMax string, cpuQuota string) error {
	dropInDir := fmt.Sprintf("/etc/systemd/system/firecracker@%s.service.d", vmID)
	if err := os.MkdirAll(dropInDir, 0o755); err != nil {
		return fmt.Errorf("mkdir drop-in dir: %w", err)
	}

	var content strings.Builder
	content.WriteString("[Service]\n")
	if memoryMax != "" {
		content.WriteString("MemoryMax=" + memoryMax + "\n")
	}
	if cpuQuota != "" {
		content.WriteString("CPUQuota=" + cpuQuota + "\n")
	}

	dropInPath := filepath.Join(dropInDir, "limits.conf")
	return os.WriteFile(dropInPath, []byte(content.String()), 0o644)
}

// removeUnitDropIn removes the drop-in directory for a firecracker@ unit.
func removeUnitDropIn(vmID string) {
	dropInDir := fmt.Sprintf("/etc/systemd/system/firecracker@%s.service.d", vmID)
	os.RemoveAll(dropInDir)
}

// daemonReload tells systemd to re-read unit files. Required after writing
// drop-in files.
func daemonReload(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "daemon-reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
