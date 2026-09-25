package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DeleteTemplateArtifacts removes a template's snapshot dir and rootfs dir.
// Idempotent — missing dirs are not an error.
func (m *Manager) DeleteTemplateArtifacts(templateID string) error {
	if templateID == "" {
		return fmt.Errorf("template_id is required")
	}
	snapshotDir := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName, templateID)
	rundir := filepath.Join(m.cfg.RunDir, TemplatesDirName, templateID)
	if err := os.RemoveAll(snapshotDir); err != nil {
		return fmt.Errorf("remove %s: %w", snapshotDir, err)
	}
	if err := os.RemoveAll(rundir); err != nil {
		return fmt.Errorf("remove %s: %w", rundir, err)
	}
	return nil
}

// BuildArtifactEntry is a single per-build dir on this host.
type BuildArtifactEntry struct {
	TemplateID string
	BuildID    string
	MTime      time.Time
}

// ListBuildArtifacts enumerates per-build dirs for the controlplane
// reconciler.
func (m *Manager) ListBuildArtifacts() ([]BuildArtifactEntry, error) {
	root := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName)
	templates, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", root, err)
	}
	out := []BuildArtifactEntry{}
	for _, t := range templates {
		if !t.IsDir() {
			continue
		}
		tplDir := filepath.Join(root, t.Name())
		builds, err := os.ReadDir(tplDir)
		if err != nil {
			continue
		}
		for _, b := range builds {
			if !b.IsDir() {
				continue
			}
			info, err := b.Info()
			if err != nil {
				continue
			}
			out = append(out, BuildArtifactEntry{
				TemplateID: t.Name(),
				BuildID:    b.Name(),
				MTime:      info.ModTime(),
			})
		}
	}
	return out, nil
}

// DeleteBuildArtifacts removes a single build's subdir. Idempotent.
func (m *Manager) DeleteBuildArtifacts(templateID, buildID string) error {
	if !validBuildPathSegment(templateID) || !validBuildPathSegment(buildID) {
		return fmt.Errorf("template_id and build_id are required")
	}
	m.initBuildRegistry()
	m.buildsMu.Lock()
	defer m.buildsMu.Unlock()
	rec := m.builds[buildID]
	if rec != nil && rec.workerDone != nil {
		select {
		case <-rec.workerDone:
		default:
			return fmt.Errorf("build worker is still stopping")
		}
	}
	// A daemon restart loses the registry while KillMode=process leaves its
	// builder alive. Refuse deletion until an attempt-specific scan proves
	// no process can still write into these directories.
	if m.cfg.TemplateBuilderBin == "" {
		return fmt.Errorf("cannot confirm build worker exit without template-builder binary")
	}
	procs, err := findAttemptBuilders(m.cfg.TemplateBuilderBin, buildID)
	if err != nil {
		return err
	}
	if len(procs) != 0 {
		return fmt.Errorf("build worker is still running")
	}
	snapshotDir := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName, templateID, buildID)
	rundir := filepath.Join(m.cfg.RunDir, TemplatesDirName, templateID, buildID)
	if err := os.RemoveAll(snapshotDir); err != nil {
		return fmt.Errorf("remove %s: %w", snapshotDir, err)
	}
	if err := os.RemoveAll(rundir); err != nil {
		return fmt.Errorf("remove %s: %w", rundir, err)
	}
	return nil
}

// findAttemptBuilders matches the exact builder binary and --build-id argv
// pair. An unreadable process makes absence inconclusive, so cleanup retries.
func findAttemptBuilders(bin, buildID string) ([]builderProc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("scan build processes: %w", err)
	}
	var out []builderProc
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read build process %s: %w", e.Name(), err)
		}
		if !attemptBuilderCmdlineMatches(cmdline, bin, buildID) {
			continue
		}
		start, ok := procStartTime(e.Name())
		if !ok {
			return nil, fmt.Errorf("read build process identity %s", e.Name())
		}
		pid, _ := strconv.Atoi(e.Name())
		out = append(out, builderProc{pid: pid, start: start})
	}
	return out, nil
}

func attemptBuilderCmdlineMatches(cmdline []byte, bin, buildID string) bool {
	args := strings.Split(string(cmdline), "\x00")
	if len(args) < 3 || args[0] != bin {
		return false
	}
	for i := 1; i+1 < len(args); i++ {
		if args[i] == "--build-id" && args[i+1] == buildID {
			return true
		}
	}
	return false
}

func (m *Manager) stopRecoveredBuild(ctx context.Context, buildID string) error {
	if m.cfg.TemplateBuilderBin == "" {
		return fmt.Errorf("cannot confirm build worker exit without template-builder binary")
	}
	procs, err := findAttemptBuilders(m.cfg.TemplateBuilderBin, buildID)
	if err != nil {
		return err
	}
	for _, p := range procs {
		if start, ok := procStartTime(strconv.Itoa(p.pid)); ok && start == p.start {
			if err := syscall.Kill(p.pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		remaining, err := findAttemptBuilders(m.cfg.TemplateBuilderBin, buildID)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// killOrphanFirecracker SIGKILLs firecracker processes whose cmdline has
// `--id <buildVMID>` (build VMs reparented to init after a vmd crash).
func killOrphanFirecracker(buildVMID string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	killed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if !firecrackerCmdlineMatches(cmdline, buildVMID) {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err == nil {
			killed++
		}
	}
	return killed
}

// firecrackerCmdlineMatches is the identity predicate over a /proc/<pid>/cmdline:
// the NUL-delimited `--id <vmID>` argv token plus the firecracker binary name.
// Only firecracker matches — never another process that happens to mention the
// id in its args.
func firecrackerCmdlineMatches(cmdline []byte, vmID string) bool {
	if !bytes.Contains(cmdline, []byte("--id\x00"+vmID+"\x00")) {
		return false
	}
	return bytes.HasPrefix(cmdline, []byte("firecracker")) ||
		bytes.Contains(cmdline, []byte("/firecracker\x00"))
}
