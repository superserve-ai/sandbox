package vm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	if templateID == "" || buildID == "" {
		return fmt.Errorf("template_id and build_id are required")
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

// killOrphanFirecracker SIGKILLs firecracker processes whose cmdline has
// `--id <buildVMID>` (build VMs reparented to init after a vmd crash).
func killOrphanFirecracker(buildVMID string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	killed := 0
	marker := []byte("--id\x00" + buildVMID + "\x00")
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
		if !bytes.Contains(cmdline, marker) {
			continue
		}
		// Only kill firecracker — don't touch other processes that happen
		// to mention the build id in their args.
		if !bytes.HasPrefix(cmdline, []byte("firecracker")) &&
			!bytes.Contains(cmdline, []byte("/firecracker\x00")) {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err == nil {
			killed++
		}
	}
	return killed
}
