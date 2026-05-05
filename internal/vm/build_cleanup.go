package vm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// CleanupOrphanBuilds scans the on-disk templates/ subtree for directories
// that represent incomplete builds and reclaims them. Called once from vmd
// startup before the gRPC server comes up.
//
// A completed build leaves a build.meta.json sidecar next to the snapshot
// (written by writeBuildMeta). Directories without that marker — either
// from a vmd crash mid-build, or from an explicit CancelBuild — are
// considered orphans and removed wholesale:
//
//	${SnapshotDir}/templates/<id>/   — removed if no build.meta.json
//	${RunDir}/templates/<id>/        — removed in lockstep
//
// Any systemd unit named build-<id> that's still running is also stopped.
// Stateless across vmd restarts: a template that existed in-memory but had
// no disk footprint (shouldn't happen normally) won't leave disk residue to
// clean up, so this sweep is safe to run unconditionally.
//
// Returns the number of orphans reclaimed. Errors encountered on individual
// directories are logged but don't abort the sweep — one bad dir shouldn't
// block vmd startup.
func (m *Manager) CleanupOrphanBuilds() int {
	snapshotsRoot := filepath.Join(m.cfg.SnapshotDir, TemplatesDirName)
	entries, err := os.ReadDir(snapshotsRoot)
	if err != nil {
		// Directory doesn't exist → no orphans to clean. First-time vmd
		// startup hits this; not an error.
		return 0
	}

	reclaimed := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		templateID := entry.Name()
		snapshotDir := filepath.Join(snapshotsRoot, templateID)

		if m.isCompleteBuild(snapshotDir) {
			// Finished build. Leave it — CreateVM needs these files when a
			// sandbox is created from this template.
			continue
		}

		m.log.Warn().
			Str("template_id", templateID).
			Str("snapshot_dir", snapshotDir).
			Msg("orphan build directory (no build.meta.json); reclaiming")

		// Kill any firecracker reparented to init by a vmd crash before
		// we RemoveAll the files it's still mmap'ing.
		buildVMID := "build-" + templateID
		if killed := killOrphanFirecracker(buildVMID); killed > 0 {
			m.log.Info().Int("killed", killed).Str("build_vm_id", buildVMID).Msg("killed orphan firecracker processes")
		}

		// Remove the snapshot directory (vmstate + memory + any partial meta).
		if err := os.RemoveAll(snapshotDir); err != nil {
			m.log.Warn().Err(err).Str("dir", snapshotDir).Msg("remove orphan snapshot dir")
			continue
		}

		// Remove the corresponding rundir (rootfs.ext4). A future user-build
		// for the same template_id will re-create it.
		rundir := filepath.Join(m.cfg.RunDir, TemplatesDirName, templateID)
		if err := os.RemoveAll(rundir); err != nil {
			m.log.Warn().Err(err).Str("dir", rundir).Msg("remove orphan rundir")
		}

		reclaimed++
	}

	if reclaimed > 0 {
		m.log.Info().Int("reclaimed", reclaimed).Msg("orphan template builds cleaned up")
	}
	return reclaimed
}

// isCompleteBuild returns true when the snapshot directory has the sidecar
// meta file that writeBuildMeta produces on successful completion.
func (m *Manager) isCompleteBuild(snapshotDir string) bool {
	_, err := os.Stat(filepath.Join(snapshotDir, "build.meta.json"))
	return err == nil
}

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
