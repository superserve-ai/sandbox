package vm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	snapshotsRoot := filepath.Join(m.cfg.SnapshotDir, "templates")
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

		// Stop any lingering build VM systemd unit for this template.
		// Short timeout — we don't want a misbehaving systemctl call to
		// hold up vmd startup.
		buildVMID := "build-" + templateID
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := stopUnit(stopCtx, systemdUnitName(buildVMID)); err != nil {
			// Expected to error when the unit doesn't exist. Only log
			// unexpected errors.
			if !isUnitNotFound(err) {
				m.log.Warn().Err(err).Str("unit", systemdUnitName(buildVMID)).Msg("stop lingering build unit")
			}
		}
		stopCancel()

		// Remove the snapshot directory (vmstate + memory + any partial meta).
		if err := os.RemoveAll(snapshotDir); err != nil {
			m.log.Warn().Err(err).Str("dir", snapshotDir).Msg("remove orphan snapshot dir")
			continue
		}

		// Remove the corresponding rundir (rootfs.ext4). A future user-build
		// for the same template_id will re-create it.
		rundir := filepath.Join(m.cfg.RunDir, "templates", templateID)
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

// isUnitNotFound returns true when a systemctl stop error indicates the unit
// simply doesn't exist (the common case during orphan cleanup). Matches the
// text systemd emits; brittle but acceptable for a log-only decision.
func isUnitNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not loaded") || strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist")
}
