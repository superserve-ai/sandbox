package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserve-ai/sandbox/internal/network"
	"github.com/superserve-ai/sandbox/internal/presence"
)

// TestPlanRestore pins the restore-decision behavior across the four input
// shapes. Earlier code had two switches keying off different signals; a
// stale combination could clobber the per-VM overlay.
func TestPlanRestore(t *testing.T) {
	tests := []struct {
		name       string
		basePath   string
		deltaDir   string
		inPlace    bool
		wantAction restoreDiskAction
		wantDelta  string
	}{
		{
			name:       "create-from-template: fresh overlay, hydrate from delta",
			basePath:   "/run/templates/t/b/base.ext4",
			deltaDir:   "/snap/templates/t/b",
			inPlace:    false,
			wantAction: restoreCreateOverlay,
			wantDelta:  "/snap/templates/t/b",
		},
		{
			name:       "controlplane fallback: reuse existing overlay, no delta",
			basePath:   "/run/templates/t/b/base.ext4",
			deltaDir:   "",
			inPlace:    false,
			wantAction: restoreReuseOverlay,
			wantDelta:  "",
		},
		{
			name:       "in-place resume: reuse, force-empty delta even if caller passes one",
			basePath:   "/run/templates/t/b/base.ext4",
			deltaDir:   "/snap/templates/t/b",
			inPlace:    true,
			wantAction: restoreReuseOverlay,
			wantDelta:  "",
		},
		{
			name:       "legacy: no overlay fields → resolve disk the old way",
			basePath:   "",
			deltaDir:   "",
			inPlace:    false,
			wantAction: restoreLegacyResolve,
			wantDelta:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := planRestore(tc.basePath, tc.deltaDir, tc.inPlace)
			if got.action != tc.wantAction {
				t.Errorf("action = %v, want %v", got.action, tc.wantAction)
			}
			if got.deltaDir != tc.wantDelta {
				t.Errorf("deltaDir = %q, want %q", got.deltaDir, tc.wantDelta)
			}
		})
	}
}

func TestTemplateRunDir(t *testing.T) {
	cfg := ManagerConfig{RunDir: "/var/lib/sandbox/rundir"}
	mgr := &Manager{cfg: cfg}

	got := mgr.templateRunDir()
	want := "/var/lib/sandbox/rundir/template"
	if got != want {
		t.Errorf("templateRunDir() = %q, want %q", got, want)
	}
}

func TestTemplateMagicDir_MatchesTemplateRunDir(t *testing.T) {
	// The exported helper used by cmd/template-builder must agree with vmd's
	// internal templateRunDir — divergence here silently re-introduces the
	// shared-rootfs bug because the build side and restore side would target
	// different paths.
	cfg := ManagerConfig{RunDir: "/var/lib/sandbox/rundir"}
	mgr := &Manager{cfg: cfg}

	if got, want := TemplateMagicDir(cfg.RunDir), mgr.templateRunDir(); got != want {
		t.Errorf("TemplateMagicDir = %q, templateRunDir = %q — must match", got, want)
	}
	if got, want := TemplateMagicRootfsPath(cfg.RunDir), filepath.Join(mgr.templateRunDir(), "rootfs.ext4"); got != want {
		t.Errorf("TemplateMagicRootfsPath = %q, want %q", got, want)
	}
}

func TestTemplateRootfsForSnapshot_RejectsNonTemplatePaths(t *testing.T) {
	// Caller must error out, not silently fall back to BaseRootfsPath.
	for _, p := range []string{"", ".", "/", "/var/lib/sandbox/snapshots/foo"} {
		if _, err := templateRootfsForSnapshot("/var/lib/sandbox/rundir", p); err == nil {
			t.Errorf("expected error for non-template snapshot path %q", p)
		}
	}
}

// TestResolveRestoreDisk_NonTemplate_NoExistingRootfs_Errors is the
// integration-shaped test the PR review asked for: drive the actual disk
// resolution path with a non-template snapshot AND no per-VM rootfs on
// disk, and assert it errors instead of silently using BaseRootfsPath.
func TestResolveRestoreDisk_NonTemplate_NoExistingRootfs_Errors(t *testing.T) {
	runDir := t.TempDir()
	mgr := &Manager{cfg: ManagerConfig{
		RunDir:         runDir,
		BaseRootfsPath: "/should/not/be/used.ext4",
	}}

	_, err := mgr.resolveRestoreDisk(context.Background(), "vm-abc", "/snapshots/not-a-template/vmstate.snap")
	if err == nil {
		t.Fatalf("expected error for non-template snapshot with no per-VM rootfs; got nil")
	}
}

// TestResolveRestoreDisk_SandboxResume_UsesExistingPerVMRootfs covers the
// vmd-cold-restart path: snapshot path isn't a template path, but the
// per-VM rootfs already exists from when the sandbox was first created.
// Resolution should reuse that file (no copy, no error).
func TestResolveRestoreDisk_SandboxResume_UsesExistingPerVMRootfs(t *testing.T) {
	runDir := t.TempDir()
	vmID := "vm-abc"
	existing := filepath.Join(runDir, vmID, "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(existing), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	mgr := &Manager{cfg: ManagerConfig{RunDir: runDir}}
	got, err := mgr.resolveRestoreDisk(context.Background(), vmID, "/snapshots/sb-1/snap-1/vmstate.snap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != existing {
		t.Errorf("got %q, want %q", got, existing)
	}
}

func TestTemplateRootfsForSnapshot(t *testing.T) {
	runDir := "/var/lib/sandbox/rundir"
	cases := []struct {
		name     string
		snapPath string
		want     string
		wantErr  bool
	}{
		{
			name:     "well-formed template snapshot path",
			snapPath: "/var/lib/sandbox/snapshots/templates/abcd-1234/vmstate.snap",
			want:     "/var/lib/sandbox/rundir/templates/abcd-1234/rootfs.ext4",
		},
		{
			name:     "mem.snap also resolves to the same template",
			snapPath: "/var/lib/sandbox/snapshots/templates/abcd-1234/mem.snap",
			want:     "/var/lib/sandbox/rundir/templates/abcd-1234/rootfs.ext4",
		},
		{
			name:     "non-template snapshot path is rejected (re-pause / sandbox snapshots)",
			snapPath: "/var/lib/sandbox/snapshots/sandbox-1/snap-123/vmstate.snap",
			wantErr:  true,
		},
		{
			name:     "missing templates segment is rejected",
			snapPath: "/var/lib/sandbox/snapshots/abcd-1234/vmstate.snap",
			wantErr:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := templateRootfsForSnapshot(runDir, tc.snapPath)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got %q", tc.snapPath, got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTemplateDirNameIsFixed(t *testing.T) {
	if templateDirName != "template" {
		t.Errorf("templateDirName = %q, want %q", templateDirName, "template")
	}
}

// ---------------------------------------------------------------------------
// DeleteSnapshotFiles path-traversal guards
// ---------------------------------------------------------------------------

// writeFile creates a file under dir with the given name, mkdir-p-ing parents.
func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestDeleteSnapshotFiles_UnderVMDir_OK(t *testing.T) {
	root := t.TempDir()
	vmID := "vm-abc"
	snap := filepath.Join(root, vmID, "vmstate.snap")
	mem := filepath.Join(root, vmID, "mem.snap")
	writeFile(t, snap)
	writeFile(t, mem)

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if err := mgr.DeleteSnapshotFiles(vmID, snap, mem); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(snap); !os.IsNotExist(err) {
		t.Errorf("snap still exists: %v", err)
	}
	if _, err := os.Stat(mem); !os.IsNotExist(err) {
		t.Errorf("mem still exists: %v", err)
	}
	// The vm's own root dir is preserved — it belongs to the VM's lifecycle,
	// not the snapshot's. Only strict descendants get the empty-dir cleanup.
	if _, err := os.Stat(filepath.Join(root, vmID)); err != nil {
		t.Errorf("vm dir should be preserved even when empty: %v", err)
	}
}

func TestReadLayeredBase_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")
	base := "/var/lib/sandbox/snapshots/templates/abc/build-1/mem.snap"

	// Missing sidecar → not present.
	if got, ok := readLayeredBase(mem); ok || got != "" {
		t.Errorf("missing sidecar: got (%q,%v), want (\"\",false)", got, ok)
	}

	// Write via the canonical path, read back the exact base.
	if err := os.WriteFile(layeredBaseSidecarPath(mem), []byte(base), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	if got, ok := readLayeredBase(mem); !ok || got != base {
		t.Errorf("round-trip: got (%q,%v), want (%q,true)", got, ok, base)
	}

	// Empty sidecar → not present (a 0-byte record must not be trusted as a base).
	if err := os.WriteFile(layeredBaseSidecarPath(mem), []byte("  \n"), 0o644); err != nil {
		t.Fatalf("write empty sidecar: %v", err)
	}
	if got, ok := readLayeredBase(mem); ok || got != "" {
		t.Errorf("empty sidecar: got (%q,%v), want (\"\",false)", got, ok)
	}
}

func TestFreshenFirstPassOverlay(t *testing.T) {
	dir := t.TempDir()

	// Missing overlay → nil (the normal first-pause case).
	if err := freshenFirstPassOverlay(filepath.Join(dir, "absent.diff")); err != nil {
		t.Errorf("missing overlay: got %v, want nil", err)
	}

	// Existing overlay (and its presence side-car) → both removed, nil.
	f := filepath.Join(dir, "mem.diff")
	if err := os.WriteFile(f, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(presence.SidecarPath(f), []byte("stale bits"), 0o600); err != nil {
		t.Fatalf("write side-car: %v", err)
	}
	if err := freshenFirstPassOverlay(f); err != nil {
		t.Errorf("existing overlay: got %v, want nil", err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("overlay not removed: %v", err)
	}
	if _, err := os.Stat(presence.SidecarPath(f)); !os.IsNotExist(err) {
		t.Errorf("presence side-car not removed: %v", err)
	}

	// Un-removable overlay (non-empty dir stands in for any remove failure) → error,
	// which drives the caller's fall-back-to-Full path.
	stuck := filepath.Join(dir, "stuck.diff")
	if err := os.MkdirAll(filepath.Join(stuck, "child"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := freshenFirstPassOverlay(stuck); err == nil {
		t.Error("un-removable overlay: got nil, want error (so caller falls back to Full)")
	}
}

func TestDeleteSnapshotFiles_RemovesSidecars(t *testing.T) {
	root := t.TempDir()
	vmID := "vm-abc"
	snap := filepath.Join(root, vmID, "vmstate.snap")
	mem := filepath.Join(root, vmID, "mem.diff")
	overlay := snap + ".overlay"
	base := layeredBaseSidecarPath(mem)   // mem.diff.base
	presence := presence.SidecarPath(mem) // mem.diff.presence
	for _, p := range []string{snap, mem, overlay, base, presence} {
		writeFile(t, p)
	}

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if err := mgr.DeleteSnapshotFiles(vmID, snap, mem); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// A leftover sidecar would make a later restore mis-handle a non-layered
	// mem file as a layered overlay — and a stale .presence next to a future
	// same-size overlay passes Firecracker's geometry checks and silently
	// mis-layers pages. All must go with the files they describe.
	for _, p := range []string{overlay, base, presence} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("sidecar still exists: %s (%v)", p, err)
		}
	}
}

func TestGateOverlayPresence(t *testing.T) {
	dir := t.TempDir()
	mem := filepath.Join(dir, "mem.diff")
	nop := zerolog.Nop()

	// Missing side-car, gate off → allowed (warn-only compat for pre-side-car
	// local snapshots).
	m := &Manager{}
	if err := m.gateOverlayPresence(mem, nop); err != nil {
		t.Errorf("gate off: got %v, want nil", err)
	}

	// Missing side-car, gate on → refused, carrying the sentinel both restore
	// entry points map to FailedPrecondition. Without the sentinel the fresh
	// path would surface this deterministic refusal as a retryable error.
	m = &Manager{cfg: ManagerConfig{RequirePresenceSidecar: "always"}}
	err := m.gateOverlayPresence(mem, nop)
	if !errors.Is(err, ErrPresenceSidecarMissing) {
		t.Errorf("gate on: got %v, want ErrPresenceSidecarMissing", err)
	}

	// Side-car present → allowed regardless of the gate. Only confirmed
	// absence gates; other stat outcomes defer to Firecracker's own read.
	writeFile(t, presence.SidecarPath(mem))
	if err := m.gateOverlayPresence(mem, nop); err != nil {
		t.Errorf("side-car present: got %v, want nil", err)
	}
}

func TestDeleteSnapshotFiles_PathEqualSnapshotRoot_Rejected(t *testing.T) {
	root := t.TempDir()
	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}

	if err := mgr.DeleteSnapshotFiles("vm-abc", root, ""); err == nil {
		t.Error("expected rejection when path equals SnapshotDir root")
	}
}

func TestDeleteSnapshotFiles_PathEqualVMDir_Rejected(t *testing.T) {
	root := t.TempDir()
	vmID := "vm-abc"
	vmDir := filepath.Join(root, vmID)
	if err := os.MkdirAll(vmDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}

	if err := mgr.DeleteSnapshotFiles(vmID, vmDir, ""); err == nil {
		t.Error("expected rejection when path equals the vm's snapshot dir")
	}
}

func TestDeleteSnapshotFiles_RelativePath_Rejected(t *testing.T) {
	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: t.TempDir()}}
	if err := mgr.DeleteSnapshotFiles("vm-abc", "relative/path.snap", ""); err == nil {
		t.Error("expected rejection for relative path")
	}
}

func TestDeleteSnapshotFiles_DotDotTraversal_Rejected(t *testing.T) {
	root := t.TempDir()
	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}

	// Path that cleans to something outside <root>/<vmID>/.
	bad := filepath.Join(root, "vm-abc", "..", "..", "etc", "passwd")
	if err := mgr.DeleteSnapshotFiles("vm-abc", bad, ""); err == nil {
		t.Error("expected rejection for .. traversal escaping vm dir")
	}
}

func TestDeleteSnapshotFiles_WrongVMID_Rejected(t *testing.T) {
	root := t.TempDir()
	// File belongs to vm-other, but we ask the manager to delete it as vm-abc.
	snap := filepath.Join(root, "vm-other", "vmstate.snap")
	writeFile(t, snap)

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if err := mgr.DeleteSnapshotFiles("vm-abc", snap, ""); err == nil {
		t.Error("expected rejection when path lives under a different vmID")
	}
	if _, err := os.Stat(snap); err != nil {
		t.Errorf("file for wrong vmID should not have been touched: %v", err)
	}
}

func TestDeleteSnapshotFiles_MissingFiles_Idempotent(t *testing.T) {
	root := t.TempDir()
	vmID := "vm-abc"
	snap := filepath.Join(root, vmID, "vmstate.snap")
	mem := filepath.Join(root, vmID, "mem.snap")

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if err := mgr.DeleteSnapshotFiles(vmID, snap, mem); err != nil {
		t.Fatalf("idempotent delete on missing files should succeed: %v", err)
	}
}

func TestDeleteSnapshotFiles_BothEmpty_Rejected(t *testing.T) {
	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: t.TempDir()}}
	if err := mgr.DeleteSnapshotFiles("vm-abc", "", ""); err == nil {
		t.Error("expected rejection when both paths are empty")
	}
}

// TestDestroyVM_AbsentInstance_CleansRundir: destroying a VM that's absent from
// m.vms (e.g. a paused sandbox) must still remove its rundir, not leak it.
func TestDestroyVM_AbsentInstance_CleansRundir(t *testing.T) {
	runDir := t.TempDir()
	vmID := "11111111-1111-1111-1111-111111111111"
	dir := filepath.Join(runDir, vmID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlay.ext4"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// nil vms → getInstance NotFound (the absent path); zero-value netMgr and
	// nil state make CleanupVM/deleteState no-ops for an unknown vmID.
	mgr := &Manager{
		cfg:    ManagerConfig{RunDir: runDir},
		netMgr: &network.Manager{},
		log:    zerolog.Nop(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.DestroyVM(ctx, vmID, true); err != nil {
		t.Fatalf("DestroyVM: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("rundir %s still present after DestroyVM — leaked", dir)
	}
}

// TestDestroyVM_UnsafeVMID_Rejected: a non-path-safe or reserved vmID is
// rejected before cleanup, so it can't escape RunDir or wipe shared dirs.
func TestDestroyVM_UnsafeVMID_Rejected(t *testing.T) {
	runDir := t.TempDir()
	shared := []string{"keep", templateDirName, TemplatesDirName}
	for _, name := range shared {
		if err := os.MkdirAll(filepath.Join(runDir, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}

	mgr := &Manager{
		cfg:    ManagerConfig{RunDir: runDir},
		netMgr: &network.Manager{},
		log:    zerolog.Nop(),
	}

	rejected := []string{"", ".", "..", "../escape", "a/b", templateDirName, TemplatesDirName}
	for _, vmID := range rejected {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := mgr.DestroyVM(ctx, vmID, true)
		cancel()
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("DestroyVM(%q): want InvalidArgument, got %v", vmID, err)
		}
	}
	for _, name := range shared {
		if _, err := os.Stat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("shared dir %q removed by a rejected vmID: %v", name, err)
		}
	}

	// Per-VM build/recording ids must remain cleanable, not reserved.
	for _, vmID := range []string{"build-tmpl1", "build-record-tmpl1"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := mgr.DestroyVM(ctx, vmID, true)
		cancel()
		if err != nil {
			t.Errorf("DestroyVM(%q): want nil, got %v", vmID, err)
		}
	}
}

func TestDeleteSnapshotFiles_EmptyVMID_Rejected(t *testing.T) {
	root := t.TempDir()
	snap := filepath.Join(root, "vm-abc", "vmstate.snap")
	writeFile(t, snap)

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if err := mgr.DeleteSnapshotFiles("", snap, ""); err == nil {
		t.Error("expected rejection when vmID is empty")
	}
}

func TestDeleteSnapshotFiles_NonEmptyDir_Kept(t *testing.T) {
	root := t.TempDir()
	vmID := "vm-abc"
	snap := filepath.Join(root, vmID, "vmstate.snap")
	mem := filepath.Join(root, vmID, "mem.snap")
	sibling := filepath.Join(root, vmID, "other.file")
	writeFile(t, snap)
	writeFile(t, mem)
	writeFile(t, sibling)

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if err := mgr.DeleteSnapshotFiles(vmID, snap, mem); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, vmID)); err != nil {
		t.Errorf("non-empty vm dir should have been kept: %v", err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Errorf("sibling file should have been kept: %v", err)
	}
}

func TestDeleteSandboxSnapshots_RemovesWholeDir(t *testing.T) {
	root := t.TempDir()
	vmID := "11111111-1111-1111-1111-111111111111"
	writeFile(t, filepath.Join(root, vmID, "mem.snap"))
	writeFile(t, filepath.Join(root, vmID, "vmstate.snap"))

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if err := mgr.DeleteSandboxSnapshots(vmID); err != nil {
		t.Fatalf("DeleteSandboxSnapshots: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, vmID)); !os.IsNotExist(err) {
		t.Fatalf("snapshot dir still present after delete")
	}
	// Idempotent: a second call on a missing dir is not an error.
	if err := mgr.DeleteSandboxSnapshots(vmID); err != nil {
		t.Fatalf("DeleteSandboxSnapshots (missing): %v", err)
	}
}

func TestDeleteSandboxSnapshots_RejectsReservedAndUnsafe(t *testing.T) {
	root := t.TempDir()
	// The shared template snapshot tree must never be removable via this call.
	tmplFile := filepath.Join(root, TemplatesDirName, "tpl1", "base.snap")
	writeFile(t, tmplFile)

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	for _, vmID := range []string{"", ".", "..", "../escape", "a/b", templateDirName, TemplatesDirName} {
		if status.Code(mgr.DeleteSandboxSnapshots(vmID)) != codes.InvalidArgument {
			t.Errorf("DeleteSandboxSnapshots(%q): want InvalidArgument", vmID)
		}
	}
	if _, err := os.Stat(tmplFile); err != nil {
		t.Fatalf("template snapshot tree removed by a rejected vmID: %v", err)
	}

	// Unconfigured snapshot dir must be rejected, not joined into a relative path.
	empty := &Manager{}
	if status.Code(empty.DeleteSandboxSnapshots("11111111-1111-1111-1111-111111111111")) != codes.InvalidArgument {
		t.Error("DeleteSandboxSnapshots with empty SnapshotDir: want InvalidArgument")
	}
}

func TestDeleteSnapshotFiles_NestedSnapDir_ParentCleaned(t *testing.T) {
	root := t.TempDir()
	vmID := "vm-abc"
	// Re-pause layout: <root>/<vmID>/snap-123/vmstate.snap
	snap := filepath.Join(root, vmID, "snap-123", "vmstate.snap")
	mem := filepath.Join(root, vmID, "snap-123", "mem.snap")
	writeFile(t, snap)
	writeFile(t, mem)

	mgr := &Manager{cfg: ManagerConfig{SnapshotDir: root}}
	if err := mgr.DeleteSnapshotFiles(vmID, snap, mem); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// snap-123 (strict descendant of vm dir) should be removed.
	if _, err := os.Stat(filepath.Join(root, vmID, "snap-123")); !os.IsNotExist(err) {
		t.Errorf("empty snap-123 should have been cleaned up: %v", err)
	}
	// vm dir itself should NOT be removed — it's the vm's root, not a strict descendant.
	if _, err := os.Stat(filepath.Join(root, vmID)); err != nil {
		t.Errorf("vm dir should be preserved even when empty: %v", err)
	}
}

func TestDeleteSnapshotFiles_NoSnapshotDirConfigured_Rejected(t *testing.T) {
	mgr := &Manager{cfg: ManagerConfig{}}
	if err := mgr.DeleteSnapshotFiles("vm-abc", "/tmp/anything", ""); err == nil {
		t.Error("expected rejection when SnapshotDir is unconfigured")
	}
}

func newTestManager() *Manager {
	return &Manager{log: zerolog.Nop()}
}

func TestRecordWarmup_CompletesWhenTimerFires(t *testing.T) {
	start := time.Now()
	got := recordWarmup(context.Background(), 20*time.Millisecond)
	elapsed := time.Since(start)
	if got != warmupCompleted {
		t.Fatalf("got %v, want warmupCompleted", got)
	}
	if elapsed < 15*time.Millisecond {
		t.Fatalf("returned too early: %v", elapsed)
	}
}

func TestRecordWarmup_ReturnsCancelledWhenCtxFiresFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	start := time.Now()
	got := recordWarmup(ctx, 5*time.Second)
	elapsed := time.Since(start)
	if got != warmupCancelled {
		t.Fatalf("got %v, want warmupCancelled", got)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("cancellation did not propagate promptly: %v", elapsed)
	}
}

func TestInspectRecordedTrace_MissingFile(t *testing.T) {
	pages, exists := inspectRecordedTrace(filepath.Join(t.TempDir(), "does-not-exist.log"))
	if exists {
		t.Errorf("exists = true for missing file")
	}
	if pages != 0 {
		t.Errorf("pages = %d for missing file, want 0", pages)
	}
}

func TestInspectRecordedTrace_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	pages, exists := inspectRecordedTrace(path)
	if !exists {
		t.Errorf("exists = false for empty file")
	}
	if pages != 0 {
		t.Errorf("pages = %d for empty file, want 0", pages)
	}
}

func TestInspectRecordedTrace_CountsLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.log")
	if err := os.WriteFile(path, []byte("0\n4096\n8192\n12288\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pages, exists := inspectRecordedTrace(path)
	if !exists {
		t.Errorf("exists = false for present file")
	}
	if pages != 4 {
		t.Errorf("pages = %d, want 4", pages)
	}
}

// shortSockPath returns a socket path safely under sun_path's ~108-byte
// cap — t.TempDir embeds long test names that can blow it.
func shortSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fcs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

// bindOnlySocket creates a unix socket file via bind() WITHOUT listen() —
// the exact state a connect() gets ECONNREFUSED from. Returns the fd so the
// test can listen() later.
func bindOnlySocket(t *testing.T, path string) int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

func TestWaitForSocket_AlreadyListening(t *testing.T) {
	path := shortSockPath(t)
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := waitForSocket(path, time.Second); err != nil {
		t.Errorf("waitForSocket on listening socket: %v", err)
	}
}

func TestWaitForSocket_AppearsAfterStart(t *testing.T) {
	path := shortSockPath(t)

	lch := make(chan net.Listener, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Error(err)
		}
		lch <- l
	}()
	defer func() {
		if l := <-lch; l != nil {
			l.Close()
		}
	}()

	start := time.Now()
	if err := waitForSocket(path, time.Second); err != nil {
		t.Errorf("waitForSocket: %v", err)
	}
	// 100ms guards against an accidental fall-through to polling.
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("waitForSocket took %s; expected < 100ms", elapsed)
	}
}

func TestWaitForSocket_TimesOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "never-appears")
	err := waitForSocket(path, 50*time.Millisecond)
	if err == nil {
		t.Errorf("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "did not appear within 50ms") {
		t.Errorf("error should state the budget, got: %v", err)
	}
}

func TestWaitForSocket_BindListenGap(t *testing.T) {
	// The socket FILE exists (bind done) but refuses connections until
	// listen() — waitForSocket must wait out the gap, not return early.
	path := shortSockPath(t)
	fd := bindOnlySocket(t, path)

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = syscall.Listen(fd, 8)
	}()

	if err := waitForSocket(path, time.Second); err != nil {
		t.Errorf("waitForSocket across the bind→listen gap: %v", err)
	}
}

func TestWaitForSocket_NeverListens_FailsWithinCap(t *testing.T) {
	// A bound-but-dead socket refuses forever; the connect phase must give
	// up at its 1s cap, not spin the caller's full budget.
	path := shortSockPath(t)
	bindOnlySocket(t, path) // file exists, never listens

	start := time.Now()
	err := waitForSocket(path, 10*time.Second)
	if err == nil {
		t.Fatal("expected an error for a socket that never accepts")
	}
	if !strings.Contains(err.Error(), "not accepting connections") {
		t.Errorf("error should name the refused state, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("gave up after %s; the connect phase is capped at 1s", elapsed)
	}
}

func TestWaitForSocketConnectable_NonRefusedFailsFast(t *testing.T) {
	// Anything but ECONNREFUSED (here: ENOENT from a teardown race) must
	// surface immediately, not spin until the deadline.
	dir := t.TempDir()
	path := filepath.Join(dir, "gone")

	start := time.Now()
	err := waitForSocketConnectable(path, time.Now().Add(5*time.Second))
	if err == nil {
		t.Fatal("expected an error for a missing socket")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("non-refused error took %s to surface; must fail fast", elapsed)
	}
}

func TestShouldWriteDiff(t *testing.T) {
	const base = "/snap/vm/mem.snap"
	cases := []struct {
		name                      string
		incremental, dirtyTracked bool
		memPath, resumeBase       string
		baseExists                bool
		want                      bool
	}{
		{"all conditions met", true, true, base, base, true, true},
		{"feature off", false, true, base, base, true, false},
		{"tracking not armed (e.g. cold create or non-incremental resume)", true, false, base, base, true, false},
		{"different path than resume base (custom snapshot dir)", true, true, "/snap/vm/other.snap", base, true, false},
		{"base file missing (first pause)", true, true, base, base, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldWriteDiff(c.incremental, c.dirtyTracked, c.memPath, c.resumeBase, c.baseExists); got != c.want {
				t.Fatalf("shouldWriteDiff = %v, want %v", got, c.want)
			}
		})
	}
}

func TestIsTemplateMemPath(t *testing.T) {
	m := &Manager{cfg: ManagerConfig{SnapshotDir: "/var/lib/sandbox/snapshots"}}
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"flat template", "/var/lib/sandbox/snapshots/templates/abc/mem.snap", true},
		{"build-nested template", "/var/lib/sandbox/snapshots/templates/abc/build-abc/mem.snap", true},
		{"paused sandbox (not template)", "/var/lib/sandbox/snapshots/vm123/mem.snap", false},
		{"layered overlay of a sandbox", "/var/lib/sandbox/snapshots/vm123/mem.diff", false},
		{"empty", "", false},
		{"templates substring elsewhere", "/var/lib/sandbox/snapshots/vm-templates-x/mem.snap", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := m.isTemplateMemPath(c.path); got != c.want {
				t.Fatalf("isTemplateMemPath(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
	if isOverlayMemFile("/x/mem.diff") != true || isOverlayMemFile("/x/mem.snap") != false {
		t.Fatal("isOverlayMemFile basename detection wrong")
	}
}

// waitForPIDExit is the primitive the restore-error tap0 fix relies on: after
// SIGKILLing the lingering Firecracker, stopUnitDuringRestoreError must block
// until the process is actually gone (its tap0 fd released) before the slot is
// recycled. These pin both directions of that behavior.

func TestWaitForPIDExit_LiveProcessWaitsFullTimeout(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	start := time.Now()
	waitForPIDExit(pid, 200*time.Millisecond)
	elapsed := time.Since(start)

	// A live process is never reaped, so the wait must burn ~the full timeout —
	// this is what forces the cleanup to wait for the tap fd before recycling.
	if elapsed < 150*time.Millisecond {
		t.Errorf("returned after %v; expected to wait ~200ms for a live process", elapsed)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Errorf("process should still be alive after the wait: %v", err)
	}
}

func TestWaitForPIDExit_DeadProcessReturnsPromptly(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Kill()
	_ = cmd.Wait() // reap so kill(pid,0) sees ESRCH, mirroring systemd reaping the FC

	start := time.Now()
	waitForPIDExit(pid, 2*time.Second)
	elapsed := time.Since(start)

	// Once the process is gone the wait must return promptly, not stall the
	// restore-error cleanup for the whole timeout.
	if elapsed > 500*time.Millisecond {
		t.Errorf("returned after %v; expected a prompt return once the process exited", elapsed)
	}
}

func TestPauseVM_AlreadyPaused_ReturnsRecordedSnapshot(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inst := &VMInstance{
		ID:           "vm-1",
		Status:       StatusPaused,
		SnapshotPath: snapPath,
		MemFilePath:  memPath,
	}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": inst}}

	snap, mem, _, err := mgr.PauseVM(context.Background(), "vm-1", "")
	if err != nil {
		t.Fatalf("retried pause of a paused VM should succeed, got %v", err)
	}
	if snap != snapPath || mem != memPath {
		t.Fatalf("got (%q, %q), want the recorded snapshot artifacts", snap, mem)
	}
}

func TestPauseVM_AlreadyPausedButArtifactsMissing_Fails(t *testing.T) {
	dir := t.TempDir()
	inst := &VMInstance{
		ID:           "vm-1",
		Status:       StatusPaused,
		SnapshotPath: filepath.Join(dir, "gone-vmstate.snap"),
		MemFilePath:  filepath.Join(dir, "gone-mem.snap"),
	}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": inst}}

	_, _, _, err := mgr.PauseVM(context.Background(), "vm-1", "")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for dangling artifacts, got %v", err)
	}
}

func TestRestoreVMSnapshot_AlreadyRunningHealthy_ReturnsExisting(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()
	gated := false
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(context.Context, *Manager, string) error { gated = true; return nil }
	defer func() { adoptionBoxdReady = origReady }()

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		vms:        map[string]*VMInstance{"vm-1": existing},
		restoreSem: make(chan struct{}, 1),
	}

	inst, err := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if err != nil {
		t.Fatalf("retried restore of a healthy running VM should succeed, got %v", err)
	}
	if inst != existing {
		t.Fatal("expected the existing running instance, not a re-restore")
	}
	if gated {
		t.Fatal("a verified record must adopt without the readiness gate — a wedged boxd must not be able to demote it")
	}
	mgr.mu.RLock()
	still := mgr.vms["vm-1"]
	mgr.mu.RUnlock()
	if still != existing {
		t.Fatal("existing instance must remain tracked untouched")
	}
}

// A vanished caller must not stop the gate reaching a verdict. Callers arrive
// with a deadline no larger than the gate's own budget, so if cancellation
// meant "no verdict" the record would never flip and every retry would repeat
// the same wait — the sandbox stuck until the orphan reaper hours later.
func TestRestoreVMSnapshot_AdoptionWaitCanceled_StillReachesVerdict(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()
	ctx, cancel := context.WithCancel(context.Background())
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(c context.Context, _ *Manager, _ string) error {
		cancel() // the caller goes away mid-wait
		if c.Err() != nil {
			return c.Err() // inherited ctx: would end "no verdict"
		}
		return errors.New("boxd silent for the whole budget") // genuine verdict
	}
	defer func() { adoptionBoxdReady = origReady }()

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		vms:        map[string]*VMInstance{"vm-1": existing},
		restoreSem: make(chan struct{}, 1),
	}

	_, err := mgr.RestoreVMSnapshot(ctx, "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if err == nil {
		t.Fatal("a silent guest must fail the adoption")
	}
	// The verdict must come from the PROBE, not from the caller vanishing:
	// acting on a cancellation would flip a possibly-healthy VM to Error.
	if errors.Is(err, context.Canceled) {
		t.Fatal("the gate must not treat caller cancellation as a verdict about the VM")
	}
	// The verdict must be applied: Running would leave the record adoptable
	// and the next retry would repeat this wait forever.
	existing.mu.RLock()
	status := existing.Status
	existing.mu.RUnlock()
	if status != StatusError {
		t.Fatalf("a definitive verdict must flip the record out of Running, got %s", status)
	}
}

// A destroy landing inside the adoption readiness wait must not be reported
// as a successful restore.
func TestRestoreVMSnapshot_DestroyedDuringAdoptionWait_Fails(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(_ context.Context, m *Manager, _ string) error {
		m.mu.Lock()
		delete(m.vms, "vm-1") // destroy races the wait
		m.mu.Unlock()
		return nil
	}
	defer func() { adoptionBoxdReady = origReady }()

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		vms:        map[string]*VMInstance{"vm-1": existing},
		restoreSem: make(chan struct{}, 1),
	}

	if _, err := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0); err == nil {
		t.Fatal("a VM destroyed during the adoption wait must not restore successfully")
	}
}

// The crash-window guard: a reattached Running record whose restore was
// interrupted before readiness must not be adopted as a successful create.
func TestRestoreVMSnapshot_AdoptedButBoxdNeverReady_Fails(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(context.Context, *Manager, string) error {
		return errors.New("boxd never became ready")
	}
	defer func() { adoptionBoxdReady = origReady }()

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		vms:        map[string]*VMInstance{"vm-1": existing},
		restoreSem: make(chan struct{}, 1),
	}

	if _, err := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0); err == nil {
		t.Fatal("adopting an unverified VM must fail when boxd never becomes ready")
	}
	// The failed adoption must break the adoption gates: a Running record
	// would be re-gated by every retry, never converging.
	existing.mu.RLock()
	status := existing.Status
	existing.mu.RUnlock()
	if status == StatusRunning {
		t.Fatal("a definitively-unready adopted VM must not stay Running")
	}
}

func TestRestoreVMSnapshot_DifferentArtifacts_NotTreatedAsRetry(t *testing.T) {

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The live VM was restored from other artifacts: the request must NOT
	// short-circuit to it, even with boxd healthy.
	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5",
		SnapshotPath: filepath.Join(dir, "old-vmstate.snap"),
		MemFilePath:  filepath.Join(dir, "old-mem.snap"),
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		vms:        map[string]*VMInstance{"vm-1": existing},
		restoreSem: make(chan struct{}, 1),
	}

	inst, _ := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if inst == existing {
		t.Fatal("a restore for different artifacts must not return the old VM")
	}
}

func TestResumeVM_AlreadyRunningHealthy_ReturnsExisting(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()

	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5",
		SnapshotPath: "/snapshots/vm-1/vmstate.snap",
		MemFilePath:  "/snapshots/vm-1/mem.snap",
	}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}}

	inst, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "")
	if err != nil {
		t.Fatalf("retried resume of a healthy running VM should succeed, got %v", err)
	}
	if inst != existing {
		t.Fatal("expected the existing running instance, not a relaunch")
	}
}

// Resume adoption verifies an unverified target before adopting it. When that
// verdict comes back negative the record is a corpse, so it must not be
// adopted — the resume falls through to a fresh launch instead.
func TestResumeVM_UnverifiedRecord_NotAdopted(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(context.Context, *Manager, string) error {
		return errors.New("boxd never became ready") // a genuine corpse verdict
	}
	defer func() { adoptionBoxdReady = origReady }()

	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: "/snapshots/vm-1/vmstate.snap",
		MemFilePath:  "/snapshots/vm-1/mem.snap",
	}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}}

	// The fallthrough fails on the missing snapshot files — the assertion is
	// only that the corpse was not returned as a healthy VM.
	inst, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "")
	if err == nil && inst == existing {
		t.Fatal("an unverified record that fails verification must not be adopted")
	}
}

func TestVMOpLock_SerializesSameID_TryLockSkips(t *testing.T) {
	m := &Manager{log: zerolog.Nop()}

	unlock, err := m.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatal(err)
	}
	// A different vmID is independent — must acquire freely.
	if u2, ok := m.tryLockVMOp("vm-2"); !ok {
		t.Fatal("different vmID must not contend")
	} else {
		u2()
	}
	// The held vmID must not be re-acquirable (this is what makes the
	// reconciler skip a unit a launch is mid-flight on).
	if _, ok := m.tryLockVMOp("vm-1"); ok {
		t.Fatal("held vmID must fail TryLock")
	}
	// A queued acquire whose context is already cancelled returns ctx.Err()
	// instead of waiting for the lock — no abandoned pause/restore work.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.lockVMOp(cancelled, "vm-1"); err == nil {
		t.Fatal("cancelled context must not acquire a held lock")
	}
	// Free lock + already-cancelled ctx: even if the random select picks
	// the send case, the post-acquire recheck must release and return err,
	// not leave the lock held.
	freeCancel, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if u, err := m.lockVMOp(freeCancel, "vm-free"); err == nil {
		u()
		t.Fatal("cancelled ctx must not acquire even a free lock")
	}
	if u, ok := m.tryLockVMOp("vm-free"); !ok {
		t.Fatal("a cancelled acquire must not leave the lock held")
	} else {
		u()
	}
	unlock()
	// Released — now acquirable.
	if u, ok := m.tryLockVMOp("vm-1"); !ok {
		t.Fatal("released vmID must be acquirable")
	} else {
		u()
	}
}

func TestRestoreVMSnapshot_RunningRecordButUnitDead_NotReturned(t *testing.T) {
	// A record can read Running while the firecracker process is gone. The
	// retry guard must not hand back that corpse — it must fall through to
	// a fresh restore.
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return true } // unit definitively dead
	defer func() { vmUnitDead = orig }()

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}}

	if got, _ := m.retriedLaunchTarget("vm-1", snapPath, memPath); got != nil {
		t.Fatal("a dead-unit Running record must not be returned as a retry target")
	}
}

func TestInstanceRunning(t *testing.T) {
	m := &Manager{
		log: zerolog.Nop(),
		vms: map[string]*VMInstance{
			"run":   {ID: "run", Status: StatusRunning},
			"pause": {ID: "pause", Status: StatusPaused},
		},
	}
	if !m.instanceRunning("run") {
		t.Fatal("running instance must report running")
	}
	if m.instanceRunning("pause") {
		t.Fatal("paused instance must not report running (a genuine stale-unit target)")
	}
	if m.instanceRunning("absent") {
		t.Fatal("absent instance must not report running")
	}
}

// A reattached crash-window record (Running persisted before readiness) must
// not be adopted; the caller falls through to a fresh, verified restore. The
// durable flag must also stay off the wire for verified records so rollback
// binaries read them unchanged.
func TestRetriedLaunchTargetFlagsUnverifiedRecord(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()

	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: "/snapshots/vm-1/vmstate.snap",
		MemFilePath:  "/snapshots/vm-1/mem.snap",
	}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}}
	got, needsVerify := mgr.retriedLaunchTarget("vm-1", existing.SnapshotPath, existing.MemFilePath)
	if got == nil || !needsVerify {
		t.Fatal("an unverified Running record must be returned flagged for verification")
	}

	existing.Unverified = false
	got, needsVerify = mgr.retriedLaunchTarget("vm-1", existing.SnapshotPath, existing.MemFilePath)
	if got == nil || needsVerify {
		t.Fatal("a verified Running record must be adoptable without verification")
	}

	out, err := json.Marshal(toRecord(existing))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "unverified") {
		t.Fatalf("verified records must omit the unverified key, got %s", out)
	}
	unv := toRecord(&VMInstance{ID: "u", Status: StatusRunning, Unverified: true})
	round, err := json.Marshal(unv)
	if err != nil {
		t.Fatal(err)
	}
	var back VMRecord
	if err := json.Unmarshal(round, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Unverified {
		t.Fatal("unverified must survive the record round-trip")
	}
}

// The durable half of verification: the background persist after a successful
// readiness wait clears the unverified marker in BoltDB, so after a vmd
// restart a duplicate delivery adopts the live VM instead of refusing the
// record and relaunching it (which rolls the guest back to its snapshot).
func TestRestoreVMSnapshot_VerifiedRecordAfterRestart_Adopted(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(context.Context, *Manager, string) error { return nil } // boxd healthy
	defer func() { adoptionBoxdReady = origReady }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	inst := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	mgr := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": inst}}
	mgr.persistState(inst) // the optimistic pre-wait persist

	// What the success path runs once readiness is proven.
	inst.mu.Lock()
	inst.Unverified = false
	inst.mu.Unlock()
	mgr.persistStateIfPresent(inst)

	// Simulated vmd restart: only the durable record survives.
	rec, err := store.Get("vm-1")
	if err != nil || rec == nil {
		t.Fatalf("record must survive the restart: %v", err)
	}
	if rec.Unverified {
		t.Fatal("the verified clear must be durable, not in-memory only")
	}
	reloaded := toInstance(*rec)
	mgr2 := &Manager{
		log:        zerolog.Nop(),
		state:      store,
		vms:        map[string]*VMInstance{"vm-1": reloaded},
		restoreSem: make(chan struct{}, 1),
	}

	got, err := mgr2.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if err != nil {
		t.Fatalf("duplicate delivery after restart must adopt the live VM, got %v", err)
	}
	if got != reloaded {
		t.Fatal("expected adoption of the reattached instance, not a relaunch")
	}
}

// A crash between the response and the background verified persist leaves a
// durable unverified record for a live VM. The next duplicate delivery must
// re-verify and adopt it — and heal the marker — rather than relaunching it
// and rolling the guest back.
func TestRestoreVMSnapshot_UnverifiedRecordAfterRestart_ReverifiedAndAdopted(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(context.Context, *Manager, string) error { return nil } // boxd healthy
	defer func() { adoptionBoxdReady = origReady }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	inst := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	mgr := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": inst}}
	mgr.persistState(inst)
	// Crash here: the verified persist never ran.

	rec, err := store.Get("vm-1")
	if err != nil || rec == nil {
		t.Fatalf("record must survive the restart: %v", err)
	}
	reloaded := toInstance(*rec)
	mgr2 := &Manager{
		log:        zerolog.Nop(),
		state:      store,
		vms:        map[string]*VMInstance{"vm-1": reloaded},
		restoreSem: make(chan struct{}, 1),
	}

	got, err := mgr2.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner", "", nil, 0)
	if err != nil {
		t.Fatalf("a healthy unverified VM must be re-verified and adopted, got %v", err)
	}
	if got != reloaded {
		t.Fatal("expected adoption of the reattached instance, not a relaunch")
	}
	healed, err := store.Get("vm-1")
	if err != nil || healed == nil {
		t.Fatal(err)
	}
	if healed.Unverified {
		t.Fatal("successful re-verification must clear the durable marker")
	}
}

// A restore whose state cannot be made durable must not report success: the
// VM would be invisible to the next reattach. Pinned here at the store
// layer: a persist into a closed store reports failure rather than logging
// and claiming success.
func TestPersistStateReportsFailure(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": inst}}
	if !m.persistState(inst) {
		t.Fatal("persist into a healthy store must report success")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if m.persistState(inst) {
		t.Fatal("persist into a broken store must report failure, not log and claim success")
	}
}

// The unverified-relaunch readiness gate tears the VM down on failure, so it
// must probe on a ctx detached from the caller: a client disconnect or spent
// deadline must not masquerade as a dead guest — and a completed wait clears
// the marker so the next retry adopts instead of relaunching.
func TestVerifyBoxdReadyDetachedFromCaller(t *testing.T) {
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	cancelCaller() // caller already gone before the gate runs

	var gateCtxDone bool
	orig := adoptionBoxdReady
	adoptionBoxdReady = func(ctx context.Context, _ *Manager, _ string) error {
		gateCtxDone = ctx.Err() != nil
		return nil
	}
	defer func() { adoptionBoxdReady = orig }()

	m := &Manager{log: zerolog.Nop()}
	if err := m.verifyBoxdReady(callerCtx, "192.0.2.5"); err != nil {
		t.Fatalf("healthy gate must pass, got %v", err)
	}
	if gateCtxDone {
		t.Fatal("relaunch gate must run on a ctx detached from the caller — a dead caller must not read as a dead guest")
	}
}

// An unverified retry target must be VERIFIED and adopted by resume, not
// blindly refused: refusal relaunches over a possibly-live guest, and a stale
// marker (swallowed clear, crash before the verified persist) would make that
// rollback happen to a healthy VM. Success must also heal the marker durably.
func TestResumeVM_UnverifiedTarget_VerifiedAndAdopted(t *testing.T) {
	origDead := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = origDead }()
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(context.Context, *Manager, string) error { return nil }
	defer func() { adoptionBoxdReady = origReady }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: "/snapshots/vm-1/vmstate.snap",
		MemFilePath:  "/snapshots/vm-1/mem.snap",
	}
	if err := store.Put(toRecord(existing)); err != nil {
		t.Fatal(err)
	}
	mgr := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": existing}}

	inst, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "")
	if err != nil {
		t.Fatalf("verified adoption must succeed, got %v", err)
	}
	if inst != existing {
		t.Fatal("expected the existing live instance, not a relaunch")
	}
	if inst.Unverified {
		t.Fatal("adoption must clear the marker in memory")
	}
	rec, err := store.Get("vm-1")
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	if rec.Unverified {
		t.Fatal("adoption must clear the marker durably")
	}
}

// commitVerifiedAdoption must treat the store refusing the marker-clear write
// (record deleted by a concurrent destroy) as NotFound, never success.
func TestCommitVerifiedAdoption_DestroyedRecordIsNotFound(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// No record in the store: PutIfPresent refuses — the destroy signal.
	existing := &VMInstance{ID: "vm-1", Status: StatusRunning, Unverified: true}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": existing}}

	err = m.commitVerifiedAdoption(existing)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("a refused marker-clear write must surface NotFound, got %v", err)
	}
}

// The post-resume readiness gate must probe on a ctx detached from the
// caller: a client disconnect mid-gate must not read as a dead guest and tear
// down a healthy VM the control plane's retry would have adopted.
func TestResumeReadyOrAbortGateDetachedFromCaller(t *testing.T) {
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	var doneAfterCancel bool
	orig := boxdHealthProbe
	boxdHealthProbe = func(ctx context.Context, ip string, timeout time.Duration) error {
		cancelCaller()                       // client disconnects mid-probe
		doneAfterCancel = ctx.Err() != nil   // detached gate ctx must NOT be done
		return nil                           // boxd healthy
	}
	defer func() { boxdHealthProbe = orig }()

	m := &Manager{log: zerolog.Nop(), netMgr: &network.Manager{}, vms: map[string]*VMInstance{}}
	// The return value is not asserted here (the ownership re-check needs a
	// real network slot this bare manager can't provide); this test pins only
	// that the probe's ctx is detached from the caller.
	_ = m.resumeReadyOrAbort(callerCtx, "vm-1", "10.0.0.1")
	if doneAfterCancel {
		t.Fatal("readiness gate must survive caller cancellation (detached) — a disconnect must not read as a dead guest")
	}
}

// A /health that answers after DestroyVM recycled the IP to another VM must
// not pass the gate: the resume must fail unless THIS VM still owns the slot.
func TestResumeReadyOrAbortAbortsWhenSlotRecycled(t *testing.T) {
	orig := boxdHealthProbe
	boxdHealthProbe = func(context.Context, string, time.Duration) error {
		return nil // a guest answered on this IP — but maybe the recycled one
	}
	defer func() { boxdHealthProbe = orig }()

	// Instance reads Running with the IP, but the net manager holds no slot for
	// it (GetVMNetInfo nil) — the state after a concurrent destroy freed the IP.
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, IP: "10.11.0.5"}
	m := &Manager{log: zerolog.Nop(), netMgr: &network.Manager{}, vms: map[string]*VMInstance{"vm-1": inst}}
	if err := m.resumeReadyOrAbort(context.Background(), "vm-1", "10.11.0.5"); err == nil {
		t.Fatal("a healthy /health against an IP the VM no longer owns must fail the resume")
	}
	inst.mu.RLock()
	st := inst.Status
	inst.mu.RUnlock()
	if st != StatusPaused {
		t.Fatalf("ownership loss must abort the resume (revert to Paused), got %s", st)
	}
}

// A genuinely unreachable guest (probe fails for the whole budget) must abort
// the resume: revert the tracked instance to Paused for a clean fresh restore.
func TestResumeReadyOrAbortAbortsOnGenuineFailure(t *testing.T) {
	orig := boxdHealthProbe
	boxdHealthProbe = func(context.Context, string, time.Duration) error {
		return fmt.Errorf("boxd not ready")
	}
	defer func() { boxdHealthProbe = orig }()

	inst := &VMInstance{ID: "vm-1", Status: StatusRunning}
	m := &Manager{log: zerolog.Nop(), netMgr: &network.Manager{}, vms: map[string]*VMInstance{"vm-1": inst}}
	if err := m.resumeReadyOrAbort(context.Background(), "vm-1", "10.0.0.1"); err == nil {
		t.Fatal("genuine unreachability must fail the gate")
	}
	inst.mu.RLock()
	st := inst.Status
	inst.mu.RUnlock()
	if st != StatusPaused {
		t.Fatalf("genuine failure must abort the resume (revert to Paused), got %s", st)
	}
}

// A VM inside DestroyVM's teardown window must not be lazily reattached: doing
// so would rebind the slot destroy is freeing and hand a live pointer to a
// recycling IP (the credential-delivery / cross-tenant hazard).
func TestGetInstanceRefusesResurrectionDuringDestroy(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, IP: "10.11.0.5", Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, netMgr: &network.Manager{}, vms: map[string]*VMInstance{}}

	m.destroying.Store("vm-1", struct{}{})
	if _, err := m.getInstance("vm-1"); err == nil {
		t.Fatal("a VM mid-destroy must not be lazily reattached")
	}
	if _, tracked := m.vms["vm-1"]; tracked {
		t.Fatal("a VM mid-destroy must not be republished to m.vms")
	}
}

// DestroyVM bypasses the lifecycle lock, so it can land during a resume —
// most likely inside the unverified readiness wait, which runs a full budget
// detached from the caller. The resume's persist must not resurrect the
// deleted record and report success.
func TestCommitResumeState_DestroyedMidFlight_NotResurrected(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// The destroy already completed: instance untracked, record gone — exactly
	// what DestroyVM leaves behind while this resume was mid-flight.
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}}

	err = m.commitResumeState(inst)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("a destroy landing mid-resume must surface NotFound, got %v", err)
	}
	present, herr := store.Has("vm-1")
	if herr != nil {
		t.Fatal(herr)
	}
	if present {
		t.Fatal("the resume persist must be erased, not left resurrecting a destroyed VM")
	}
}

// The normal path: a still-tracked VM persists and proceeds.
func TestCommitResumeState_TrackedVM_Persists(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	inst := &VMInstance{ID: "vm-1", Status: StatusRunning}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": inst}}

	if err := m.commitResumeState(inst); err != nil {
		t.Fatalf("a tracked VM must commit cleanly, got %v", err)
	}
	present, herr := store.Has("vm-1")
	if herr != nil {
		t.Fatal(herr)
	}
	if !present {
		t.Fatal("a tracked VM's state must be persisted")
	}
}

// Callers arrive with a deadline no larger than the gate's own budget and have
// already spent part of it, so an inherited ctx would always expire first and
// every attempt would end "no verdict" — leaving the record unchanged for the
// next attempt to repeat forever. The gate must reach its own verdict anyway.
func TestVerifyBoxdReadyReachesVerdictUnderShorterCallerDeadline(t *testing.T) {
	orig := adoptionBoxdReady
	var sawDeadline bool
	adoptionBoxdReady = func(ctx context.Context, _ *Manager, _ string) error {
		_, sawDeadline = ctx.Deadline()
		return errors.New("boxd silent for the whole budget") // a genuine verdict
	}
	defer func() { adoptionBoxdReady = orig }()

	// A caller deadline shorter than the gate's own budget — the common case,
	// since the control plane's per-attempt budget equals it and the RPC has
	// already spent part of it before reaching here.
	callerCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	m := &Manager{log: zerolog.Nop()}
	err := m.verifyBoxdReady(callerCtx, "192.0.2.5")
	if err == nil {
		t.Fatal("a silent guest must produce a verdict, not be swallowed")
	}
	if sawDeadline {
		t.Fatal("the gate must not inherit the caller's deadline — it would expire before any verdict")
	}
}

// When the readiness gate condemns an unverified record, the relaunch that
// follows can still fail on a precondition — and those paths return without
// touching status. The corpse verdict must therefore be recorded first, or the
// crash-window record keeps advertising Running for a VM that never came back.
func TestResumeVM_CorpseVerdict_ClearsRunningBeforeRelaunch(t *testing.T) {
	origDead := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive → adoption considered
	defer func() { vmUnitDead = origDead }()
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(context.Context, *Manager, string) error {
		return errors.New("boxd silent for the whole budget")
	}
	defer func() { adoptionBoxdReady = origReady }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Snapshot paths that do not exist: the relaunch fails a precondition
	// right after the fallthrough, which is exactly the case that used to
	// leave the stale Running claim behind.
	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: "/nonexistent/vmstate.snap", MemFilePath: "/nonexistent/mem.snap",
	}
	if err := store.Put(toRecord(existing)); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": existing}}

	if _, err := m.resumeVMLocked(context.Background(), "vm-1", "", ""); err == nil {
		t.Fatal("a relaunch with missing artifacts must fail")
	}
	existing.mu.RLock()
	st, unver := existing.Status, existing.Unverified
	existing.mu.RUnlock()
	if st == StatusRunning {
		t.Fatal("a condemned record must not still advertise Running after a failed relaunch")
	}
	if !unver {
		t.Fatal("readiness is still unproven — the marker must survive so the relaunch verifies")
	}
	rec, err := store.Get("vm-1")
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	if rec.Status == StatusRunning {
		t.Fatal("the durable record must not advertise Running either")
	}
}

// CreateVMSnapshot mutates DirtyTracked without the vm-op lock and deliberately
// does not persist, because that field is in-memory only — so the write would
// be a pure clobber, able to resurrect a concurrent lifecycle op's fields (the
// crash-window marker most damagingly). If DirtyTracked ever becomes durable,
// this fails: that path then needs the lock before it may persist.
func TestToRecordIgnoresDirtyTracked(t *testing.T) {
	base := &VMInstance{ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5", DirtyTracked: false}
	dirty := &VMInstance{ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5", DirtyTracked: true}

	a, err := json.Marshal(toRecord(base))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(toRecord(dirty))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("DirtyTracked is now persisted — CreateVMSnapshot must take the vm-op lock before persisting:\n %s\n %s", a, b)
	}
}

// The ad-hoc snapshot path must not write the record at all: it holds no
// vm-op lock, so any write races whatever lifecycle op is in flight.
func TestCreateVMSnapshotDoesNotPersist(t *testing.T) {
	src, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := string(src)
	start := strings.Index(fn, "func (m *Manager) CreateVMSnapshot(")
	if start < 0 {
		t.Fatal("CreateVMSnapshot not found")
	}
	end := strings.Index(fn[start:], "\nfunc ")
	if end < 0 {
		t.Fatal("could not bound CreateVMSnapshot")
	}
	if body := fn[start : start+end]; strings.Contains(body, "persistState(") {
		t.Fatal("CreateVMSnapshot must not persist: it holds no vm-op lock, so a full-record write can clobber a concurrent lifecycle op")
	}
}

// The corpse verdict must be durable before relaunching: the relaunch can fail
// on a precondition and return, so an unrecorded verdict would leave the record
// still claiming Running. A failed write must refuse the relaunch outright.
func TestResumeVM_CorpseVerdictUnrecordable_RefusesRelaunch(t *testing.T) {
	origDead := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive → adoption considered
	defer func() { vmUnitDead = origDead }()
	origReady := adoptionBoxdReady
	adoptionBoxdReady = func(context.Context, *Manager, string) error {
		return errors.New("boxd silent for the whole budget")
	}
	defer func() { adoptionBoxdReady = origReady }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, Unverified: true, IP: "192.0.2.5",
		SnapshotPath: "/nonexistent/vmstate.snap", MemFilePath: "/nonexistent/mem.snap",
	}
	if err := store.Put(toRecord(existing)); err != nil {
		t.Fatal(err)
	}
	store.Close() // every later write fails — the store is broken

	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": existing}}
	_, err = m.resumeVMLocked(context.Background(), "vm-1", "", "")
	if err == nil {
		t.Fatal("an unrecordable verdict must fail the resume")
	}
	// It must fail ON the verdict, not sail past it into the relaunch and fail
	// there on the missing artifacts.
	if !strings.Contains(err.Error(), "record readiness verdict") {
		t.Fatalf("must refuse at the verdict, got %v", err)
	}
}

// DestroyVM stops the unit and frees the slot before it removes the map entry,
// so tracked-ness alone would let a resume report success for a VM already
// being torn down.
func TestCommitResumeState_DestroyInProgress_NotReportedSuccessful(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	inst := &VMInstance{ID: "vm-1", Status: StatusRunning}
	// Still tracked — DestroyVM has not reached removeVM yet — but tombstoned.
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": inst}}
	m.destroying.Store("vm-1", struct{}{})

	if err := m.commitResumeState(inst); status.Code(err) != codes.NotFound {
		t.Fatalf("a resume racing an in-progress destroy must surface NotFound, got %v", err)
	}
	present, herr := store.Has("vm-1")
	if herr != nil {
		t.Fatal(herr)
	}
	if present {
		t.Fatal("the resume's write must be erased for a VM being destroyed")
	}
}
