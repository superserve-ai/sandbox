package vm

import (
	"context"
	"errors"
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

	snap, mem, err := mgr.PauseVM(context.Background(), "vm-1", "")
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

	_, _, err := mgr.PauseVM(context.Background(), "vm-1", "")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for dangling artifacts, got %v", err)
	}
}

func TestRestoreVMSnapshot_AlreadyRunningHealthy_ReturnsExisting(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
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
		ID: "vm-1", Status: StatusRunning, IP: "10.11.0.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		vms:        map[string]*VMInstance{"vm-1": existing},
		restoreSem: make(chan struct{}, 1),
	}

	inst, err := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner")
	if err != nil {
		t.Fatalf("retried restore of a healthy running VM should succeed, got %v", err)
	}
	if inst != existing {
		t.Fatal("expected the existing running instance, not a re-restore")
	}
	mgr.mu.RLock()
	still := mgr.vms["vm-1"]
	mgr.mu.RUnlock()
	if still != existing {
		t.Fatal("existing instance must remain tracked untouched")
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
		ID: "vm-1", Status: StatusRunning, IP: "10.11.0.5",
		SnapshotPath: filepath.Join(dir, "old-vmstate.snap"),
		MemFilePath:  filepath.Join(dir, "old-mem.snap"),
	}
	mgr := &Manager{
		log:        zerolog.Nop(),
		vms:        map[string]*VMInstance{"vm-1": existing},
		restoreSem: make(chan struct{}, 1),
	}

	inst, _ := mgr.RestoreVMSnapshot(context.Background(), "vm-1", snapPath, memPath, VMConfig{}, nil, "team", "owner")
	if inst == existing {
		t.Fatal("a restore for different artifacts must not return the old VM")
	}
}

func TestResumeVM_AlreadyRunningHealthy_ReturnsExisting(t *testing.T) {
	orig := vmUnitDead
	vmUnitDead = func(string) bool { return false } // unit alive
	defer func() { vmUnitDead = orig }()

	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, IP: "10.11.0.5",
		SnapshotPath: "/snapshots/vm-1/vmstate.snap",
		MemFilePath:  "/snapshots/vm-1/mem.snap",
	}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}}

	inst, err := mgr.ResumeVM(context.Background(), "vm-1", "", "")
	if err != nil {
		t.Fatalf("retried resume of a healthy running VM should succeed, got %v", err)
	}
	if inst != existing {
		t.Fatal("expected the existing running instance, not a relaunch")
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
		ID: "vm-1", Status: StatusRunning, IP: "10.11.0.5",
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}}

	if got := m.retriedLaunchTarget("vm-1", snapPath, memPath); got != nil {
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
