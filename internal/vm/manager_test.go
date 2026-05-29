package vm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
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

func TestWaitForSocket_AlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sock")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := waitForSocket(path, time.Second); err != nil {
		t.Errorf("waitForSocket on existing file: %v", err)
	}
}

func TestWaitForSocket_AppearsAfterStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sock")

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, nil, 0o644)
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
}

func TestWaitForSocketPolling_AppearsAfterStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sock")
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, nil, 0o644)
	}()
	if err := waitForSocketPolling(path, time.Second); err != nil {
		t.Errorf("waitForSocketPolling: %v", err)
	}
}
