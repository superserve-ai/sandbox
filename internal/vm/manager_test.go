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
	"slices"
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

type fakeNetMgr struct {
	setupInfo       map[string]*network.VMNetInfo
	setupCalls      []string
	cleanupVMCalls  []string
	teardownCalls   []string
	teardownNSCalls []struct {
		vmID string
		ns   string
	}
	claimCalls   []string
	cleanupCalls []struct {
		vmID string
		ns   string
	}
	reserved      map[string]string
	poolFresh     int
	poolRecycled  int
	poolEnabled   bool
	netnsTotal    int
	ownedSlots    int
	orphaned      int
	firewallCalls []struct {
		vmID         string
		allowedCIDRs []string
		deniedCIDRs  []string
	}
	beforeRelease func(op, vmID, ns string)
}

func (f *fakeNetMgr) CleanupVM(vmID string) {
	if f.beforeRelease != nil {
		f.beforeRelease("cleanup", vmID, "")
	}
	f.cleanupVMCalls = append(f.cleanupVMCalls, vmID)
}

func (f *fakeNetMgr) CleanupVMOrNamespace(vmID, fallbackNamespace string) {
	if f.beforeRelease != nil {
		f.beforeRelease("cleanup_ns", vmID, fallbackNamespace)
	}
	f.cleanupCalls = append(f.cleanupCalls, struct {
		vmID string
		ns   string
	}{vmID: vmID, ns: fallbackNamespace})
}

func (f *fakeNetMgr) ClaimFreshSlot(owner string) (int, error) {
	f.claimCalls = append(f.claimCalls, owner)
	return 0, nil
}

func (f *fakeNetMgr) EnsureVMSlot(context.Context, string, string, string, string) (*network.VMNetInfo, error) {
	return &network.VMNetInfo{}, nil
}

func (f *fakeNetMgr) Forget(string) {}

func (f *fakeNetMgr) GetVMNetInfo(string) *network.VMNetInfo { return nil }

func (f *fakeNetMgr) NetnsStats() (int, int, int) { return f.netnsTotal, f.ownedSlots, f.orphaned }

func (f *fakeNetMgr) PoolStats() (int, int, bool) { return f.poolFresh, f.poolRecycled, f.poolEnabled }

func (f *fakeNetMgr) NamespaceForPID(int) string { return "" }

func (f *fakeNetMgr) ReattachVM(string, string, string, string) error { return nil }

func (f *fakeNetMgr) ReclaimUnusedSlots() int { return 0 }

func (f *fakeNetMgr) DrainWarmPool(int) int { return 0 }

func (f *fakeNetMgr) ReleaseSlot(string, int) {}

func (f *fakeNetMgr) ReserveSlotsAbove(reservations map[string]string) {
	f.reserved = make(map[string]string, len(reservations))
	for vmID, ns := range reservations {
		f.reserved[vmID] = ns
	}
}

func (f *fakeNetMgr) SetupVM(_ context.Context, vmID string, _ *network.Config) (*network.VMNetInfo, error) {
	f.setupCalls = append(f.setupCalls, vmID)
	if info, ok := f.setupInfo[vmID]; ok {
		cp := *info
		return &cp, nil
	}
	return &network.VMNetInfo{
		Namespace:  "ns-99",
		TAPDevice:  network.TAPName,
		VMIP:       network.VMInternalIP,
		GatewayIP:  network.VMGatewayIP,
		HostIP:     "10.11.0.99",
		MACAddress: "02:FC:00:00:00:63",
	}, nil
}

func (f *fakeNetMgr) SweepOrphanNamespaces(map[string]bool) int { return 0 }

func (f *fakeNetMgr) UpdateFirewallRules(vmID string, allowedCIDRs, deniedCIDRs []string) error {
	f.firewallCalls = append(f.firewallCalls, struct {
		vmID         string
		allowedCIDRs []string
		deniedCIDRs  []string
	}{vmID: vmID, allowedCIDRs: append([]string(nil), allowedCIDRs...), deniedCIDRs: append([]string(nil), deniedCIDRs...)})
	return nil
}

func (f *fakeNetMgr) TeardownVM(vmID string) {
	if f.beforeRelease != nil {
		f.beforeRelease("teardown", vmID, "")
	}
	f.teardownCalls = append(f.teardownCalls, vmID)
}

func (f *fakeNetMgr) TeardownVMOrNamespace(vmID, fallbackNamespace string) {
	if f.beforeRelease != nil {
		f.beforeRelease("teardown_ns", vmID, fallbackNamespace)
	}
	f.teardownNSCalls = append(f.teardownNSCalls, struct {
		vmID string
		ns   string
	}{vmID: vmID, ns: fallbackNamespace})
}

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

func TestReclaimPausedNetworkInventory_RecyclesOldestPausedInstance(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	defer store.Close()

	now := time.Now()
	rec := VMRecord{
		ID:         "vm-tracked",
		Status:     StatusPaused,
		Namespace:  "ns-17",
		IP:         "10.11.0.17",
		TAPDevice:  network.TAPName,
		MACAddress: "02:FC:00:00:00:11",
		PausedAt:   now.Add(-time.Hour),
	}
	if err := store.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	inst := toInstance(rec)
	fake := &fakeNetMgr{
		poolEnabled:  true,
		poolFresh:    4,
		poolRecycled: 2,
		netnsTotal:   1,
		ownedSlots:   network.MaxSlots - 1,
	}
	// A tracked instance still releases by namespace name: the by-vmID call
	// no-ops for a VM missing from the net manager's device table, which would
	// strand the kernel state after the record has already been cleared.
	fake.beforeRelease = func(op, vmID, ns string) {
		if op != "cleanup_ns" || vmID != rec.ID || ns != rec.Namespace {
			t.Fatalf("unexpected release hook call: op=%q vmID=%q ns=%q", op, vmID, ns)
		}
		got, err := store.Get(rec.ID)
		if err != nil {
			t.Fatalf("get during release hook: %v", err)
		}
		if got.Namespace != "" || got.IP != "" || got.TAPDevice != "" || got.MACAddress != "" {
			t.Fatalf("record not cleared before cleanup: %+v", got)
		}
	}
	mgr := &Manager{
		cfg: ManagerConfig{
			PausedNetworkReclaimEnabled:         true,
			PausedNetworkSlotHeadroomReserve:    10,
			PausedNetworkSlotHeadroomHysteresis: 1,
			PausedNetworkNetnsThreshold:         1_000_000,
			PausedNetworkNetnsHysteresis:        1,
			PausedNetworkMountThreshold:         1_000_000,
			PausedNetworkMountHysteresis:        1,
			PausedNetworkMaxReclaims:            1,
		},
		state:  store,
		netMgr: fake,
		vms:    map[string]*VMInstance{rec.ID: inst},
		log:    zerolog.Nop(),
	}

	reclaimed := mgr.reclaimPausedNetworkInventory(now)
	if reclaimed != 1 {
		t.Fatalf("reclaimed = %d, want 1", reclaimed)
	}
	if got := fake.cleanupCalls; len(got) != 1 || got[0].vmID != rec.ID || got[0].ns != rec.Namespace {
		t.Fatalf("cleanup calls = %+v, want one recycle for %q/%q", got, rec.ID, rec.Namespace)
	}
	if len(fake.teardownCalls) != 0 || len(fake.teardownNSCalls) != 0 {
		t.Fatalf("teardown calls = %v/%v, want none", fake.teardownCalls, fake.teardownNSCalls)
	}
	if inst.Namespace != "" || inst.IP != "" || inst.TAPDevice != "" || inst.MACAddress != "" {
		t.Fatalf("tracked instance still held network identity: %+v", inst)
	}
	got, err := store.Get(rec.ID)
	if err != nil {
		t.Fatalf("get cleared record: %v", err)
	}
	if got.Namespace != "" || got.IP != "" || got.TAPDevice != "" || got.MACAddress != "" {
		t.Fatalf("stored record still held network identity: %+v", got)
	}
	if !got.PausedAt.Equal(rec.PausedAt) {
		t.Fatalf("stored paused_at = %v, want %v", got.PausedAt, rec.PausedAt)
	}
}

func TestReclaimPausedNetworkInventory_ShrinksKernelPressure(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	defer store.Close()

	rec := VMRecord{
		ID:         "vm-shrink",
		Status:     StatusPaused,
		Namespace:  "ns-18",
		IP:         "10.11.0.18",
		TAPDevice:  network.TAPName,
		MACAddress: "02:FC:00:00:00:12",
		PausedAt:   time.Now().Add(-time.Minute),
	}
	if err := store.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	fake := &fakeNetMgr{
		poolEnabled: true,
		netnsTotal:  2,
		ownedSlots:  network.MaxSlots - 1,
	}
	fake.beforeRelease = func(op, vmID, ns string) {
		if op != "teardown_ns" || vmID != rec.ID || ns != rec.Namespace {
			t.Fatalf("unexpected release hook call: op=%q vmID=%q ns=%q", op, vmID, ns)
		}
		got, err := store.Get(rec.ID)
		if err != nil {
			t.Fatalf("get during release hook: %v", err)
		}
		if got.Namespace != "" || got.IP != "" || got.TAPDevice != "" || got.MACAddress != "" {
			t.Fatalf("record not cleared before teardown: %+v", got)
		}
	}
	mgr := &Manager{
		cfg: ManagerConfig{
			PausedNetworkReclaimEnabled:         true,
			PausedNetworkSlotHeadroomReserve:    10,
			PausedNetworkSlotHeadroomHysteresis: 1,
			PausedNetworkNetnsThreshold:         1,
			PausedNetworkNetnsHysteresis:        0,
			PausedNetworkMountThreshold:         1_000_000,
			PausedNetworkMountHysteresis:        1,
		},
		state:  store,
		netMgr: fake,
		log:    zerolog.Nop(),
	}

	reclaimed := mgr.reclaimPausedNetworkInventory(time.Now())
	if reclaimed != 1 {
		t.Fatalf("reclaimed = %d, want 1", reclaimed)
	}
	if len(fake.cleanupVMCalls) != 0 {
		t.Fatalf("cleanup calls = %v, want none in shrink mode", fake.cleanupVMCalls)
	}
	if len(fake.teardownNSCalls) != 1 || fake.teardownNSCalls[0].vmID != rec.ID || fake.teardownNSCalls[0].ns != rec.Namespace {
		t.Fatalf("teardown-ns calls = %+v, want one full teardown for %q/%q", fake.teardownNSCalls, rec.ID, rec.Namespace)
	}
}

func TestReclaimPausedNetworkInventory_HonorsMinWarmAgeAndCooldown(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	defer store.Close()

	oldRec := VMRecord{ID: "vm-old", Status: StatusPaused, Namespace: "ns-19", PausedAt: time.Now().Add(-time.Hour)}
	newRec := VMRecord{ID: "vm-new", Status: StatusPaused, Namespace: "ns-20", PausedAt: time.Now().Add(-time.Minute)}
	for _, rec := range []VMRecord{oldRec, newRec} {
		if err := store.Put(rec); err != nil {
			t.Fatalf("put %s: %v", rec.ID, err)
		}
	}

	fake := &fakeNetMgr{
		poolEnabled: true,
		netnsTotal:  1,
		ownedSlots:  network.MaxSlots - 1,
	}
	mgr := &Manager{
		cfg: ManagerConfig{
			PausedNetworkReclaimEnabled:         true,
			PausedNetworkSlotHeadroomReserve:    10,
			PausedNetworkSlotHeadroomHysteresis: 1,
			PausedNetworkNetnsThreshold:         1_000_000,
			PausedNetworkNetnsHysteresis:        1,
			PausedNetworkMountThreshold:         1_000_000,
			PausedNetworkMountHysteresis:        1,
			PausedNetworkMinWarmAge:             10 * time.Minute,
			PausedNetworkMaxReclaims:            1,
			PausedNetworkReclaimCooldown:        time.Hour,
		},
		state:  store,
		netMgr: fake,
		log:    zerolog.Nop(),
	}
	now := time.Now()
	if reclaimed := mgr.reclaimPausedNetworkInventory(now); reclaimed != 1 {
		t.Fatalf("first reclaim = %d, want 1", reclaimed)
	}
	if len(fake.cleanupCalls) != 1 || fake.cleanupCalls[0].vmID != oldRec.ID {
		t.Fatalf("cleanup calls = %+v, want oldest record first", fake.cleanupCalls)
	}
	if reclaimed := mgr.reclaimPausedNetworkInventory(now); reclaimed != 0 {
		t.Fatalf("second reclaim = %d, want 0 while cooldown active", reclaimed)
	}
}

func TestPausedNetworkPressureSnapshot_CountsWarmPoolAsAvailableHeadroom(t *testing.T) {
	mgr := &Manager{
		netMgr: &fakeNetMgr{
			ownedSlots:   network.MaxSlots - 12,
			poolFresh:    3,
			poolRecycled: 4,
			poolEnabled:  true,
		},
	}

	snapshot := mgr.pausedNetworkPressureSnapshot()
	if snapshot.freeSlots != 12+3+4 {
		t.Fatalf("freeSlots = %d, want %d", snapshot.freeSlots, 19)
	}
}

func TestReleasePausedNetworkSlot_SkipsResurrectionWhenRecordDeleted(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	defer store.Close()

	rec := VMRecord{
		ID:         "vm-deleted",
		Status:     StatusPaused,
		Namespace:  "ns-19",
		IP:         "10.11.0.19",
		TAPDevice:  network.TAPName,
		MACAddress: "02:FC:00:00:00:13",
		PausedAt:   time.Now().Add(-time.Minute),
	}
	if err := store.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Delete(rec.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	fake := &fakeNetMgr{}
	mgr := &Manager{
		state:  store,
		netMgr: fake,
		log:    zerolog.Nop(),
	}
	released, err := mgr.releasePausedNetworkSlot(rec, false)
	if err != nil {
		t.Fatalf("releasePausedNetworkSlot: %v", err)
	}
	if released {
		t.Fatal("releasePausedNetworkSlot reported success for a deleted record")
	}
	if len(fake.cleanupVMCalls) != 0 || len(fake.teardownCalls) != 0 {
		t.Fatalf("network teardown should not run after record deletion: cleanup=%v teardown=%v", fake.cleanupVMCalls, fake.teardownCalls)
	}
	if got, gerr := store.Get(rec.ID); gerr != nil {
		t.Fatalf("get after release: %v", gerr)
	} else if got != nil {
		t.Fatalf("record resurrected after delete: %+v", got)
	}
}

func TestReclaimPausedNetworkInventory_ActiveControllerContinuesThroughBand(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	defer store.Close()

	rec := VMRecord{ID: "vm-band", Status: StatusPaused, Namespace: "ns-band", PausedAt: time.Now().Add(-time.Hour)}
	if err := store.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	fake := &fakeNetMgr{
		poolEnabled: true,
		netnsTotal:  1,
		ownedSlots:  network.MaxSlots - 101,
	}
	mgr := &Manager{
		cfg: ManagerConfig{
			PausedNetworkReclaimEnabled:         true,
			PausedNetworkSlotHeadroomReserve:    100,
			PausedNetworkSlotHeadroomHysteresis: 10,
			PausedNetworkNetnsThreshold:         1_000_000,
			PausedNetworkNetnsHysteresis:        1,
			PausedNetworkMountThreshold:         1_000_000,
			PausedNetworkMountHysteresis:        1,
			PausedNetworkMaxReclaims:            1,
		},
		state:                          store,
		netMgr:                         fake,
		log:                            zerolog.Nop(),
		pausedNetworkControllerActive:  true,
		pausedNetworkControllerLastRun: time.Now().Add(-time.Hour),
	}

	if reclaimed := mgr.reclaimPausedNetworkInventory(time.Now()); reclaimed != 1 {
		t.Fatalf("reclaimed = %d, want 1 while active controller is still recovering", reclaimed)
	}
	got, err := store.Get(rec.ID)
	if err != nil {
		t.Fatalf("get cleared record: %v", err)
	}
	if got.Namespace != "" {
		t.Fatalf("record not cleared during active-band reclaim: %+v", got)
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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()
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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()
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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()
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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()
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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()

	existing := &VMInstance{
		ID: "vm-1", Status: StatusRunning, IP: "192.0.2.5",
		SnapshotPath: "/snapshots/vm-1/vmstate.snap",
		MemFilePath:  "/snapshots/vm-1/mem.snap",
	}
	mgr := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": existing}}

	inst, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()
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
	inst, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
	if err == nil && inst == existing {
		t.Fatal("an unverified record that fails verification must not be adopted")
	}
}

func TestResumeVM_RebuildsNetworkSlotWhenNamespaceMissingAndCleansUpOnLaunchFailure(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	if err := os.WriteFile(snapPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	if err := os.WriteFile(memPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write mem: %v", err)
	}

	fake := &fakeNetMgr{
		setupInfo: map[string]*network.VMNetInfo{
			"vm-1": {
				Namespace:  "ns-99",
				TAPDevice:  network.TAPName,
				VMIP:       network.VMInternalIP,
				GatewayIP:  network.VMGatewayIP,
				HostIP:     "10.11.0.99",
				MACAddress: "02:FC:00:00:00:63",
			},
		},
	}
	inst := &VMInstance{
		ID:           "vm-1",
		Status:       StatusPaused,
		SnapshotPath: snapPath,
		MemFilePath:  memPath,
		DiskPath:     filepath.Join(dir, "rootfs.ext4"),
	}
	mgr := &Manager{
		log:    zerolog.Nop(),
		cfg:    ManagerConfig{RunDir: dir},
		netMgr: fake,
		vms:    map[string]*VMInstance{"vm-1": inst},
	}
	resumeRules := &sandboxNetworkRules{
		allowedCIDRs:   []string{"10.0.0.0/8"},
		deniedCIDRs:    []string{"198.51.100.0/24"},
		allowedDomains: []string{"example.com"},
	}
	mgr.launchFirecrackerHook = func(_ context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string, existing Supervision, hadPriorLife, freshUnit bool) (int, Supervision, error) {
		if vmID != "vm-1" {
			t.Fatalf("vmID = %q, want vm-1", vmID)
		}
		if netNS != "ns-99" {
			t.Fatalf("netNS = %q, want ns-99", netNS)
		}
		if len(fake.firewallCalls) != 1 {
			t.Fatalf("firewall calls = %+v, want one pre-launch apply", fake.firewallCalls)
		}
		got := fake.firewallCalls[0]
		if got.vmID != "vm-1" || !slices.Equal(got.allowedCIDRs, resumeRules.allowedCIDRs) || !slices.Equal(got.deniedCIDRs, resumeRules.deniedCIDRs) {
			t.Fatalf("firewall call = %+v, want vm-1 with resume rules", got)
		}
		if existing != SupervisionUnit || !hadPriorLife || freshUnit {
			t.Fatalf("unexpected launch args: existing=%q hadPriorLife=%v freshUnit=%v", existing, hadPriorLife, freshUnit)
		}
		if socketPath == "" || perVMRootfs == "" || basePath != "" {
			t.Fatalf("unexpected launch paths: socket=%q rootfs=%q base=%q", socketPath, perVMRootfs, basePath)
		}
		return 0, SupervisionUnit, errors.New("launch failed")
	}

	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatalf("lock op: %v", err)
	}
	defer unlock()

	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", resumeRules); err == nil {
		t.Fatal("expected launch failure")
	}
	if got := fake.setupCalls; len(got) != 1 || got[0] != "vm-1" {
		t.Fatalf("setup calls = %v, want [vm-1]", got)
	}
	if got := fake.teardownCalls; len(got) != 1 || got[0] != "vm-1" {
		t.Fatalf("teardown calls = %v, want [vm-1]", got)
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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return true } // unit definitively dead
	defer func() { vmDeadForRetry = orig }()

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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()

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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()
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
	orig := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = orig }()
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
	origDead := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive
	defer func() { vmDeadForRetry = origDead }()
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

	inst, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
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

// When a paused record has had its network identity cleared, the unverified
// resume path must verify the replacement slot's IP, not the empty pre-release
// address. Otherwise a healthy relaunch gets stopped as "unready" and marked
// failed.
func TestResumeVM_UnverifiedRelaunchVerifiesReplacementIP(t *testing.T) {
	var verifiedIP string
	origReady := adoptionBoxdReady
	defer func() { adoptionBoxdReady = origReady }()

	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	rootfsPath := filepath.Join(dir, "rootfs.ext4")
	for _, p := range []string{snapPath, memPath, rootfsPath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fake := &fakeNetMgr{
		setupInfo: map[string]*network.VMNetInfo{
			"vm-1": {
				Namespace:  "ns-99",
				TAPDevice:  network.TAPName,
				VMIP:       network.VMInternalIP,
				GatewayIP:  network.VMGatewayIP,
				HostIP:     "10.11.0.99",
				MACAddress: "02:FC:00:00:00:63",
			},
		},
	}
	inst := &VMInstance{
		ID:           "vm-1",
		Status:       StatusPaused,
		Unverified:   true,
		SnapshotPath: snapPath,
		MemFilePath:  memPath,
		DiskPath:     rootfsPath,
	}
	mgr := &Manager{
		log:    zerolog.Nop(),
		cfg:    ManagerConfig{RunDir: dir},
		netMgr: fake,
		vms:    map[string]*VMInstance{"vm-1": inst},
	}
	mgr.launchFirecrackerHook = func(_ context.Context, vmID, socketPath, perVMRootfs, basePath, netNS string, existing Supervision, hadPriorLife, freshUnit bool) (int, Supervision, error) {
		if vmID != "vm-1" {
			t.Fatalf("vmID = %q, want vm-1", vmID)
		}
		if netNS != "ns-99" {
			t.Fatalf("netNS = %q, want ns-99", netNS)
		}
		if perVMRootfs != rootfsPath || basePath != "" || socketPath == "" {
			t.Fatalf("unexpected launch paths: socket=%q rootfs=%q base=%q", socketPath, perVMRootfs, basePath)
		}
		if existing != SupervisionUnit || !hadPriorLife || freshUnit {
			t.Fatalf("unexpected launch args: existing=%q hadPriorLife=%v freshUnit=%v", existing, hadPriorLife, freshUnit)
		}
		return 4321, SupervisionUnit, nil
	}
	mgr.restoreForResumeHook = func(_ string, _ string, _ string, _ string, _ *network.VMNetInfo) (bool, error) {
		return true, nil
	}
	adoptionBoxdReady = func(_ context.Context, _ *Manager, ip string) error {
		verifiedIP = ip
		return nil
	}

	unlock, err := mgr.lockVMOp(context.Background(), "vm-1")
	if err != nil {
		t.Fatalf("lock op: %v", err)
	}
	defer unlock()

	if _, err := mgr.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err != nil {
		t.Fatalf("resumeVMLocked: %v", err)
	}
	if verifiedIP != "10.11.0.99" {
		t.Fatalf("verified IP = %q, want replacement host IP", verifiedIP)
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
		cancelCaller()                     // client disconnects mid-probe
		doneAfterCancel = ctx.Err() != nil // detached gate ctx must NOT be done
		return nil                         // boxd healthy
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
	origDead := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive → adoption considered
	defer func() { vmDeadForRetry = origDead }()
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

	if _, err := m.resumeVMLocked(context.Background(), "vm-1", "", "", nil); err == nil {
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
	origDead := vmDeadForRetry
	vmDeadForRetry = func(*Manager, string) bool { return false } // unit alive → adoption considered
	defer func() { vmDeadForRetry = origDead }()
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
	_, err = m.resumeVMLocked(context.Background(), "vm-1", "", "", nil)
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

// A parked Error VM cannot be snapshotted; pause must fail fast with a clear
// precondition error instead of dialing the dead socket and returning a
// generic failure the control plane retries against.
func TestPauseVM_ErrorInstance_FailsFast(t *testing.T) {
	inst := &VMInstance{ID: "vm-1", Status: StatusError}
	m := &Manager{log: zerolog.Nop(), vms: map[string]*VMInstance{"vm-1": inst}}
	_, _, _, err := m.PauseVM(context.Background(), "vm-1", "")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for an error-state VM, got %v", err)
	}
}

// A parked Error record can ride out a vmd restart while its wedged unit is
// still deactivating. unitDefinitelyDead reads that state as dead; the eager
// startup cleanup must instead require the terminal state and park the
// refusal again — releasing the record would free the namespace under a
// possibly-live FC.
func TestReattachRecord_DeactivatingUnit_ParksNotReleases(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false } // deactivating: not terminal
	defer func() { vmUnitFullyDown = origDown }()
	origStop := staleUnitStopConfirmed
	staleUnitStopConfirmed = func(context.Context, string) bool { return false }
	defer func() { staleUnitStopConfirmed = origStop }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rec := VMRecord{
		ID: "vm-1", Status: StatusError,
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
	}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}}

	inst, ok := m.reattachRecord(context.Background(), rec, true)
	if inst == nil || !ok || inst.Status != StatusError {
		t.Fatalf("a non-terminal unit must re-park the Error refusal, got inst=%+v ok=%v", inst, ok)
	}
	kept, err := store.Get("vm-1")
	if err != nil || kept == nil {
		t.Fatalf("the record must be kept while the unit is not terminal, got rec=%v err=%v", kept, err)
	}
	if kept.Status != StatusError {
		t.Fatalf("kept record must stay Error, got %s", kept.Status)
	}
}

// A confirmed stop whose record delete fails must also park the refusal:
// the surviving Running row would otherwise be re-adopted onto a slot this
// path was about to free.
func TestReattachRecord_DeleteFailsAfterConfirmedStop_ParksError(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false } // unit alive (not terminal)
	defer func() { vmUnitFullyDown = origDown }()
	origStop := staleUnitStopConfirmed
	staleUnitStopConfirmed = func(context.Context, string) bool { return true }
	defer func() { staleUnitStopConfirmed = origStop }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	rec := VMRecord{
		ID: "vm-1", Status: StatusRunning,
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
	}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil { // the delete will fail
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}}

	inst, ok := m.reattachRecord(context.Background(), rec, true)
	if inst == nil || !ok || inst.Status != StatusError {
		t.Fatalf("a failed delete must park the refusal, got inst=%+v ok=%v", inst, ok)
	}
	if tracked := m.vms["vm-1"]; tracked != inst {
		t.Fatal("the Error instance must be tracked in memory")
	}
}

// A destroy or markStale deleting the record while the stale stop waits owns
// the teardown: the reattach must abandon, not resurrect the row.
func TestReattachRecord_DeletedDuringStaleStop_Abandoned(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false } // unit alive (not terminal)
	defer func() { vmUnitFullyDown = origDown }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	origStop := staleUnitStopConfirmed
	staleUnitStopConfirmed = func(context.Context, string) bool {
		if err := store.Delete("vm-1"); err != nil { // markStale races the wait
			t.Error(err)
		}
		return false
	}
	defer func() { staleUnitStopConfirmed = origStop }()

	rec := VMRecord{
		ID: "vm-1", Status: StatusRunning,
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
	}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}}

	inst, ok := m.reattachRecord(context.Background(), rec, true)
	if inst != nil || ok {
		t.Fatal("a record deleted mid-wait must be abandoned, not published")
	}
	present, err := store.Has("vm-1")
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("the deleted record must not be resurrected")
	}
	if _, tracked := m.vms["vm-1"]; tracked {
		t.Fatal("an abandoned reattach must not track the VM")
	}
}

// When the error write fails (broken store) and there is no verifiable pid to
// escalate against, the VM must still be refused in memory — the only refusal
// a broken store leaves.
func TestReattachRecord_ErrorPersistFails_StillRefusedInMemory(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false } // unit alive (not terminal)
	defer func() { vmUnitFullyDown = origDown }()
	origStop := staleUnitStopConfirmed
	staleUnitStopConfirmed = func(context.Context, string) bool { return false }
	defer func() { staleUnitStopConfirmed = origStop }()
	origKill := killUnitSIGKILL
	killUnitSIGKILL = func(context.Context, string) bool { return false } // escalation inconclusive too
	defer func() { killUnitSIGKILL = origKill }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	rec := VMRecord{
		ID: "vm-1", Status: StatusRunning,
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
	}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil { // every later write fails
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}}

	inst, ok := m.reattachRecord(context.Background(), rec, true)
	if inst == nil || !ok || inst.Status != StatusError {
		t.Fatalf("a broken store must still yield an in-memory Error refusal, got inst=%+v ok=%v", inst, ok)
	}
	if tracked := m.vms["vm-1"]; tracked != inst {
		t.Fatal("the Error instance must be tracked in memory")
	}
}

// A socket-missing record whose unit stop cannot be confirmed must keep its
// BoltDB record: deleting it would leave a live Firecracker no record points
// to, invisible to the next reattach.
// A record with an unknown supervision mode must be PARKED at reattach, not
// released: the stale-cleanup's unit probe answers vacuously "down" for a
// nonexistent unit, and acting on that evidence would delete the record and
// free the network under whatever the unknown mode left running.
func TestReattachRecord_UnknownSupervision_ParksUnmanageable(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return true } // the vacuous answer
	defer func() { vmUnitFullyDown = origDown }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rec := VMRecord{ID: "vm-1", Status: StatusRunning, Supervision: Supervision("checkpointed"), Namespace: "ns-1"}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, netMgr: &network.Manager{}, vms: map[string]*VMInstance{}}

	inst, ok := m.reattachRecord(context.Background(), rec, true)
	if inst == nil || !ok || inst.Status != StatusError {
		t.Fatalf("an unknown mode must park as Error, got inst=%+v ok=%v", inst, ok)
	}
	kept, err := store.Get("vm-1")
	if err != nil || kept == nil {
		t.Fatalf("the record must be kept, got rec=%v err=%v", kept, err)
	}
	if kept.Supervision != Supervision("checkpointed") {
		t.Fatalf("the unknown value must be preserved for the binary that understands it, got %q", kept.Supervision)
	}
	if kept.Status != StatusError {
		t.Fatalf("the refusal must be durable, got %s", kept.Status)
	}
}

// A failed restore whose direct-spawned FC survived (populated group, or a
// kill whose completion cannot be proven) still holds its tap and disk: the
// failure path must NOT free the network slot or rundir — ownership stays
// with the record until the reconciler confirms death. Only a confirmed-dead
// or unit-mode VM releases.
func TestReleaseFailedRestore_LiveCgroupRetainsOwnership(t *testing.T) {
	newMgr := func(events string) *Manager {
		vms := t.TempDir()
		if err := os.MkdirAll(filepath.Join(vms, "vm-1"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vms, "vm-1", "cgroup.events"), []byte(events), 0o644); err != nil {
			t.Fatal(err)
		}
		return &Manager{log: zerolog.Nop(), netMgr: &network.Manager{}, cgroups: &cgroupTree{vms: vms}}
	}
	release := func(m *Manager) bool {
		cleaned := false
		m.releaseFailedRestore("vm-1", false, false, func() { cleaned = true })
		return cleaned
	}

	if release(newMgr("populated 1\n")) {
		t.Fatal("a live cgroup FC still holds its disk — the rundir must not be freed")
	}
	if release(newMgr("frozen 0\n")) { // malformed events: death unprovable
		t.Fatal("an unprovable kill must retain ownership, not free the rundir")
	}
	if !release(newMgr("populated 0\n")) {
		t.Fatal("a confirmed-dead VM must release its rundir")
	}
	unitMode := &Manager{log: zerolog.Nop(), netMgr: &network.Manager{}}
	if !release(unitMode) {
		t.Fatal("a plain unit VM must not be blocked by the cgroup guard")
	}
}

func TestReattachRecord_SocketMissingStopUnconfirmed_KeepsRecord(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false } // unit alive (not terminal)
	defer func() { vmUnitFullyDown = origDown }()
	origStop := staleUnitStopConfirmed
	stoppedUnit := ""
	staleUnitStopConfirmed = func(_ context.Context, unit string) bool {
		stoppedUnit = unit
		return false // stop failed and the unit is not provably down
	}
	defer func() { staleUnitStopConfirmed = origStop }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	rec := VMRecord{
		ID: "vm-1", Status: StatusRunning,
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
	}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{}}

	inst, ok := m.reattachRecord(context.Background(), rec, true)
	if inst == nil || !ok {
		t.Fatal("an unconfirmed stop must publish the VM so a lazy reattach cannot re-adopt the Running row")
	}
	if inst.Status != StatusError {
		t.Fatalf("published instance must read Error, got %s", inst.Status)
	}
	if stoppedUnit != systemdUnitName("vm-1") {
		t.Fatalf("stop attempted on %q, want the record's unit", stoppedUnit)
	}
	if tracked := m.vms["vm-1"]; tracked != inst {
		t.Fatal("the Error instance must be tracked in memory")
	}
	kept, err := store.Get("vm-1")
	if err != nil || kept == nil {
		t.Fatalf("an unconfirmed stop must keep the record so the unit stays findable, got rec=%v err=%v", kept, err)
	}
	if kept.Status != StatusError {
		t.Fatalf("kept record must read Error so no retry adopts a socket-less VM, got %s", kept.Status)
	}
}

// The paused status is set in memory before it is persisted, so a failed write
// leaves the durable record reading Running behind a stopped unit — which the
// next reattach deletes as stale. The retry must re-record it rather than
// report a pause whose only trace is in memory.
func TestPauseVM_RetryRepersistsPausedState(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "vmstate.snap")
	memPath := filepath.Join(dir, "mem.snap")
	for _, p := range []string{snapPath, memPath} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dbPath := filepath.Join(dir, "vmd.db")
	store, err := OpenStateStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// The durable record still reads Running: the original pause's write failed.
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning}); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{
		ID: "vm-1", Status: StatusPaused,
		SnapshotPath: snapPath, MemFilePath: memPath,
	}
	m := &Manager{
		log:      zerolog.Nop(),
		state:    store,
		vms:      map[string]*VMInstance{"vm-1": inst},
		unitDead: func(context.Context, string) bool { return false }, // skip the retry backup
	}

	// Retry 1: the store is still refusing writes, so the pause must not be
	// reported complete.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.PauseVM(context.Background(), "vm-1", dir); err == nil {
		t.Fatal("a retry that cannot record the paused state must not report success")
	}

	// Retry 2: the store recovers and the retry makes the paused state durable.
	reopened, err := OpenStateStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	m.state = reopened
	gotSnap, gotMem, _, err := m.PauseVM(context.Background(), "vm-1", dir)
	if err != nil {
		t.Fatalf("retry must succeed once the store recovers: %v", err)
	}
	if gotSnap != snapPath || gotMem != memPath {
		t.Fatalf("retry must return the recorded artifacts, got %q %q", gotSnap, gotMem)
	}
	rec, err := reopened.Get("vm-1")
	if err != nil || rec == nil {
		t.Fatalf("record must survive, got rec=%v err=%v", rec, err)
	}
	if rec.Status != StatusPaused {
		t.Fatalf("the retry must make Paused durable, record still reads %v", rec.Status)
	}
}

// A resume whose Running write cannot be made durable must fail: the durable
// record still reads its pre-resume state (Error for a parked VM), and after a
// vmd restart the error rules would trust it and stop the healthy unit.
func TestCommitResumeState_UndurableRunning_FailsResume(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: "vm-1", Status: StatusRunning, DirtyTracked: true}
	m := &Manager{log: zerolog.Nop(), state: store, vms: map[string]*VMInstance{"vm-1": inst}}
	if err := store.Close(); err != nil { // the Running write cannot land
		t.Fatal(err)
	}

	if cerr := m.commitResumeState(inst); cerr == nil {
		t.Fatal("an undurable Running state must fail the resume, not report success")
	}
	inst.mu.RLock()
	st, dirty := inst.Status, inst.DirtyTracked
	inst.mu.RUnlock()
	if st != StatusError {
		t.Fatalf("instance must be parked Error so a retry cannot adopt the stopped unit, got %v", st)
	}
	if dirty {
		t.Fatal("DirtyTracked must clear with the unit stopped")
	}
}

// A failed record lookup for a cgroup survivor skips the kill but leaves the
// VM in no protected set, so it must also disable the startup orphan sweep —
// otherwise the sweep could reclaim a live FC's namespace.
func TestReapRecordlessCgroupVMsUnreadableRecordDisablesSweep(t *testing.T) {
	vms := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vms, "vm-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	store.Close() // every read now errors — the unreadable-record case
	m := &Manager{log: zerolog.Nop(), cgroups: &cgroupTree{vms: vms}, state: store}
	if _, sweepSafe := m.ReapRecordlessCgroupVMs(t.Context()); sweepSafe {
		t.Fatal("unreadable record for a cgroup survivor must disable the sweep")
	}
}

// The reattach half of the demotion handshake: the rollback demotion can
// rewrite the durable supervision while a lock-free reattach holds a stale
// record; the paused publish must adopt the fresh durable mode, or the next
// resume acts on the stale one and re-promotes a demoted record.
func TestReattachRecord_PausedAdoptsDemotedSupervision(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// The store already holds the DEMOTED record (unit)...
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusPaused, Supervision: SupervisionUnit}); err != nil {
		t.Fatal(err)
	}
	// ...while this reattach still carries the pre-demotion snapshot (cgroup).
	stale := VMRecord{ID: "vm-1", Status: StatusPaused, Supervision: SupervisionCgroup}
	m := &Manager{log: zerolog.Nop(), state: store, netMgr: &network.Manager{}, vms: map[string]*VMInstance{}}

	inst, ok := m.reattachRecord(context.Background(), stale, true)
	if inst == nil || !ok {
		t.Fatalf("paused reattach must publish, got inst=%v ok=%v", inst, ok)
	}
	inst.mu.RLock()
	got := inst.Supervision
	inst.mu.RUnlock()
	if got != SupervisionUnit {
		t.Fatalf("published instance must adopt the demoted durable mode, got %q", got)
	}
}

// When a failed restore retains a possibly-live VM's resources, the parked
// state must be explicit and durable: the record itself says what is held
// and that the reconciler owns the teardown — and a successful relaunch
// retires the claim.
func TestReleaseFailedRestore_ParksExplicitDurableMarker(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	vms := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vms, "vm-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vms, "vm-1", "cgroup.events"), []byte("populated 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inst := &VMInstance{ID: "vm-1", Status: StatusError, Supervision: SupervisionCgroup}
	if err := store.Put(toRecord(inst)); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, netMgr: &network.Manager{},
		cgroups: &cgroupTree{vms: vms}, vms: map[string]*VMInstance{"vm-1": inst}}

	m.releaseFailedRestore("vm-1", false, false, func() { t.Fatal("must not clean the rundir of a possibly-live VM") })

	inst.mu.RLock()
	marker := inst.TeardownPending
	inst.mu.RUnlock()
	if marker == "" {
		t.Fatal("a retained release must stamp the explicit teardown marker")
	}
	rec, gerr := store.Get("vm-1")
	if gerr != nil || rec == nil || rec.TeardownPending == "" {
		t.Fatalf("the marker must be durable, got rec=%+v err=%v", rec, gerr)
	}

	// A successful relaunch retires the claim durably.
	inst.mu.Lock()
	inst.Status = StatusRunning
	inst.mu.Unlock()
	if err := m.commitResumeState(inst); err != nil {
		t.Fatalf("commitResumeState: %v", err)
	}
	rec, gerr = store.Get("vm-1")
	if gerr != nil || rec == nil {
		t.Fatal(gerr)
	}
	if rec.TeardownPending != "" {
		t.Fatal("a successful relaunch must retire the parked-teardown claim")
	}
}

// The scope-gone fallback's crash window leaves a cgroup RECORD over a live
// firecracker@ UNIT. Every record-keyed release must require BOTH supervisors
// down — the cgroup oracle alone reads that state as dead and would free the
// tap under the running unit.
func TestDestroyVM_CgroupRecordOverFallbackUnit_RefusesUntilUnitDown(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(VMRecord{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, Namespace: "ns-1"}); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		log: zerolog.Nop(), state: store, netMgr: &network.Manager{},
		cgroups: &cgroupTree{vms: t.TempDir()}, // no group: the cgroup side reads dead
		vms:     map[string]*VMInstance{},
		cfg:     ManagerConfig{RunDir: t.TempDir()},
	}

	shimSystemctlActive(t) // the fallback unit is alive
	err = m.DestroyVM(context.Background(), "vm-1", false)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("destroy over a live fallback unit must refuse Unavailable, got %v", err)
	}
	if rec, gerr := store.Get("vm-1"); gerr != nil || rec == nil {
		t.Fatal("the record must survive the refusal")
	}

	shimSystemctlDown(t) // unit finally terminal
	if err := m.DestroyVM(context.Background(), "vm-1", false); err != nil {
		t.Fatalf("destroy must complete once both supervisors are down, got %v", err)
	}
	if rec, _ := store.Get("vm-1"); rec != nil {
		t.Fatal("the record must be released after a confirmed destroy")
	}
}

// The reattach stale-sweep's release proof must also see the fallback unit.
func TestReattachRecord_CgroupRecordOverFallbackUnit_NotReleased(t *testing.T) {
	origDown := vmUnitFullyDown
	vmUnitFullyDown = func(string) bool { return false } // fallback unit alive
	defer func() { vmUnitFullyDown = origDown }()

	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dir := t.TempDir()
	sock := filepath.Join(dir, "fc.sock")
	if err := os.WriteFile(sock, []byte(""), 0o644); err != nil { // socket present
		t.Fatal(err)
	}
	rec := VMRecord{ID: "vm-1", Status: StatusRunning, Supervision: SupervisionCgroup, SocketPath: sock}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	m := &Manager{log: zerolog.Nop(), state: store, netMgr: &network.Manager{},
		cgroups: &cgroupTree{vms: t.TempDir()}, vms: map[string]*VMInstance{}}

	inst, ok := m.reattachRecord(context.Background(), rec, true)
	if inst == nil || !ok {
		t.Fatalf("the record must be kept and published, got inst=%v ok=%v", inst, ok)
	}
	if kept, gerr := store.Get("vm-1"); gerr != nil || kept == nil {
		t.Fatal("a cgroup record over a live fallback unit must never be released")
	}

	vmUnitFullyDown = func(string) bool { return true } // both down now
	m2 := &Manager{log: zerolog.Nop(), state: store, netMgr: &network.Manager{},
		cgroups: &cgroupTree{vms: t.TempDir()}, vms: map[string]*VMInstance{}}
	if _, ok := m2.reattachRecord(context.Background(), rec, true); ok {
		t.Fatal("with both supervisors down the stale record must be released")
	}
	if kept, _ := store.Get("vm-1"); kept != nil {
		t.Fatal("release must delete the record")
	}
}
