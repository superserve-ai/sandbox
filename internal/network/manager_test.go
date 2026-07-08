package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

func withTestNetnsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := netnsDir
	netnsDir = dir
	t.Cleanup(func() { netnsDir = old })
	return dir
}

func touchNS(t *testing.T, dir, name string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("create fake netns %s: %v", name, err)
	}
	_ = f.Close()
}

func newTestManager() *Manager {
	return &Manager{
		log:       zerolog.Nop(),
		devices:   make(map[string]*VMNetInfo),
		slotOwner: make(map[int]string),
		nextSlot:  1,
	}
}

func TestReserveSlotsAbove(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	// Every record's slot is reserved under its vmID and bumps nextSlot —
	// including ns-9 whose netns is absent (a dead record still holds its index
	// until the reattach reclaims it). bogus is unparseable and skipped.
	m.ReserveSlotsAbove(map[string]string{"vm-5": "ns-5", "vm-b": "bogus", "vm-9": "ns-9"})
	if m.nextSlot != 10 {
		t.Fatalf("nextSlot = %d, want 10 (past highest reserved ns-9)", m.nextSlot)
	}
	if m.slotOwner[5] != "vm-5" || m.slotOwner[9] != "vm-9" {
		t.Errorf("slots must be owned by their vmIDs: slotOwner=%v", m.slotOwner)
	}
	// A lower index reserves but must never pull nextSlot back down.
	m.ReserveSlotsAbove(map[string]string{"vm-3": "ns-3"})
	if m.nextSlot != 10 {
		t.Fatalf("nextSlot = %d, want 10 (unchanged by lower index)", m.nextSlot)
	}
}

func TestSlotFromNamespace(t *testing.T) {
	cases := []struct {
		in      string
		wantIdx int
		wantOK  bool
	}{
		{"ns-0", 0, true},
		{"ns-1", 1, true},
		{"ns-17", 17, true},
		{"ns-9999", 9999, true},
		{"", 0, false},
		{"ns-", 0, false},
		{"ns", 0, false},
		{"foo-1", 0, false},
		{"ns-abc", 0, false},
		{"ns-1foo", 0, false},
		{"ns-2-extra", 0, false},
		{"ns--1", 0, false},
		{"ns-0x10", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			idx, ok := slotFromNamespace(tc.in)
			if ok != tc.wantOK || idx != tc.wantIdx {
				t.Errorf("slotFromNamespace(%q) = (%d, %v), want (%d, %v)", tc.in, idx, ok, tc.wantIdx, tc.wantOK)
			}
		})
	}
}

func TestClaimSlotIndex_FreshNextSlot(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()

	idx, err := m.claimSlotIndex(poolOwner)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if idx != 1 {
		t.Errorf("idx = %d, want 1", idx)
	}
	if m.nextSlot != 2 {
		t.Errorf("nextSlot = %d, want 2", m.nextSlot)
	}
}

func TestClaimSlotIndex_PrefersFreeSlotsLIFO(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	m.freeSlots = []int{5, 7}

	idx, err := m.claimSlotIndex(poolOwner)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if idx != 7 {
		t.Errorf("idx = %d, want 7 (LIFO pop)", idx)
	}
	if len(m.freeSlots) != 1 || m.freeSlots[0] != 5 {
		t.Errorf("freeSlots = %v, want [5]", m.freeSlots)
	}
	if m.nextSlot != 1 {
		t.Errorf("nextSlot bumped to %d when popping from freeSlots", m.nextSlot)
	}
}

func TestClaimSlotIndex_SkipsPhantomFromNextSlot(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-1")
	touchNS(t, dir, "ns-2")
	m := newTestManager()

	idx, err := m.claimSlotIndex(poolOwner)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if idx != 3 {
		t.Errorf("idx = %d, want 3 (1 and 2 are phantoms)", idx)
	}
	if m.nextSlot != 4 {
		t.Errorf("nextSlot = %d, want 4 (advanced past phantoms)", m.nextSlot)
	}
}

func TestClaimSlotIndex_SkipsPhantomFromFreeSlots(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-7") // 7 is top-of-stack (LIFO), phantom in kernel
	m := newTestManager()
	m.freeSlots = []int{5, 7}

	idx, err := m.claimSlotIndex(poolOwner)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if idx != 5 {
		t.Errorf("idx = %d, want 5 (7 skipped as phantom, fell back to 5)", idx)
	}
	if len(m.freeSlots) != 0 {
		t.Errorf("freeSlots = %v, want [] (both popped)", m.freeSlots)
	}
}

func TestClaimSlotIndex_ErrNoSlotsWhenExhausted(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	m.nextSlot = MaxSlots + 1

	_, err := m.claimSlotIndex(poolOwner)
	if !errors.Is(err, ErrNoSlots) {
		t.Errorf("err = %v, want ErrNoSlots", err)
	}
}

func TestEnsureVMSlot_HealthyVMReplaysFirewall(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-3")
	m := newTestManager()
	existing := &VMNetInfo{Namespace: "ns-3", HostIP: "10.11.0.3"}
	m.devices["vm-x"] = existing

	got, err := m.EnsureVMSlot(context.Background(), "vm-x", "ns-3", "10.11.0.3", "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != existing {
		t.Errorf("expected same VMNetInfo pointer back (Firewall handle preserved)")
	}
}

func TestEnsureVMSlot_ReconstructWhenDeviceMapEmpty(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-7")
	m := newTestManager()

	got, err := m.EnsureVMSlot(context.Background(), "vm-y", "ns-7", "10.11.0.7", "AA:FC:00:00:00:07")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Namespace != "ns-7" || got.HostIP != "10.11.0.7" || got.MACAddress != "AA:FC:00:00:00:07" {
		t.Errorf("reconstructed info wrong: %+v", got)
	}
	if got.Firewall != nil {
		t.Errorf("Firewall handle should be nil; UpdateFirewallRules creates a fresh one")
	}
	if m.devices["vm-y"] != got {
		t.Errorf("vm-y not registered in devices map after reconstruct")
	}
	if m.nextSlot < 8 {
		t.Errorf("nextSlot = %d, want >= 8 (advanced past idx 7)", m.nextSlot)
	}
}

func TestEnsureVMSlot_InvalidNamespace(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()

	_, err := m.EnsureVMSlot(context.Background(), "vm-x", "garbage", "10.11.0.3", "")
	if err == nil {
		t.Fatalf("expected error for invalid namespace, got nil")
	}
}

func TestCleanupVMOrNamespace_TrackedDelegates(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	m.devices["vm-t"] = &VMNetInfo{Namespace: "ns-2", HostIP: "10.11.0.2"}

	m.CleanupVMOrNamespace("vm-t", "")

	if _, ok := m.devices["vm-t"]; ok {
		t.Error("tracked VM should have been removed from devices via CleanupVM")
	}
}

func TestCleanupVMOrNamespace_EmptyAndInvalidNamespaceNoop(t *testing.T) {
	withTestNetnsDir(t)
	for _, ns := range []string{"", "garbage"} {
		m := newTestManager()
		m.CleanupVMOrNamespace("vm-u", ns)
		if len(m.freeSlots) != 0 {
			t.Errorf("ns=%q: freeSlots = %v, want [] (no reclaim)", ns, m.freeSlots)
		}
	}
}

func TestCleanupVMOrNamespace_MissingNamespaceStillReclaims(t *testing.T) {
	withTestNetnsDir(t) // ns-5 intentionally not touched → netns already gone
	m := newTestManager()
	m.slotOwner[5] = "vm-u" // vm-u owns slot 5 (reserved record)

	// The host-side veth-N can outlive its netns, so cleanup must still tear it
	// down and reclaim the slot even when the namespace itself is already gone.
	m.CleanupVMOrNamespace("vm-u", "ns-5")

	if len(m.freeSlots) != 1 || m.freeSlots[0] != 5 {
		t.Errorf("freeSlots = %v, want [5] (slot reclaimed despite missing netns)", m.freeSlots)
	}
}

func TestCleanupVMOrNamespace_ReclaimsUntrackedSlot(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-5")
	m := newTestManager()
	m.slotOwner[5] = "vm-u" // vm-u owns slot 5

	m.CleanupVMOrNamespace("vm-u", "ns-5")

	if len(m.freeSlots) != 1 || m.freeSlots[0] != 5 {
		t.Errorf("freeSlots = %v, want [5] (slot reclaimed)", m.freeSlots)
	}
	if _, ok := m.slotOwner[5]; ok {
		t.Error("slot 5 must be released from slotOwner")
	}
}

// Identity guard (the core fix): a stale cleanup for an old vmID must NOT tear
// down or reclaim a slot the pool/another VM has since reused.
func TestCleanupVMOrNamespace_SkipsSlotReusedByAnotherOwner(t *testing.T) {
	dir := withTestNetnsDir(t)
	touchNS(t, dir, "ns-5")
	m := newTestManager()
	m.slotOwner[5] = "new-tenant" // slot 5 was freed and reused by a new VM

	// A late cleanup for the OLD owner of ns-5 must be a no-op.
	m.CleanupVMOrNamespace("old-vm", "ns-5")

	if m.slotOwner[5] != "new-tenant" {
		t.Errorf("slot 5 ownership must be untouched, got %q", m.slotOwner[5])
	}
	if len(m.freeSlots) != 0 {
		t.Errorf("freeSlots = %v, want [] (must not reclaim a reused slot)", m.freeSlots)
	}
}

// claimSlotIndex must never return an index that is already owned — the core
// invariant that makes slot duplication impossible.
func TestClaimSlotIndex_SkipsOwned(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	m.slotOwner[1] = "vm-a" // idx 1 owned by a VM; nextSlot still 1

	idx, err := m.claimSlotIndex(poolOwner)
	if err != nil {
		t.Fatalf("claimSlotIndex: %v", err)
	}
	if idx == 1 {
		t.Fatal("claimSlotIndex returned owned idx 1")
	}
	if _, ok := m.slotOwner[idx]; !ok {
		t.Errorf("returned idx %d must be marked owned", idx)
	}
}

// Regression for the phantom-revival slot-duplication bug: a warm pool slot's
// index stays owned even when its netns is momentarily absent, so the allocator
// must NOT re-hand-out that index (which previously produced a second warm slot
// on the same index → two sandboxes on one slot).
func TestClaimSlotIndex_PhantomRevivalPrevented(t *testing.T) {
	withTestNetnsDir(t) // ns-1 absent: the warm slot's netns was deleted (phantom)
	m := newTestManager()
	m.slotOwner[1] = poolOwner // idx 1 is a warm pool slot, still owned

	idx, err := m.claimSlotIndex(poolOwner)
	if err != nil {
		t.Fatalf("claimSlotIndex: %v", err)
	}
	if idx == 1 {
		t.Fatal("claimSlotIndex re-allocated a warm (owned) slot with a missing netns — phantom revival not prevented")
	}
}

// Concurrent claims must never collide — every returned index is distinct.
func TestClaimSlotIndex_ConcurrentDistinct(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()

	const n = 64
	var wg sync.WaitGroup
	got := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			idx, err := m.claimSlotIndex(poolOwner)
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			got[i] = idx
		}(i)
	}
	wg.Wait()

	seen := make(map[int]bool, n)
	for _, idx := range got {
		if seen[idx] {
			t.Fatalf("duplicate slot index handed out: %d", idx)
		}
		seen[idx] = true
	}
}

// CleanupVMOrNamespace releases the index from owned so it can be reused.
func TestCleanupVMOrNamespace_ReleasesOwnership(t *testing.T) {
	withTestNetnsDir(t) // ns-5 absent
	m := newTestManager()
	m.ReserveSlotsAbove(map[string]string{"stale-vm": "ns-5"}) // stale-vm owns ns-5

	m.CleanupVMOrNamespace("stale-vm", "ns-5")

	if _, ok := m.slotOwner[5]; ok {
		t.Error("slot 5 must be released from owned after cleanup")
	}
	if len(m.freeSlots) != 1 || m.freeSlots[0] != 5 {
		t.Errorf("freeSlots = %v, want [5] (slot reclaimed)", m.freeSlots)
	}
}
