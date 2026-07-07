package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
		log:          zerolog.Nop(),
		devices:      make(map[string]*VMNetInfo),
		relinquished: make(map[int]bool),
		inFlight:     make(map[int]bool),
		nextSlot:     1,
	}
}

func TestReserveSlotsAbove(t *testing.T) {
	dir := withTestNetnsDir(t)
	m := newTestManager()
	// liveOnly: ns-5 exists (reserved), ns-9 does NOT (stale running record —
	// skipped so its slot stays free). bogus is unparseable.
	touchNS(t, dir, "ns-5")
	m.ReserveSlotsAbove(nil, []string{"ns-5", "bogus", "ns-9"})
	if m.nextSlot != 6 {
		t.Fatalf("nextSlot = %d, want 6 (past live ns-5; ns-9 skipped — no netns)", m.nextSlot)
	}
	// resumable: a paused VM's slot must be reserved even though its netns is
	// gone (host reboot wiped it) — it rebuilds ns-20 on resume.
	m.ReserveSlotsAbove([]string{"ns-20"}, nil)
	if m.nextSlot != 21 {
		t.Fatalf("nextSlot = %d, want 21 (paused ns-20 reserved despite missing netns)", m.nextSlot)
	}
	// A lower existing index must never pull nextSlot back down.
	m.ReserveSlotsAbove([]string{"ns-3"}, []string{"ns-4"})
	if m.nextSlot != 21 {
		t.Fatalf("nextSlot = %d, want 21 (unchanged by lower index)", m.nextSlot)
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

	idx, err := m.claimSlotIndex()
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

	idx, err := m.claimSlotIndex()
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

	idx, err := m.claimSlotIndex()
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

	idx, err := m.claimSlotIndex()
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

	_, err := m.claimSlotIndex()
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

	m.CleanupVMOrNamespace("vm-u", "ns-5")

	if len(m.freeSlots) != 1 || m.freeSlots[0] != 5 {
		t.Errorf("freeSlots = %v, want [5] (slot reclaimed)", m.freeSlots)
	}
}

// A slot relinquished at startup (running record whose netns was gone) that the
// pool has since reused — ns-5 exists again — must NOT be torn down or reclaimed
// by the stale record's deferred cleanup, or it corrupts the new sandbox.
func TestCleanupVMOrNamespace_RelinquishedReusedSlotSkipped(t *testing.T) {
	dir := withTestNetnsDir(t)
	m := newTestManager()

	// Startup: running record at ns-5 has no netns → relinquished.
	m.ReserveSlotsAbove(nil, []string{"ns-5"})
	// Pool reuses slot 5 for a new sandbox (recreates the netns).
	touchNS(t, dir, "ns-5")

	m.CleanupVMOrNamespace("stale-vm", "ns-5")

	if len(m.freeSlots) != 0 {
		t.Errorf("freeSlots = %v, want [] (reused slot must not be reclaimed)", m.freeSlots)
	}
}

// IsRelinquished reports true only for slots freed at startup (running record
// with no netns), so the reattach path can refuse to bind a stale vmID onto a
// slot the pool may have reused.
func TestIsRelinquished(t *testing.T) {
	dir := withTestNetnsDir(t)
	m := newTestManager()

	touchNS(t, dir, "ns-7") // ns-7 live → reserved, not relinquished
	m.ReserveSlotsAbove(nil, []string{"ns-7", "ns-5"})

	if !m.IsRelinquished("ns-5") {
		t.Error("ns-5 (running, no netns) must be relinquished")
	}
	if m.IsRelinquished("ns-7") {
		t.Error("ns-7 (live netns) must not be relinquished")
	}
	if m.IsRelinquished("ns-99") {
		t.Error("ns-99 (never seen) must not be relinquished")
	}
	if m.IsRelinquished("bogus") {
		t.Error("unparseable namespace must not be relinquished")
	}
}

// A relinquished slot the pool has CLAIMED but not yet built (ns-N doesn't
// exist yet, but it's marked in-flight) must NOT be reclaimed by a stale-record
// cleanup — otherwise the slot is double-owned and later handed out twice.
func TestCleanupVMOrNamespace_RelinquishedInFlightSlotSkipped(t *testing.T) {
	withTestNetnsDir(t) // ns-5 intentionally absent: allocator is mid-setupSlot
	m := newTestManager()
	m.ReserveSlotsAbove(nil, []string{"ns-5"}) // ns-5 relinquished at startup
	m.mu.Lock()
	m.inFlight[5] = true // pool claimed slot 5, before setupSlot creates ns-5
	m.mu.Unlock()

	m.CleanupVMOrNamespace("stale-vm", "ns-5")

	if len(m.freeSlots) != 0 {
		t.Errorf("freeSlots = %v, want [] (in-flight slot must not be reclaimed)", m.freeSlots)
	}
}

// A relinquished slot the pool did NOT reuse — netns still gone — is safely
// reclaimed (and any leftover host veth removed) by the deferred cleanup.
func TestCleanupVMOrNamespace_RelinquishedUnusedSlotReclaimed(t *testing.T) {
	withTestNetnsDir(t) // ns-5 never recreated → still gone
	m := newTestManager()

	m.ReserveSlotsAbove(nil, []string{"ns-5"})
	m.CleanupVMOrNamespace("stale-vm", "ns-5")

	if len(m.freeSlots) != 1 || m.freeSlots[0] != 5 {
		t.Errorf("freeSlots = %v, want [5] (unused relinquished slot reclaimed)", m.freeSlots)
	}
}
