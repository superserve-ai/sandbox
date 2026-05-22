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
		log:      zerolog.Nop(),
		devices:  make(map[string]*VMNetInfo),
		nextSlot: 1,
	}
}

func TestSlotFromNamespace(t *testing.T) {
	cases := []struct {
		in        string
		wantIdx   int
		wantOK    bool
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
