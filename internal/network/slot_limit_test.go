package network

import (
	"errors"
	"testing"
)

// The operator limit caps how many indexes a host MINTS. Reuse of an index
// the host already prepared is not growth and must stay allowed, which is
// also what keeps a resume working on a host at its limit: a resume reuses
// the index recorded in its namespace and never reaches the mint path.
func TestOperatorSlotLimitCapsMintingButNotReuse(t *testing.T) {
	m := &Manager{
		slotOwner:        make(map[int]string),
		nextSlot:         1,
		operatorMaxSlots: 2,
	}

	first, err := m.claimSlotIndex("vm-1")
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if _, err := m.claimSlotIndex("vm-2"); err != nil {
		t.Fatalf("second claim: %v", err)
	}
	// Third mint is over the operator's policy.
	if _, err := m.claimSlotIndex("vm-3"); !errors.Is(err, ErrOperatorSlotLimit) {
		t.Fatalf("third claim: got %v, want ErrOperatorSlotLimit", err)
	}

	// Recycle the index the way reclaim does — return it to freeSlots and
	// drop its ownership — rather than through ReleaseSlot, which also
	// tears down real namespace and veth state this test has no business
	// standing up. What matters here is only that a claim served from
	// inventory is a reuse, not a mint, so the limit must not block it.
	m.mu.Lock()
	delete(m.slotOwner, first)
	m.freeSlots = append(m.freeSlots, first)
	m.mu.Unlock()

	if got, err := m.claimSlotIndex("vm-4"); err != nil {
		t.Fatalf("reuse of a recycled index refused at the operator limit: %v", err)
	} else if got != first {
		t.Fatalf("reuse handed out index %d, want the recycled %d", got, first)
	}
}

// Zero means no policy limit, which is what every host that has not opted
// in runs with — including hosts where VMD_MAX_NETWORK_SLOTS is already set
// for pressure publication.
func TestOperatorSlotLimitZeroIsUnlimited(t *testing.T) {
	m := &Manager{
		slotOwner: make(map[int]string),
		nextSlot:  1,
	}
	for i := 0; i < 50; i++ {
		if _, err := m.claimSlotIndex("vm"); err != nil {
			t.Fatalf("claim %d refused with no operator limit set: %v", i, err)
		}
	}
}

// The policy refusal must stay distinguishable from kernel exhaustion: one
// means "place this elsewhere", the other means the host's slot range is
// genuinely used up. Collapsing them would make a policy limit read as a
// host fault.
func TestOperatorSlotLimitIsDistinctFromKernelExhaustion(t *testing.T) {
	if errors.Is(ErrOperatorSlotLimit, ErrNoSlots) || errors.Is(ErrNoSlots, ErrOperatorSlotLimit) {
		t.Fatal("operator-limit and kernel-exhaustion errors are conflated")
	}
}
