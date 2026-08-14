package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withReceiptSeams points the receipt machinery's paths at a temp dir and
// writes the given boot-id and reader generation; empty generation means
// the mechanism is not installed.
func withReceiptSeams(t *testing.T, bootID, generation string) {
	t.Helper()
	dir := t.TempDir()
	oldReceipt, oldGen, oldBoot := receiptPath, generationPath, bootIDPath
	receiptPath = filepath.Join(dir, "netpool-receipt.json")
	generationPath = filepath.Join(dir, "generation")
	bootIDPath = filepath.Join(dir, "boot_id")
	t.Cleanup(func() { receiptPath, generationPath, bootIDPath = oldReceipt, oldGen, oldBoot })
	if err := os.WriteFile(bootIDPath, []byte(bootID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if generation != "" {
		if err := os.WriteFile(generationPath, []byte(generation+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// stubNsExecGo replaces the namespace-entry seam so vouched-slot validation
// runs without kernel namespaces. The default stub succeeds without calling
// fn (no tap/firewall to inspect); pass a custom fn to fail selectively.
func stubNsExecGo(t *testing.T, fn func(ns string, inner func() error) error) {
	t.Helper()
	old := nsExecGoFunc
	nsExecGoFunc = fn
	t.Cleanup(func() { nsExecGoFunc = old })
}

func writeTestReceipt(t *testing.T, r *poolReceipt) {
	t.Helper()
	if err := writePoolReceipt(r); err != nil {
		t.Fatal(err)
	}
}

func TestReceipt_RoundtripAndOneShot(t *testing.T) {
	withReceiptSeams(t, "boot-a", "8")
	writeTestReceipt(t, &poolReceipt{
		BootID: "boot-a", Generation: 7, Fingerprint: slotPolicyFingerprint(),
		Fresh: []int{1, 2}, Recycled: []int{3},
	})

	r, reason := consumePoolReceipt()
	if r == nil {
		t.Fatalf("valid receipt rejected: %s", reason)
	}
	if len(r.Fresh) != 2 || len(r.Recycled) != 1 {
		t.Fatalf("receipt contents lost: %+v", r)
	}
	if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatal("receipt file must be deleted on consumption")
	}
	if r2, reason2 := consumePoolReceipt(); r2 != nil || reason2 != "absent" {
		t.Fatalf("second consume must find nothing, got %v / %s", r2, reason2)
	}
}

func TestReceipt_RejectionGates(t *testing.T) {
	cases := []struct {
		name       string
		bootID     string
		writerGen  uint64
		readerGen  string
		fp         string
		wantReason string
	}{
		{"boot id mismatch", "boot-other", 7, "8", slotPolicyFingerprint(), "boot id mismatch"},
		{"generation gap", "boot-a", 6, "8", slotPolicyFingerprint(), "not the immediate successor"},
		{"same generation", "boot-a", 8, "8", slotPolicyFingerprint(), "not the immediate successor"},
		{"mechanism missing", "boot-a", 7, "", slotPolicyFingerprint(), "generation unavailable"},
		{"policy changed", "boot-a", 7, "8", "stale-fingerprint", "slot policy changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withReceiptSeams(t, "boot-a", tc.readerGen)
			writeTestReceipt(t, &poolReceipt{
				BootID: tc.bootID, Generation: tc.writerGen, Fingerprint: tc.fp, Fresh: []int{1},
			})
			r, reason := consumePoolReceipt()
			if r != nil {
				t.Fatalf("receipt must be rejected, got %+v", r)
			}
			if len(reason) < len(tc.wantReason) || reason[:len(tc.wantReason)] != tc.wantReason {
				t.Fatalf("reason = %q, want prefix %q", reason, tc.wantReason)
			}
			// Rejection must still consume: trust is destroyed, not retried.
			if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
				t.Fatal("rejected receipt must still be deleted")
			}
		})
	}
}

func TestReceipt_MalformedRejected(t *testing.T) {
	withReceiptSeams(t, "boot-a", "8")
	if err := os.WriteFile(receiptPath, []byte("{torn"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r, reason := consumePoolReceipt(); r != nil || reason[:9] != "malformed" {
		t.Fatalf("torn receipt must be rejected as malformed, got %v / %s", r, reason)
	}
}

func TestPoolStop_QuiesceSnapshotsInventory(t *testing.T) {
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	touchNS(t, dir, "ns-1")
	touchNS(t, dir, "ns-2")
	m.assignSlotLocked(1, poolOwner)
	m.assignSlotLocked(2, poolOwner)
	p.fresh <- &preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}}
	p.recycled <- &preallocSlot{idx: 2, info: &VMNetInfo{Namespace: "ns-2"}}

	p.Stop()

	if !p.quiesced {
		t.Fatal("an idle pool must quiesce within the bound")
	}
	if len(p.receiptFresh) != 1 || p.receiptFresh[0] != 1 {
		t.Fatalf("fresh snapshot = %v, want [1]", p.receiptFresh)
	}
	if len(p.receiptRecycled) != 1 || p.receiptRecycled[0] != 2 {
		t.Fatalf("recycled snapshot = %v, want [2]", p.receiptRecycled)
	}
}

func TestCommitReceipt_WritesOnlyWhenQuiesced(t *testing.T) {
	withReceiptSeams(t, "boot-a", "8")
	withTestNetnsDir(t)
	m := newTestManager()

	p := newTestPool(t, m)
	p.abandonOnStop = true
	p.quiesced = false
	p.CommitReceipt()
	if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatal("unquiesced pool must not write a receipt")
	}

	p.quiesced = true
	p.receiptFresh = []int{4}
	p.receiptRecycled = []int{5}
	p.CommitReceipt()
	r, reason := consumePoolReceipt()
	if r != nil {
		t.Fatalf("commit stamped writer generation; same-process consume must reject, got %+v", r)
	}
	if reason[:25] != "not the immediate success" {
		t.Fatalf("unexpected reason %q", reason)
	}
}

func TestCommitReceipt_AcceptedBySuccessor(t *testing.T) {
	withReceiptSeams(t, "boot-a", "8")
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true
	p.quiesced = true
	p.receiptFresh = []int{4}
	p.receiptRecycled = []int{5}
	p.CommitReceipt()

	// Simulate the successor: the drop-in bumps the generation.
	if err := os.WriteFile(generationPath, []byte("9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, reason := consumePoolReceipt()
	if r == nil {
		t.Fatalf("successor must accept, got %s", reason)
	}
	if len(r.Fresh) != 1 || r.Fresh[0] != 4 || len(r.Recycled) != 1 || r.Recycled[0] != 5 {
		t.Fatalf("snapshot mangled: %+v", r)
	}
}

func TestCommitReceipt_NoGenerationMechanismNoReceipt(t *testing.T) {
	withReceiptSeams(t, "boot-a", "")
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true
	p.quiesced = true
	p.receiptFresh = []int{4}
	p.CommitReceipt()
	if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatal("no generation mechanism → no receipt")
	}
}

// TestAdoptFromReceipt_FastPathSkipsFullAdoption pins the payoff: vouched,
// validating slots rejoin inventory without the full per-slot rebuild, and
// everything else still takes the full path.
func TestAdoptFromReceipt_FastPathSkipsFullAdoption(t *testing.T) {
	withReceiptSeams(t, "boot-a", "9")
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	// Three orphans: 1 and 2 vouched, 3 not. Slot 2's host veth is missing,
	// so its voucher must not save it — demoted to the full path.
	for _, idx := range []int{1, 2, 3} {
		touchNS(t, dir, fmt.Sprintf("ns-%d", idx))
	}
	for _, idx := range []int{1, 3} {
		if err := os.WriteFile(filepath.Join(hostNetDir, fmt.Sprintf("veth-%d", idx)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeTestReceipt(t, &poolReceipt{
		BootID: "boot-a", Generation: 8, Fingerprint: slotPolicyFingerprint(),
		Fresh: []int{1}, Recycled: []int{2},
	})

	stubNsExecGo(t, func(ns string, inner func() error) error { return nil })
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(*Manager, context.Context, string) error { return nil })
	var fullPathMu sync.Mutex
	var fullPath []int
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		fullPathMu.Lock()
		fullPath = append(fullPath, idx)
		fullPathMu.Unlock()
		return &VMNetInfo{Namespace: nsNameForSlot(idx), HostIP: hostIPForSlot(idx)}, vethNameForSlot(idx), nil
	})

	adopted, invalid, _ := p.AdoptOrphanSlots(context.Background())

	if adopted != 3 || invalid != 0 {
		t.Fatalf("adopted=%d invalid=%d, want 3/0", adopted, invalid)
	}
	// Slot 1 must have been placed by the fast path — never seen by adoptSlot.
	for _, idx := range fullPath {
		if idx == 1 {
			t.Fatal("vouched slot 1 went through full adoption")
		}
	}
	// Slots 2 (demoted) and 3 (unvouched) must have taken the full path.
	seen := map[int]bool{}
	for _, idx := range fullPath {
		seen[idx] = true
	}
	if !seen[2] || !seen[3] {
		t.Fatalf("full path handled %v, want it to include 2 and 3", fullPath)
	}
	// Fast-placed slot 1 must be claimable with its identity intact.
	var got *VMNetInfo
	for i := 0; i < 3; i++ {
		if info := p.Claim(fmt.Sprintf("vm-%d", i)); info != nil && info.Namespace == "ns-1" {
			got = info
		}
	}
	if got == nil {
		t.Fatal("fast-adopted slot never became claimable")
	}
	if got.HostIP != hostIPForSlot(1) || got.MACAddress != macForSlot(1) {
		t.Fatalf("fast-adopted identity wrong: %+v", got)
	}
}

// TestAdoptFromReceipt_CrashNeverMintsTrust pins the one-shot invariant end
// to end: a pass that consumed the receipt and then died (simulated by a
// second AdoptOrphanSlots run) must find nothing to trust.
func TestAdoptFromReceipt_CrashNeverMintsTrust(t *testing.T) {
	withReceiptSeams(t, "boot-a", "9")
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	touchNS(t, dir, "ns-1")
	if err := os.WriteFile(filepath.Join(hostNetDir, "veth-1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestReceipt(t, &poolReceipt{
		BootID: "boot-a", Generation: 8, Fingerprint: slotPolicyFingerprint(), Fresh: []int{1},
	})
	stubNsExecGo(t, func(ns string, inner func() error) error { return nil })

	p.AdoptOrphanSlots(context.Background())
	if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatal("receipt must be consumed by the pass")
	}

	// "Crash and retry": a fresh pool adopting the same host state again.
	p2 := newTestPool(t, m)
	p2.abandonOnStop = true
	var fullPath atomic.Int64
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		fullPath.Add(1)
		return &VMNetInfo{Namespace: nsNameForSlot(idx), HostIP: hostIPForSlot(idx)}, vethNameForSlot(idx), nil
	})
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(*Manager, context.Context, string) error { return nil })
	// Slot 1 is still owned by pool from the first pass, so re-adoption sees
	// no candidates — the point is only that no receipt survives to consult.
	p2.AdoptOrphanSlots(context.Background())
	if n := fullPath.Load(); n != 0 {
		t.Fatalf("no candidates expected on re-adoption, full path ran %d times", n)
	}
}

func TestPlaceVouched_PrefersPriorChannel(t *testing.T) {
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)

	if !p.placeVouched(&preallocSlot{idx: 1, info: &VMNetInfo{Namespace: "ns-1"}}, true) {
		t.Fatal("place failed with empty channels")
	}
	select {
	case s := <-p.recycled:
		if s.idx != 1 {
			t.Fatalf("wrong slot in recycled: %d", s.idx)
		}
	default:
		t.Fatal("recycled-vouched slot must land in recycled")
	}

	for i := 0; i < cap(p.recycled); i++ {
		p.recycled <- &preallocSlot{idx: 100 + i}
	}
	if !p.placeVouched(&preallocSlot{idx: 2, info: &VMNetInfo{Namespace: "ns-2"}}, true) {
		t.Fatal("overflow must fall to the other channel")
	}
	select {
	case s := <-p.fresh:
		if s.idx != 2 {
			t.Fatalf("wrong slot in fresh: %d", s.idx)
		}
	default:
		t.Fatal("overflow slot must land in fresh")
	}
}

func TestFingerprint_StableWithinProcess(t *testing.T) {
	a, b := slotPolicyFingerprint(), slotPolicyFingerprint()
	if a == "" || a != b {
		t.Fatalf("fingerprint must be non-empty and stable, got %q / %q", a, b)
	}
}

func TestReceipt_QuiesceTimeoutWritesNothing(t *testing.T) {
	withReceiptSeams(t, "boot-a", "8")
	withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	oldWait := abandonStopWait
	abandonStopWait = 50 * time.Millisecond
	t.Cleanup(func() { abandonStopWait = oldWait })

	// A worker that never observes stopCh in time: hold the wait group past
	// the quiesce bound so Stop must give up.
	p.wg.Add(1)
	release := make(chan struct{})
	go func() { defer p.wg.Done(); <-release }()

	tStart := time.Now()
	p.Stop()
	close(release)
	if time.Since(tStart) > 5*time.Second {
		t.Fatal("Stop must stay bounded")
	}
	if p.quiesced {
		t.Fatal("an un-joined pool must not report quiesced")
	}
	p.CommitReceipt()
	if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatal("timeout quiesce must write no receipt")
	}
}

// stubAttachVerify overrides the attach+verify seam.
func stubAttachVerify(t *testing.T, fn func(FirewallConfig) (*Firewall, error)) {
	t.Helper()
	old := attachAndVerifyFirewall
	attachAndVerifyFirewall = fn
	t.Cleanup(func() { attachAndVerifyFirewall = old })
}

// TestFastAdopt_UnverifiedFirewallDemotes pins the security gate: an attach
// that cannot verify the kernel objects must demote, never publish a slot
// whose namespace may hold no enforcement.
func TestFastAdopt_UnverifiedFirewallDemotes(t *testing.T) {
	withReceiptSeams(t, "boot-a", "9")
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	touchNS(t, dir, "ns-1")
	if err := os.WriteFile(filepath.Join(hostNetDir, "veth-1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestReceipt(t, &poolReceipt{
		BootID: "boot-a", Generation: 8, Fingerprint: slotPolicyFingerprint(), Fresh: []int{1},
	})
	stubNsExecGo(t, func(ns string, inner func() error) error { return inner() })
	stubAttachVerify(t, func(FirewallConfig) (*Firewall, error) {
		return nil, fmt.Errorf("attached but unverified: chain missing")
	})
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(*Manager, context.Context, string) error { return nil })
	var fullPath atomic.Int64
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		fullPath.Add(1)
		return &VMNetInfo{Namespace: nsNameForSlot(idx), HostIP: hostIPForSlot(idx)}, vethNameForSlot(idx), nil
	})

	adopted, _, _ := p.AdoptOrphanSlots(context.Background())
	if adopted != 1 || fullPath.Load() != 1 {
		t.Fatalf("unverified slot must demote to full path: adopted=%d fullPath=%d", adopted, fullPath.Load())
	}
}

// TestFastAdopt_PanicDemotes pins index accounting: a panic inside vouched
// validation must land the index in the full path, never strand it.
func TestFastAdopt_PanicDemotes(t *testing.T) {
	withReceiptSeams(t, "boot-a", "9")
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	touchNS(t, dir, "ns-1")
	if err := os.WriteFile(filepath.Join(hostNetDir, "veth-1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestReceipt(t, &poolReceipt{
		BootID: "boot-a", Generation: 8, Fingerprint: slotPolicyFingerprint(), Fresh: []int{1},
	})
	stubNsExecGo(t, func(ns string, inner func() error) error { panic("validation blew up") })
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(*Manager, context.Context, string) error { return nil })
	var fullPath atomic.Int64
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		fullPath.Add(1)
		return &VMNetInfo{Namespace: nsNameForSlot(idx), HostIP: hostIPForSlot(idx)}, vethNameForSlot(idx), nil
	})

	adopted, _, _ := p.AdoptOrphanSlots(context.Background())
	if adopted != 1 || fullPath.Load() != 1 {
		t.Fatalf("panicking validation must demote: adopted=%d fullPath=%d", adopted, fullPath.Load())
	}
}

// TestFastAdopt_TimeoutDemotesAndAborts pins the wedge protection: a hung
// in-namespace validation demotes its slot after the bound, and systemic
// timeouts abort the whole fast pass instead of hanging adoption.
func TestFastAdopt_TimeoutDemotesAndAborts(t *testing.T) {
	withReceiptSeams(t, "boot-a", "9")
	dir := withTestNetnsDir(t)
	m := newTestManager()
	p := newTestPool(t, m)
	p.abandonOnStop = true

	oldTimeout := fastAdoptSlotTimeout
	fastAdoptSlotTimeout = 30 * time.Millisecond
	t.Cleanup(func() { fastAdoptSlotTimeout = oldTimeout })

	const slots = 6
	var vouched []int
	for i := 1; i <= slots; i++ {
		touchNS(t, dir, fmt.Sprintf("ns-%d", i))
		if err := os.WriteFile(filepath.Join(hostNetDir, fmt.Sprintf("veth-%d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		vouched = append(vouched, i)
	}
	writeTestReceipt(t, &poolReceipt{
		BootID: "boot-a", Generation: 8, Fingerprint: slotPolicyFingerprint(), Fresh: vouched,
	})
	// The abandoned validation goroutines outlive the adoption pass by
	// design; the test must unblock AND drain them before the stub seam is
	// restored, or their late reads race the cleanup write. t.Cleanup runs
	// LIFO: restore is registered first (runs last), drain second (runs
	// first).
	block := make(chan struct{})
	var entered, exited atomic.Int64
	oldExec := nsExecGoFunc
	t.Cleanup(func() { nsExecGoFunc = oldExec })
	nsExecGoFunc = func(ns string, inner func() error) error {
		entered.Add(1)
		<-block
		exited.Add(1)
		return nil
	}
	t.Cleanup(func() {
		close(block)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			e := entered.Load()
			time.Sleep(50 * time.Millisecond)
			if entered.Load() == e && exited.Load() == e {
				return
			}
		}
		t.Log("warning: abandoned validators did not drain")
	})
	stubPidsInNs(t, func(string) ([]int, bool) { return nil, true })
	stubResetTap(t, func(*Manager, context.Context, string) error { return nil })
	var fullPath atomic.Int64
	stubAdoptSlot(t, func(_ *Manager, _ context.Context, idx int) (*VMNetInfo, string, error) {
		fullPath.Add(1)
		return &VMNetInfo{Namespace: nsNameForSlot(idx), HostIP: hostIPForSlot(idx)}, vethNameForSlot(idx), nil
	})

	done := make(chan struct{})
	var adopted int64
	go func() { adopted, _, _ = p.AdoptOrphanSlots(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("adoption hung on wedged fast-path validation")
	}
	if adopted != slots || fullPath.Load() != slots {
		t.Fatalf("every wedged slot must reach the full path: adopted=%d fullPath=%d", adopted, fullPath.Load())
	}
}
