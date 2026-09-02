package admission

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// The whole point of the gate: N racers against room for K admit exactly K.
// The design this replaced failed precisely here — 20 concurrent admissions
// against room for 3 let 8 through — so this is written against the real
// gate under real concurrency, not a serialized approximation of it.
func TestAdmissionGateAdmitsExactlyItsLimitUnderRace(t *testing.T) {
	const limit, racers = 3, 20
	g := NewGate(true, limit)
	g.Reconstruct(nil, nil)
	g.Open()

	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release them together, so they actually contend
			if err := g.Admit(fmt.Sprintf("sb-%d", i), IntentCreate); err == nil {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if admitted != limit {
		t.Fatalf("admitted %d of %d racers against room for %d; the limit is not being enforced atomically",
			admitted, racers, limit)
	}
	if got := g.Charged(); got != limit {
		t.Fatalf("ledger charges %d, want %d", got, limit)
	}
}

// Idempotency by id is what makes retries safe, and the case that proves it
// is a retry of a sandbox on a host that is already full.
//
// Deliberately NOT written as "admit the same id repeatedly, expect the
// count to stay at one": a Go map assignment is idempotent by construction,
// so that version passes whether or not the gate checks for an existing
// token — it asserts a property of the data structure rather than of the
// code, and would have shipped a missing check. What the check actually
// buys is that an already-charged id is re-admitted when a newcomer is not.
func TestAdmissionGateReadmitsAnOwnedSandboxAtCapacity(t *testing.T) {
	g := NewGate(true, 2)
	g.Reconstruct(nil, nil)
	g.Open()

	if err := g.Admit("sb-1", IntentCreate); err != nil {
		t.Fatal(err)
	}
	if err := g.Admit("sb-2", IntentCreate); err != nil {
		t.Fatal(err)
	}
	// The host is full: a newcomer is refused...
	if err := g.Admit("sb-3", IntentCreate); !errors.Is(err, ErrHostAtCapacity) {
		t.Fatalf("newcomer at capacity: got %v, want ErrHostAtCapacity", err)
	}
	// ...but a retry of a sandbox this host already charged must still
	// succeed, or a transient failure mid-create becomes a sandbox that can
	// never finish booting on the host still holding its slot.
	if err := g.Admit("sb-1", IntentCreate); err != nil {
		t.Fatalf("retry of an already-admitted sandbox refused at capacity: %v", err)
	}
	if got := g.Charged(); got != 2 {
		t.Fatalf("charged %d after the retry, want 2", got)
	}
}

// A resume is bound to this host: refusing it strands a paused sandbox
// rather than redirecting it, so the operator's sandbox limit must not
// apply to it. A create at the same limit is still refused.
func TestAdmissionGateNeverRefusesResumeOnOperatorLimit(t *testing.T) {
	g := NewGate(true, 1)
	g.Reconstruct(nil, nil)
	g.Open()

	if err := g.Admit("sb-1", IntentCreate); err != nil {
		t.Fatal(err)
	}
	if err := g.Admit("sb-2", IntentCreate); !errors.Is(err, ErrHostAtCapacity) {
		t.Fatalf("create past the limit: got %v, want ErrHostAtCapacity", err)
	}
	if err := g.Admit("sb-3", IntentResume); err != nil {
		t.Fatalf("resume refused at the operator limit: %v; a paused sandbox would be stranded", err)
	}
	if !g.Holds("sb-3") {
		t.Fatal("resume admitted but not charged; the gate would under-count real load")
	}
}

// An unspecified intent means the caller predates the field. Guessing either
// way is silently wrong — "create" double-charges a resuming sandbox,
// "resume" lets a real create past the limit — so an enabled gate refuses.
func TestAdmissionGateRefusesUnspecifiedIntentWhenEnabled(t *testing.T) {
	g := NewGate(true, 10)
	g.Reconstruct(nil, nil)
	g.Open()

	if err := g.Admit("sb-1", IntentUnspecified); !errors.Is(err, ErrIntentRequired) {
		t.Fatalf("got %v, want ErrIntentRequired", err)
	}
	if g.Charged() != 0 {
		t.Fatal("a refused boot was charged")
	}
}

// The same call on a disabled gate must behave exactly as it did before this
// existed. This is the inertness contract the rollout depends on, and it has
// to hold even with the operator limits set — they are already set in
// production for pressure publication.
func TestAdmissionGateDisabledIsInertEvenWithLimitsSet(t *testing.T) {
	g := NewGate(false, 1)
	for i := 0; i < 10; i++ {
		if err := g.Admit(fmt.Sprintf("sb-%d", i), IntentUnspecified); err != nil {
			t.Fatalf("disabled gate refused a boot: %v", err)
		}
	}
	if got := g.Charged(); got != 0 {
		t.Fatalf("disabled gate charged %d tokens; it must not maintain a ledger", got)
	}
	if g.Enabled() {
		t.Fatal("gate reports enabled")
	}
}

// The socket survives a restart and can deliver queued requests before
// reattach finishes. An enabled gate must therefore start closed — if it
// admits during reconstruction it is admitting against an empty count,
// which is no limit at all.
func TestAdmissionGateStartsClosedAndRefusesUntilOpened(t *testing.T) {
	g := NewGate(true, 10)
	if got := g.State(); got != StateReconstructing {
		t.Fatalf("initial state %v, want reconstructing", got)
	}
	if err := g.Admit("sb-1", IntentCreate); !errors.Is(err, ErrNotReady) {
		t.Fatalf("admitted before reconstruction finished: %v", err)
	}
	g.Reconstruct([]string{"survivor-1", "survivor-2"}, []string{"build-1"})
	g.Open()
	if got := g.Charged(); got != 3 {
		t.Fatalf("reconstructed ledger holds %d, want 3 (two sandboxes and a builder)", got)
	}
	if err := g.Admit("sb-1", IntentCreate); err != nil {
		t.Fatalf("refused after opening: %v", err)
	}
}

// Builders hold a sandbox token because their pressure is published as
// provisioning sandboxes and ranking counts provisioning against this same
// limit. A gate that ignored them would enforce a different limit than the
// one placement believes in.
func TestAdmissionGateCountsBuildersAgainstTheSandboxLimit(t *testing.T) {
	g := NewGate(true, 2)
	g.Reconstruct(nil, nil)
	g.Open()

	if err := g.AdmitBuild("build-1"); err != nil {
		t.Fatal(err)
	}
	if err := g.Admit("sb-1", IntentCreate); err != nil {
		t.Fatal(err)
	}
	if err := g.Admit("sb-2", IntentCreate); !errors.Is(err, ErrHostAtCapacity) {
		t.Fatalf("got %v, want ErrHostAtCapacity — the builder's token was not counted", err)
	}
	// And the reverse: a build is itself refused once the host is full.
	// Separate from the assertion above, which only proves the builder's
	// token is counted when something else asks for room — it would still
	// pass if AdmitBuild never checked the limit at all.
	if err := g.AdmitBuild("build-2"); !errors.Is(err, ErrHostAtCapacity) {
		t.Fatalf("build admitted past the limit: got %v, want ErrHostAtCapacity", err)
	}
}

// Drain stops new placement without breaking sandboxes the host already
// owns: a resume of one of ours still lands, and a retry of an in-flight
// create still completes.
func TestAdmissionGateDrainRefusesNewButNotOwned(t *testing.T) {
	g := NewGate(true, 10)
	g.Reconstruct([]string{"existing"}, nil)
	g.Open()
	if err := g.Admit("in-flight", IntentCreate); err != nil {
		t.Fatal(err)
	}

	g.Drain()
	if err := g.Admit("newcomer", IntentCreate); !errors.Is(err, ErrNotReady) {
		t.Fatalf("drain admitted a new create: %v", err)
	}
	if err := g.Admit("in-flight", IntentCreate); err != nil {
		t.Fatalf("drain broke a retry of work already admitted: %v", err)
	}
	if err := g.Admit("returning", IntentResume); err != nil {
		t.Fatalf("drain refused a resume of a host-owned sandbox: %v", err)
	}
}

// Release must be idempotent: the failure paths that call it are not
// mutually exclusive, and a second release must not free capacity a later
// sandbox has since claimed.
func TestAdmissionGateReleaseIsIdempotent(t *testing.T) {
	g := NewGate(true, 2)
	g.Reconstruct(nil, nil)
	g.Open()

	if err := g.Admit("sb-1", IntentCreate); err != nil {
		t.Fatal(err)
	}
	g.Release("sb-1")
	g.Release("sb-1") // the reconciler, after the launch path already unwound
	if err := g.Admit("sb-2", IntentCreate); err != nil {
		t.Fatal(err)
	}
	if err := g.Admit("sb-3", IntentCreate); err != nil {
		t.Fatal(err)
	}
	if err := g.Admit("sb-4", IntentCreate); !errors.Is(err, ErrHostAtCapacity) {
		t.Fatalf("got %v, want ErrHostAtCapacity — a double release freed a slot twice", err)
	}
}

// The audit is one-directional. Pressure is sampled off the hot path and can
// be taken before a just-admitted sandbox materializes, so seeing fewer than
// the ledger holds is normal. Seeing more means something is running that the
// gate is not charging for, which is a correctness bug.
func TestAdmissionGateAuditOnlyReactsToUndercount(t *testing.T) {
	g := NewGate(true, 10)
	g.Reconstruct([]string{"a", "b", "c"}, nil)
	g.Open()

	if g.AuditUndercount(1) {
		t.Fatal("audit reacted to an observation lagging the ledger; it would close the gate on every burst")
	}
	if g.AuditUndercount(3) {
		t.Fatal("audit reacted to agreement")
	}
	if !g.AuditUndercount(4) {
		t.Fatal("audit missed an undercount: a VM is running that the gate is not charging for")
	}
}
