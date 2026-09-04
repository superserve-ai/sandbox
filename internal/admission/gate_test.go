package admission

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// The whole point of the gate: N racers against room for K admit exactly K.
// Written against the real gate under real concurrency rather than a
// serialized approximation, because a limit that is checked and then
// committed in two steps passes every sequential test and still overshoots
// under load — which is the only way this failure ever shows up.
func TestAdmissionGateAdmitsExactlyItsLimitUnderRace(t *testing.T) {
	const limit, racers = 3, 20
	g := NewGate(true, limit)
	g.Reconstruct(g.BeginReconstruct(), nil, nil)
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
	g.Reconstruct(g.BeginReconstruct(), nil, nil)
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
	g.Reconstruct(g.BeginReconstruct(), nil, nil)
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
	g.Reconstruct(g.BeginReconstruct(), nil, nil)
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

// An enabled gate starts in reconstructing, because a restarted daemon does
// not yet know what it is holding.
//
// It must NOT refuse during that window. The RPC server serves throughout a
// restart, so work that arrives mid-rebuild succeeds today; refusing it
// would convert every deploy into a create-and-resume outage on this host.
// Admitting instead is no worse than a host with no limit configured, which
// is what every host was before this existed.
func TestAdmissionGateAdmitsWhileReconstructing(t *testing.T) {
	g := NewGate(true, 1) // a limit of one, deliberately already "exceeded"
	if got := g.State(); got != StateReconstructing {
		t.Fatalf("initial state %v, want reconstructing", got)
	}
	for _, id := range []string{"sb-1", "sb-2", "sb-3"} {
		if err := g.Admit(id, IntentCreate); err != nil {
			t.Fatalf("%s refused during reconstruction: %v; a restart would deny every create", id, err)
		}
	}
	if err := g.Admit("sb-4", IntentResume); err != nil {
		t.Fatalf("resume refused during reconstruction: %v", err)
	}
}

// Admitting during the rebuild is only safe because those admissions are
// still CHARGED — they carry a generation above the rebuild's snapshot, so
// they survive it and the ledger is correct the instant the gate opens.
// Were they admitted uncharged, the host would open believing it had room
// it had already given away.
func TestAdmissionGateChargesWorkAdmittedWhileReconstructing(t *testing.T) {
	g := NewGate(true, 10)
	since := g.BeginReconstruct()
	if err := g.Admit("arrived-during-rebuild", IntentCreate); err != nil {
		t.Fatal(err)
	}
	g.Reconstruct(since, []string{"survivor-1", "survivor-2"}, []string{"build-1"})
	g.Open()

	if !g.Holds("arrived-during-rebuild") {
		t.Fatal("work admitted during the rebuild was not charged; the gate opens over-committed")
	}
	if got := g.Charged(); got != 4 {
		t.Fatalf("charged %d, want 4 (two survivors, a builder, and the in-flight create)", got)
	}
}

// Builders hold a sandbox token because their pressure is published as
// provisioning sandboxes and ranking counts provisioning against this same
// limit. A gate that ignored them would enforce a different limit than the
// one placement believes in.
func TestAdmissionGateCountsBuildersAgainstTheSandboxLimit(t *testing.T) {
	g := NewGate(true, 2)
	g.Reconstruct(g.BeginReconstruct(), nil, nil)
	g.Open()

	if err := g.AdmitBuild("build-1", "worker-1"); err != nil {
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
	if err := g.AdmitBuild("build-2", "worker-2"); !errors.Is(err, ErrHostAtCapacity) {
		t.Fatalf("build admitted past the limit: got %v, want ErrHostAtCapacity", err)
	}
}

// Drain stops new placement without breaking sandboxes the host already
// owns: a resume of one of ours still lands, and a retry of an in-flight
// create still completes.
func TestAdmissionGateDrainRefusesNewButNotOwned(t *testing.T) {
	g := NewGate(true, 10)
	g.Reconstruct(g.BeginReconstruct(), []string{"existing"}, nil)
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
	g.Reconstruct(g.BeginReconstruct(), nil, nil)
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
	g.Reconstruct(g.BeginReconstruct(), []string{"a", "b", "c"}, nil)
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

// A rebuild reads a persistent store, which takes time, and the gate keeps
// admitting owned work while it reads. A create admitted in that window is
// absent from the snapshot the rebuild is holding — so a rebuild that
// replaced the ledger wholesale would drop its charge and let the host
// over-admit by exactly the number of creates in flight.
func TestReconstructKeepsTokensChargedWhileItWasReading(t *testing.T) {
	g := NewGate(true, 10)
	g.Reconstruct(g.BeginReconstruct(), []string{"old"}, nil)
	g.Open()

	// A rebuild begins: it captures the generation, then reads its store.
	since := g.BeginReconstruct()

	// Mid-read, a create is admitted. It cannot appear in what the rebuild
	// is about to hand back, because that snapshot predates it.
	if err := g.Admit("in-flight", IntentCreate); err != nil {
		t.Fatal(err)
	}

	// The rebuild commits what it saw: only the old sandbox.
	g.Reconstruct(since, []string{"old"}, nil)

	if !g.Holds("in-flight") {
		t.Fatal("a create admitted during the rebuild lost its charge; the host would over-admit by one per in-flight create")
	}
	if !g.Holds("old") {
		t.Fatal("the rebuild dropped a sandbox it observed")
	}
	if got := g.Charged(); got != 2 {
		t.Fatalf("charged %d, want 2", got)
	}
}

// A rebuild is authoritative for everything that predates it: a token whose
// work is gone must not survive, or the host shrinks silently until restart.
func TestReconstructDropsTokensItsSnapshotDoesNotContain(t *testing.T) {
	g := NewGate(true, 10)
	g.Reconstruct(g.BeginReconstruct(), []string{"stale-1", "stale-2", "live"}, nil)
	g.Open()

	// The store now reports only one of them; the other two are gone.
	g.Reconstruct(g.BeginReconstruct(), []string{"live"}, nil)

	if g.Holds("stale-1") || g.Holds("stale-2") {
		t.Fatal("a rebuild kept tokens its authoritative source no longer lists; leaked capacity never returns")
	}
	if got := g.Charged(); got != 1 {
		t.Fatalf("charged %d, want 1", got)
	}
}

// A build id can be re-registered while the previous worker is still
// winding down, and that outgoing worker releases on its way out. Releasing
// by id alone would free the REPLACEMENT's charge and let the host
// over-admit for as long as the replacement runs.
func TestReleaseOwnedIgnoresASupersededHolder(t *testing.T) {
	g := NewGate(true, 10)
	g.Reconstruct(g.BeginReconstruct(), nil, nil)
	g.Open()

	first := "worker-a"
	second := "worker-b"
	if err := g.AdmitBuild("build-1", first); err != nil {
		t.Fatal(err)
	}
	// The id is re-registered under a new worker before the old one exits.
	if err := g.AdmitBuild("build-1", second); err != nil {
		t.Fatal(err)
	}
	// The outgoing worker finally exits and releases.
	g.ReleaseOwned("build-1", first)

	if !g.Holds("build-1") {
		t.Fatal("a superseded worker's release freed the replacement's charge")
	}
	// The replacement's own release does take effect.
	g.ReleaseOwned("build-1", second)
	if g.Holds("build-1") {
		t.Fatal("the owning worker's release did not free its charge")
	}
}
