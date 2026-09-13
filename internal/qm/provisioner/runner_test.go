package provisioner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/qm/tenantstore"
)

type fakeStep struct {
	name     string
	run      func(ctx context.Context, t *Tenant, call int) error
	rollback func(ctx context.Context, t *Tenant, call int) error

	mu        sync.Mutex
	runs      int
	rollbacks int
}

func (s *fakeStep) Name() string { return s.name }

func (s *fakeStep) Run(ctx context.Context, t *Tenant) error {
	s.mu.Lock()
	s.runs++
	call := s.runs
	s.mu.Unlock()
	if s.run == nil {
		return nil
	}
	return s.run(ctx, t, call)
}

func (s *fakeStep) Rollback(ctx context.Context, t *Tenant) error {
	s.mu.Lock()
	s.rollbacks++
	call := s.rollbacks
	s.mu.Unlock()
	if s.rollback == nil {
		return nil
	}
	return s.rollback(ctx, t, call)
}

func (s *fakeStep) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs
}

type harness struct {
	store  *tenantstore.Memory
	teamID uuid.UUID
	tenant tenantstore.Tenant
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store := tenantstore.NewMemory()
	teamID := uuid.New()
	tenant, err := store.CreateTenant(context.Background(), teamID, tenantstore.CreateParams{
		Slug: "pilot-team", OrgName: "Pilot Team", AdminEmail: "admin@example.com", SignIn: "magic_link", ModelProvider: "anthropic",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{store: store, teamID: teamID, tenant: tenant}
}

func (h *harness) runner(steps ...Step) *Runner {
	return &Runner{Store: h.store, Env: Env{BaseDomain: "qm.example.com", Stub: true}, Steps: steps, Log: zerolog.Nop()}
}

// queue mirrors what the API does before triggering: move the tenant into
// the mode's in-flight status.
func (h *harness) queue(t *testing.T, mode Mode) {
	t.Helper()
	status := tenantstore.StatusProvisioning
	if mode == ModeDeprovision {
		status = tenantstore.StatusDeprovisioning
	}
	if _, err := h.store.SetStatus(context.Background(), h.teamID, h.tenant.ID, status); err != nil {
		t.Fatal(err)
	}
}

// run queues and runs mode.
func (h *harness) run(t *testing.T, r *Runner, mode Mode) error {
	t.Helper()
	h.queue(t, mode)
	return r.Run(context.Background(), h.teamID, h.tenant.ID, mode, 0)
}

func (h *harness) status(t *testing.T) string {
	t.Helper()
	row, err := h.store.GetTenant(context.Background(), h.teamID, h.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	return row.Status
}

func (h *harness) events(t *testing.T) []string {
	t.Helper()
	events, err := h.store.ListEvents(context.Background(), h.teamID, h.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Step+":"+e.Status)
	}
	return out
}

func (h *harness) lastEvent(t *testing.T, step, status string) tenantstore.Event {
	t.Helper()
	events, _ := h.store.ListEvents(context.Background(), h.teamID, h.tenant.ID)
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Step == step && events[i].Status == status {
			return events[i]
		}
	}
	t.Fatalf("no %s:%s event in %v", step, status, h.events(t))
	return tenantstore.Event{}
}

func TestRunnerProvisionHappyPath(t *testing.T) {
	h := newHarness(t)
	a, b := &fakeStep{name: "a"}, &fakeStep{name: "b"}
	if err := h.run(t, h.runner(a, b), ModeProvision); err != nil {
		t.Fatal(err)
	}
	if got := h.status(t); got != tenantstore.StatusReady {
		t.Errorf("status = %s", got)
	}
	want := "run:started,a:started,a:ok,b:started,b:ok,run:ok"
	if got := strings.Join(h.events(t), ","); got != want {
		t.Errorf("events = %s\nwant     %s", got, want)
	}
}

// A run that dies mid-plan is resumed by running the plan again: steps that
// already did their work skip, the failed one gets another go, the rest run.
func TestRunnerResumesAfterFailure(t *testing.T) {
	h := newHarness(t)
	a := &fakeStep{name: "a", run: func(_ context.Context, _ *Tenant, call int) error {
		if call > 1 {
			return Skip("already created")
		}
		return nil
	}}
	b := &fakeStep{name: "b", run: func(_ context.Context, _ *Tenant, call int) error {
		if call == 1 {
			return errors.New("transient: quota exceeded")
		}
		return nil
	}}
	c := &fakeStep{name: "c"}
	r := h.runner(a, b, c)

	err := h.run(t, r, ModeProvision)
	if err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("first run err = %v", err)
	}
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Fatalf("status after failure = %s", got)
	}
	want := "run:started,a:started,a:ok,b:started,b:failed,c:skipped,run:failed"
	if got := strings.Join(h.events(t), ","); got != want {
		t.Errorf("events = %s\nwant     %s", got, want)
	}
	if msg := h.lastEvent(t, RunStep, tenantstore.EventFailed).Message; msg == nil || !strings.Contains(*msg, "stopped at b") {
		t.Errorf("run failure message = %v", msg)
	}
	if c.count() != 0 {
		t.Errorf("step after the failure ran %d times", c.count())
	}

	if err := h.run(t, r, ModeProvision); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := h.status(t); got != tenantstore.StatusReady {
		t.Errorf("status after resume = %s", got)
	}
	tail := h.events(t)[7:]
	want = "run:started,a:started,a:skipped,b:started,b:ok,c:started,c:ok,run:ok"
	if got := strings.Join(tail, ","); got != want {
		t.Errorf("resume events = %s\nwant            %s", got, want)
	}
	if a.count() != 2 || b.count() != 2 || c.count() != 1 {
		t.Errorf("calls a=%d b=%d c=%d", a.count(), b.count(), c.count())
	}
}

func TestRunnerNotImplementedIsTyped(t *testing.T) {
	h := newHarness(t)
	s := &fakeStep{name: "database", run: func(context.Context, *Tenant, int) error { return NotImplemented("database") }}
	err := h.run(t, h.runner(s), ModeProvision)
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v, want ErrNotImplemented", err)
	}
	var nie *NotImplementedError
	if !errors.As(err, &nie) || nie.Step != "database" {
		t.Errorf("err = %#v", err)
	}
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Errorf("status = %s", got)
	}
}

func TestRunnerConcurrentRunExitsImmediately(t *testing.T) {
	h := newHarness(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	blocking := &fakeStep{name: "slow", run: func(ctx context.Context, _ *Tenant, _ int) error {
		close(entered)
		<-release
		return nil
	}}
	r := h.runner(blocking)

	first := make(chan error, 1)
	go func() { first <- r.Run(context.Background(), h.teamID, h.tenant.ID, ModeProvision, 0) }()
	<-entered

	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background(), h.teamID, h.tenant.ID, ModeProvision, 0) }()
	select {
	case err := <-done:
		if !errors.Is(err, tenantstore.ErrLocked) {
			t.Fatalf("second run err = %v, want ErrLocked", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second run did not exit while the first held the lock")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if blocking.count() != 1 {
		t.Errorf("step ran %d times", blocking.count())
	}
	if got := h.status(t); got != tenantstore.StatusReady {
		t.Errorf("status = %s", got)
	}
	// The locked-out run must leave no trace in the event log.
	want := "run:started,slow:started,slow:ok,run:ok"
	if got := strings.Join(h.events(t), ","); got != want {
		t.Errorf("events = %s\nwant     %s", got, want)
	}
}

func TestRunnerScrubsEventDetail(t *testing.T) {
	h := newHarness(t)
	leaky := &fakeStep{name: "cloud_run", run: func(context.Context, *Tenant, int) error {
		return errors.New("deploy rejected: ANTHROPIC_API_KEY=sk-ant-api03-SECRETSECRETSECRETSECRET and dsn postgres://qm:hunter2@db.example.com/qm")
	}}
	if err := h.run(t, h.runner(leaky), ModeProvision); err == nil {
		t.Fatal("expected failure")
	}
	detail := string(h.lastEvent(t, "cloud_run", tenantstore.EventFailed).Detail)
	for _, secret := range []string{"SECRETSECRET", "hunter2", "sk-ant-api03"} {
		if strings.Contains(detail, secret) {
			t.Errorf("detail leaks %q: %s", secret, detail)
		}
	}
	if !strings.Contains(detail, "[redacted]") || !strings.Contains(detail, "deploy rejected") {
		t.Errorf("detail = %s", detail)
	}
}

func TestRunnerDeprovisionRunsRollbacksInReverse(t *testing.T) {
	h := newHarness(t)
	var order []string
	var mu sync.Mutex
	mk := func(name string) *fakeStep {
		return &fakeStep{name: name, rollback: func(context.Context, *Tenant, int) error {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return nil
		}}
	}
	a, b, c := mk("a"), mk("b"), mk("c")
	r := h.runner(a, b, c)
	if err := h.run(t, r, ModeProvision); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, r, ModeDeprovision); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "c,b,a" {
		t.Errorf("rollback order = %s", got)
	}
	if got := h.status(t); got != tenantstore.StatusDeleted {
		t.Errorf("status = %s", got)
	}
	// The completion event must have landed before the tenant was
	// retired: a deleted tenant's event log accepts nothing more.
	if ev := h.events(t); ev[len(ev)-1] != "run:ok" {
		t.Errorf("last event = %s, want run:ok", ev[len(ev)-1])
	}
	if a.count() != 1 || a.rollbacks != 1 {
		t.Errorf("a runs=%d rollbacks=%d", a.count(), a.rollbacks)
	}
	if err := r.Run(context.Background(), h.teamID, h.tenant.ID, ModeProvision, 0); !errors.Is(err, ErrTenantDeleted) {
		t.Errorf("run on deleted tenant err = %v", err)
	}
	if _, err := h.store.ListTenants(context.Background(), h.teamID); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerDeprovisionFailureIsRetryable(t *testing.T) {
	h := newHarness(t)
	a := &fakeStep{name: "a", rollback: func(_ context.Context, _ *Tenant, call int) error {
		if call == 1 {
			return errors.New("bucket not empty")
		}
		return nil
	}}
	r := h.runner(a)
	if err := h.run(t, r, ModeDeprovision); err == nil {
		t.Fatal("expected failure")
	}
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Errorf("status = %s", got)
	}
	if err := h.run(t, r, ModeDeprovision); err != nil {
		t.Fatal(err)
	}
	if got := h.status(t); got != tenantstore.StatusDeleted {
		t.Errorf("status = %s", got)
	}
}

func TestTenantHelpers(t *testing.T) {
	h := newHarness(t)
	tenant := NewTenant(h.tenant, Env{BaseDomain: "qm.example.com"}, h.store)
	if tenant.Hostname() != "pilot-team.qm.example.com" || tenant.PublicURL() != "https://pilot-team.qm.example.com" {
		t.Errorf("hostname=%s url=%s", tenant.Hostname(), tenant.PublicURL())
	}
	if tenant.SecretName("PORTAL_SESSION_SECRET") != "qm-pilot-team-PORTAL_SESSION_SECRET" {
		t.Errorf("secret name = %s", tenant.SecretName("PORTAL_SESSION_SECRET"))
	}
	name := "qm_pilot_team"
	if err := tenant.Record(context.Background(), tenantstore.Resources{DBName: &name}); err != nil {
		t.Fatal(err)
	}
	if tenant.Row.DbName == nil || *tenant.Row.DbName != name {
		t.Errorf("row not refreshed after Record: %+v", tenant.Row)
	}
}

func TestDeprovisionPlanMirrorsProvisionPlan(t *testing.T) {
	a, b := &fakeStep{name: "a"}, &fakeStep{name: "b"}
	plan := DeprovisionPlan([]Step{a, b})
	if plan.Mode != ModeDeprovision || len(plan.Steps) != 2 || plan.Steps[0].Name() != "b" || plan.Steps[1].Name() != "a" {
		t.Errorf("plan = %+v", plan)
	}
	if _, ok := ParseMode("reprovision"); ok {
		t.Error("unknown mode parsed")
	}
}

// A terminal write that fails must not leave the tenant in flight: the run
// reports the error and the tenant is retryable.
func TestRunnerTerminalWriteFailureIsRetryable(t *testing.T) {
	h := newHarness(t)
	r := h.runner(&fakeStep{name: "a"})
	readyWrites := 0
	h.store.BeforeSetStatus = func(status string) error {
		if status == tenantstore.StatusReady {
			readyWrites++
			if readyWrites == 1 {
				return errors.New("connection reset")
			}
		}
		return nil
	}
	err := h.run(t, r, ModeProvision)
	if err == nil || !strings.Contains(err.Error(), "mark tenant ready") {
		t.Fatalf("err = %v", err)
	}
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Fatalf("status = %s, want failed", got)
	}
	if msg := h.lastEvent(t, RunStep, tenantstore.EventFailed).Message; msg == nil || !strings.Contains(*msg, "marked ready") {
		t.Errorf("message = %v", msg)
	}
	if err := h.run(t, r, ModeProvision); err != nil {
		t.Fatal(err)
	}
	if got := h.status(t); got != tenantstore.StatusReady {
		t.Errorf("status after retry = %s", got)
	}

	deletes := 0
	h.store.BeforeSoftDelete = func() error {
		deletes++
		if deletes == 1 {
			return errors.New("connection reset")
		}
		return nil
	}
	if err := h.run(t, r, ModeDeprovision); err == nil {
		t.Fatal("expected soft-delete failure to surface")
	}
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Fatalf("status = %s, want failed", got)
	}
	if err := h.run(t, r, ModeDeprovision); err != nil {
		t.Fatal(err)
	}
	if got := h.status(t); got != tenantstore.StatusDeleted {
		t.Errorf("status after retry = %s", got)
	}
}

// Bookkeeping lands even when the run's context is already cancelled.
func TestRunnerRecordsUnderCancelledContext(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	step := &fakeStep{name: "a", run: func(ctx context.Context, _ *Tenant, _ int) error {
		cancel()
		return ctx.Err()
	}}
	if err := h.runner(step).Run(ctx, h.teamID, h.tenant.ID, ModeProvision, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Errorf("status = %s, want failed", got)
	}
	want := "run:started,a:started,a:failed,run:failed"
	if got := strings.Join(h.events(t), ","); got != want {
		t.Errorf("events = %s\nwant     %s", got, want)
	}
}

// A queued execution whose intent has since changed does nothing: the
// tenant keeps its status and gets no events.
func TestRunnerRejectsStaleExecution(t *testing.T) {
	h := newHarness(t)
	step := &fakeStep{name: "a"}
	r := h.runner(step)
	// Delete requested while a provision execution was still queued.
	h.queue(t, ModeDeprovision)
	err := r.Run(context.Background(), h.teamID, h.tenant.ID, ModeProvision, 0)
	if !errors.Is(err, ErrStaleRun) {
		t.Fatalf("err = %v, want ErrStaleRun", err)
	}
	if got := h.status(t); got != tenantstore.StatusDeprovisioning {
		t.Errorf("status = %s, want deprovisioning kept", got)
	}
	if step.count() != 0 || len(h.events(t)) != 0 {
		t.Errorf("stale run did work: runs=%d events=%v", step.count(), h.events(t))
	}
	// A failed tenant is only re-run once the API has re-queued it.
	if _, err := h.store.SetStatus(context.Background(), h.teamID, h.tenant.ID, tenantstore.StatusFailed); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background(), h.teamID, h.tenant.ID, ModeDeprovision, 0); !errors.Is(err, ErrStaleRun) {
		t.Errorf("run from failed without re-queue: err = %v", err)
	}
}

func TestRecordSetupFailure(t *testing.T) {
	h := newHarness(t)
	h.queue(t, ModeDeprovision)
	RecordSetupFailure(context.Background(), h.store, zerolog.Nop(), h.teamID, h.tenant.ID, ModeDeprovision, 0, errors.New("secret manager client: permission denied"))
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Fatalf("status = %s, want failed", got)
	}
	ev := h.lastEvent(t, RunStep, tenantstore.EventFailed)
	if !strings.Contains(string(ev.Detail), `"mode":"deprovision"`) {
		t.Errorf("detail = %s", ev.Detail)
	}
	// Not in flight (already reclaimed by someone else): nothing happens.
	RecordSetupFailure(context.Background(), h.store, zerolog.Nop(), h.teamID, h.tenant.ID, ModeDeprovision, 0, errors.New("again"))
	if n := len(h.events(t)); n != 1 {
		t.Errorf("events = %v", h.events(t))
	}
	// A replacement run holding the lock owns the status; the late
	// failure report leaves it alone.
	h.queue(t, ModeDeprovision)
	release, err := h.store.Lock(context.Background(), h.teamID, h.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	RecordSetupFailure(context.Background(), h.store, zerolog.Nop(), h.teamID, h.tenant.ID, ModeDeprovision, 0, errors.New("late"))
	release()
	if got := h.status(t); got != tenantstore.StatusDeprovisioning {
		t.Errorf("status = %s, want deprovisioning kept", got)
	}
	if n := len(h.events(t)); n != 1 {
		t.Errorf("events = %v", h.events(t))
	}
}

// Failure bookkeeping is ordered and bounded: the tenant is marked failed
// before the optional events, so a database that cannot take the events (or
// a job killed while it tries) still leaves the tenant retryable rather
// than in flight.
func TestRunnerMarksFailedEvenWhenEventsCannotBeWritten(t *testing.T) {
	h := newHarness(t)
	store := &eventRefusingStore{Memory: h.store}
	a := &fakeStep{name: "a", run: func(context.Context, *Tenant, int) error { return errors.New("boom") }}
	b := &fakeStep{name: "b"}
	r := &Runner{Store: store, Env: Env{BaseDomain: "qm.example.com", Stub: true}, Steps: []Step{a, b}, Log: zerolog.Nop()}
	h.queue(t, ModeProvision)
	store.refuse = true
	if err := r.Run(context.Background(), h.teamID, h.tenant.ID, ModeProvision, 0); err == nil {
		t.Fatal("run reported success")
	}
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Errorf("status = %s, want failed", got)
	}
	if b.count() != 0 {
		t.Error("the step after the failure ran")
	}
}

// eventRefusingStore rejects every event write while refuse is set, as a
// database that is gone would.
type eventRefusingStore struct {
	*tenantstore.Memory
	refuse bool
}

func (s *eventRefusingStore) InsertEvent(ctx context.Context, teamID uuid.UUID, p tenantstore.EventParams) (tenantstore.Event, error) {
	if s.refuse {
		return tenantstore.Event{}, errors.New("database unavailable")
	}
	return s.Memory.InsertEvent(ctx, teamID, p)
}

// An execution delayed past the stale reclaim can arrive after a retry has
// queued a fresh attempt in the same mode. Status alone cannot tell the two
// apart, so the run is bound to the intent event that queued it and the
// superseded execution exits without taking the tenant from its successor.
func TestRunnerRefusesASupersededAttempt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	queue := func() int64 {
		t.Helper()
		e, err := h.store.InsertEvent(ctx, h.teamID, tenantstore.EventParams{
			TenantID: h.tenant.ID, Step: TriggerStep, Status: tenantstore.EventStarted, Message: "provision run requested",
		})
		if err != nil {
			t.Fatal(err)
		}
		return e.Seq
	}
	first := queue()
	second := queue()

	a := &fakeStep{name: "a"}
	r := h.runner(a)
	h.queue(t, ModeProvision)
	if err := r.Run(ctx, h.teamID, h.tenant.ID, ModeProvision, first); !errors.Is(err, ErrStaleRun) {
		t.Fatalf("superseded attempt: err = %v, want a stale run", err)
	}
	if a.count() != 0 {
		t.Error("a superseded execution ran the plan")
	}
	if got := h.status(t); got != tenantstore.StatusProvisioning {
		t.Errorf("status = %s, want the successor left queued", got)
	}

	if err := r.Run(ctx, h.teamID, h.tenant.ID, ModeProvision, second); err != nil {
		t.Fatalf("newest attempt: %v", err)
	}
	if got := h.status(t); got != tenantstore.StatusReady {
		t.Errorf("status = %s", got)
	}
	// Zero is an operator running the job by hand: no attempt to check.
	h.queue(t, ModeProvision)
	if err := r.Run(ctx, h.teamID, h.tenant.ID, ModeProvision, 0); err != nil {
		t.Fatalf("unchecked attempt: %v", err)
	}
}

// The same rule covers a setup failure: an execution whose attempt was
// superseded owns nothing and must not mark its replacement failed.
func TestRecordSetupFailureIgnoresASupersededAttempt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	queue := func() int64 {
		t.Helper()
		e, err := h.store.InsertEvent(ctx, h.teamID, tenantstore.EventParams{
			TenantID: h.tenant.ID, Step: TriggerStep, Status: tenantstore.EventStarted, Message: "provision run requested",
		})
		if err != nil {
			t.Fatal(err)
		}
		return e.Seq
	}
	first := queue()
	queue()
	h.queue(t, ModeProvision)

	RecordSetupFailure(ctx, h.store, zerolog.Nop(), h.teamID, h.tenant.ID, ModeProvision, first, errors.New("no database"))
	if got := h.status(t); got != tenantstore.StatusProvisioning {
		t.Errorf("status = %s, want the successor left queued", got)
	}
}

// A terminal write can commit and still report an error. The fallback for
// that error marks the tenant failed, which on a run that in fact succeeded
// would undo it, so the row is consulted before the fallback runs.
func TestRunnerKeepsATerminalWriteThatCommitted(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		mode Mode
		want string
	}{
		{"provision", ModeProvision, tenantstore.StatusReady},
		{"deprovision", ModeDeprovision, tenantstore.StatusDeleted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			store := &ambiguousTerminalStore{Memory: h.store, want: tc.want}
			r := &Runner{Store: store, Env: Env{BaseDomain: "qm.example.com", Stub: true}, Steps: []Step{&fakeStep{name: "a"}}, Log: zerolog.Nop()}
			h.queue(t, tc.mode)
			if err := r.Run(ctx, h.teamID, h.tenant.ID, tc.mode, 0); err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := h.status(t); got != tc.want {
				t.Errorf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

// ambiguousTerminalStore commits the terminal write and then reports a
// transport error for it.
type ambiguousTerminalStore struct {
	*tenantstore.Memory
	want string
	done bool
}

func (s *ambiguousTerminalStore) SetStatus(ctx context.Context, teamID, tenantID uuid.UUID, status string) (tenantstore.Tenant, error) {
	t, err := s.Memory.SetStatus(ctx, teamID, tenantID, status)
	if err == nil && !s.done && status == s.want {
		s.done = true
		return tenantstore.Tenant{}, errors.New("connection reset")
	}
	return t, err
}

func (s *ambiguousTerminalStore) SoftDelete(ctx context.Context, teamID, tenantID uuid.UUID) (tenantstore.Tenant, error) {
	t, err := s.Memory.SoftDelete(ctx, teamID, tenantID)
	if err == nil && !s.done && s.want == tenantstore.StatusDeleted {
		s.done = true
		return tenantstore.Tenant{}, errors.New("connection reset")
	}
	return t, err
}

// If the terminal write commits, reports an error, and the reconciling read
// also fails, the fallback must still not undo it: it moves the tenant only
// from the status this run owns, which a committed terminal write has
// already left behind.
func TestRunnerFallbackCannotUndoACommittedTerminalWrite(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	store := &blindAmbiguousStore{Memory: h.store}
	r := &Runner{Store: store, Env: Env{BaseDomain: "qm.example.com", Stub: true}, Steps: []Step{&fakeStep{name: "a"}}, Log: zerolog.Nop()}
	h.queue(t, ModeProvision)
	if err := r.Run(ctx, h.teamID, h.tenant.ID, ModeProvision, 0); err == nil {
		t.Fatal("run reported success")
	}
	if got := h.status(t); got != tenantstore.StatusReady {
		t.Errorf("status = %s, want the committed ready kept", got)
	}
}

// blindAmbiguousStore commits the ready transition, reports an error for
// it, and then fails the reconciling read too.
type blindAmbiguousStore struct {
	*tenantstore.Memory
	blind bool
}

func (s *blindAmbiguousStore) SetStatus(ctx context.Context, teamID, tenantID uuid.UUID, status string) (tenantstore.Tenant, error) {
	t, err := s.Memory.SetStatus(ctx, teamID, tenantID, status)
	if err == nil && !s.blind && status == tenantstore.StatusReady {
		s.blind = true
		return tenantstore.Tenant{}, errors.New("connection reset")
	}
	return t, err
}

func (s *blindAmbiguousStore) GetTenant(ctx context.Context, teamID, tenantID uuid.UUID) (tenantstore.Tenant, error) {
	if s.blind {
		return tenantstore.Tenant{}, errors.New("database unavailable")
	}
	return s.Memory.GetTenant(ctx, teamID, tenantID)
}

// A transient error claiming the tenant would otherwise leave it in flight
// with nothing behind it: the job has no automatic retry, so the run marks
// it failed itself and the caller can retry at once.
func TestRunnerFailsATenantItCouldNotClaim(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	store := &claimFailingStore{Memory: h.store}
	a := &fakeStep{name: "a"}
	r := &Runner{Store: store, Env: Env{BaseDomain: "qm.example.com", Stub: true}, Steps: []Step{a}, Log: zerolog.Nop()}
	h.queue(t, ModeProvision)
	if err := r.Run(ctx, h.teamID, h.tenant.ID, ModeProvision, 0); err == nil {
		t.Fatal("run reported success")
	}
	if a.count() != 0 {
		t.Error("the plan ran without claiming the tenant")
	}
	if got := h.status(t); got != tenantstore.StatusFailed {
		t.Errorf("status = %s, want failed", got)
	}
}

// claimFailingStore reports a database error from the run's self-transition.
type claimFailingStore struct {
	*tenantstore.Memory
	done bool
}

func (s *claimFailingStore) TransitionStatus(ctx context.Context, teamID, tenantID uuid.UUID, from []string, to string) (tenantstore.Tenant, error) {
	if !s.done && len(from) == 1 && from[0] == to {
		s.done = true
		return tenantstore.Tenant{}, errors.New("database unavailable")
	}
	return s.Memory.TransitionStatus(ctx, teamID, tenantID, from, to)
}
