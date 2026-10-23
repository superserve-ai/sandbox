package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type memoryRenewalStore struct {
	mu       sync.Mutex
	now      time.Time
	journals map[renewalChoiceKey]renewalChoiceJournal
	requests map[uuid.UUID]renewalChoiceOperation
	events   []string
}
type memoryRenewalTx struct {
	s        *memoryRenewalStore
	journal  renewalChoiceJournal
	requests map[uuid.UUID]renewalChoiceOperation
	events   []string
}

func renewalClone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var copy T
	_ = json.Unmarshal(raw, &copy)
	return copy
}
func (s *memoryRenewalStore) Transact(_ context.Context, k renewalChoiceKey, f func(renewalChoiceTransaction) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journals == nil {
		s.journals = map[renewalChoiceKey]renewalChoiceJournal{}
		s.requests = map[uuid.UUID]renewalChoiceOperation{}
	}
	j, ok := s.journals[k]
	if !ok {
		j = renewalChoiceJournal{Key: k, Successor: uuid.New()}
	}
	tx := &memoryRenewalTx{s: s, journal: renewalClone(j), requests: map[uuid.UUID]renewalChoiceOperation{}}
	if err := f(tx); err != nil {
		return err
	}
	s.journals[k] = renewalClone(tx.journal)
	for id, op := range tx.requests {
		s.requests[id] = renewalClone(op)
	}
	s.events = append(s.events, tx.events...)
	return nil
}
func (t *memoryRenewalTx) SQL() pgx.Tx                    { return nil }
func (t *memoryRenewalTx) Now() time.Time                 { return t.s.now }
func (t *memoryRenewalTx) Journal() *renewalChoiceJournal { return &t.journal }
func (t *memoryRenewalTx) Find(id uuid.UUID) (*renewalChoiceOperation, error) {
	op, ok := t.s.requests[id]
	if !ok {
		return nil, nil
	}
	copy := renewalClone(op)
	return &copy, nil
}
func (t *memoryRenewalTx) Insert(op renewalChoiceOperation) error {
	t.requests[op.Request.ID] = op
	return nil
}
func (t *memoryRenewalTx) Save(event string) error {
	t.journal.Revision++
	t.events = append(t.events, event)
	return nil
}

type fixtureRenewalAuthority struct {
	key       renewalChoiceKey
	actor     uuid.UUID
	authority renewalChoiceAuthority
	monthly   bool
	revoked   bool
	now       time.Time
}

func (a *fixtureRenewalAuthority) Locate(_ context.Context, team, assignment, actor uuid.UUID) (renewalChoiceKey, error) {
	if team != a.key.Team || assignment != a.key.Assignment || actor != a.actor || a.revoked {
		return renewalChoiceKey{}, errRenewalConflict
	}
	return a.key, nil
}
func (a *fixtureRenewalAuthority) Admit(ctx context.Context, k renewalChoiceKey, actor uuid.UUID, f func(context.Context) error) error {
	if k != a.key || actor != a.actor || a.revoked {
		return errRenewalConflict
	}
	return f(ctx)
}
func (a *fixtureRenewalAuthority) Authorize(_ context.Context, _ pgx.Tx, k renewalChoiceKey, actor uuid.UUID) (renewalChoiceAuthority, error) {
	if k != a.key || actor != a.actor || a.revoked {
		return renewalChoiceAuthority{}, errRenewalConflict
	}
	return a.authority, nil
}
func (a *fixtureRenewalAuthority) Resolve(_ context.Context, _ pgx.Tx, _ renewalChoiceKey, choice string) (*renewalChoiceTerms, error) {
	if choice == "free" {
		return nil, nil
	}
	if choice == "monthly" && !a.monthly {
		return nil, errors.New("offer version unavailable")
	}
	months, amount := 12, int64(1200000)
	if choice == "monthly" {
		months, amount = 1, 120000
	}
	allowances := make([]int64, months)
	for i := range allowances {
		allowances[i] = 100000
	}
	return &renewalChoiceTerms{Offer: "pro_" + choice, Version: 1, RateCard: "payg", Price: "price_" + choice, Product: "prod_pro", Currency: "usd", Amount: amount, Months: months, Allowances: allowances}, nil
}
func (a *fixtureRenewalAuthority) DefaultProof(_ context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	return fixtureRenewalProof(k, op, a.now), nil
}
func fixtureRenewalProof(k renewalChoiceKey, op renewalChoiceOperation, now time.Time) renewalChoiceProof {
	timing := "future_configuration"
	if !now.Before(k.Boundary) {
		timing = "boundary_history"
	}
	return renewalChoiceProof{Operation: op.ID, Boundary: k.Boundary, BindingHash: renewalHash(op.Binding), TermsHash: renewalHash(op.Terms), Outcome: "confirmed", Timing: timing, VerifiedAt: now, Evidence: json.RawMessage(`{"fixture_verification":"exact_boundary"}`)}
}

type fixtureRenewalProvider struct {
	dispatch func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error)
	observe  func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error)
	writes   atomic.Int32
}

func (p *fixtureRenewalProvider) Dispatch(_ context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	p.writes.Add(1)
	return p.dispatch(k, op)
}
func (p *fixtureRenewalProvider) Observe(_ context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	return p.observe(k, op)
}

type fixtureRenewalSuccessor struct {
	calls  int
	state  string
	choice string
	id     uuid.UUID
}

func (p *fixtureRenewalSuccessor) Reconcile(_ context.Context, _ pgx.Tx, _ renewalChoiceKey, op renewalChoiceOperation, id uuid.UUID) (string, error) {
	p.calls++
	p.choice = op.Request.Choice
	if p.id != uuid.Nil && p.id != id {
		return "", errRenewalConflict
	}
	p.id = id
	return p.state, nil
}
func newRenewalFixture(t *testing.T) (*renewalChoiceService, *memoryRenewalStore, *fixtureRenewalAuthority) {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	key := renewalChoiceKey{Team: uuid.New(), Assignment: uuid.New(), Boundary: now.AddDate(0, 1, 0)}
	a := &fixtureRenewalAuthority{key: key, actor: uuid.New(), now: now, authority: renewalChoiceAuthority{Revision: 7, Acceptance: uuid.New(), Binding: renewalChoiceBinding{Contract: uuid.New(), ProviderBinding: uuid.New(), Merchant: "acct_fixture", Customer: "cus_fixture", Fee: "sub_fee", Usage: "sub_usage", Anchor: key.Boundary.AddDate(-1, 0, 0)}}}
	store := &memoryRenewalStore{now: now}
	s := &renewalChoiceService{Enabled: true, Store: store, Authority: a}
	if err := s.initialize(t.Context(), key, a.actor); err != nil {
		t.Fatal(err)
	}
	return s, store, a
}
func submitRenewal(t *testing.T, s *renewalChoiceService, a *fixtureRenewalAuthority, choice string) renewalChoiceJournal {
	t.Helper()
	j, err := s.status(t.Context(), a.key, a.actor)
	if err != nil {
		t.Fatal(err)
	}
	j, err = s.submit(t.Context(), a.key, a.actor, renewalChoiceRequest{ID: uuid.New(), Choice: choice, ApprovalRevision: a.authority.Revision, Acceptance: a.authority.Acceptance, ChoiceRevision: j.Revision})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestRenewalChoiceDefaultClosedAndCatalog(t *testing.T) {
	var empty renewalChoiceService
	if err := empty.initialize(t.Context(), renewalChoiceKey{}, uuid.New()); !errors.Is(err, errRenewalDisabled) {
		t.Fatal(err)
	}
	s, _, a := newRenewalFixture(t)
	if s.Provider != nil || s.Successors != nil {
		t.Fatal("fixture must start without provider or successor adapters")
	}
	j, _ := s.status(t.Context(), a.key, a.actor)
	if j.Confirmed.Request.Choice != "annual" || j.Requested != nil || j.SuccessorState != "scheduled" {
		t.Fatal(j)
	}
	_, err := s.submit(t.Context(), a.key, a.actor, renewalChoiceRequest{ID: uuid.New(), Choice: "monthly", ApprovalRevision: 7, Acceptance: a.authority.Acceptance, ChoiceRevision: j.Revision})
	if err == nil {
		t.Fatal("unpublished monthly accepted")
	}
	other := a.key
	other.Team = uuid.New()
	if _, err = s.status(t.Context(), other, a.actor); err == nil {
		t.Fatal("foreign tenant read accepted")
	}
	if _, err = s.status(t.Context(), a.key, uuid.New()); err == nil {
		t.Fatal("foreign actor accepted")
	}
	if err = s.reconcile(t.Context(), a.key); !errors.Is(err, errRenewalDisabled) {
		t.Fatal(err)
	}
}

func TestRenewalChoiceReplayAndConcurrentRevisions(t *testing.T) {
	s, _, a := newRenewalFixture(t)
	j := submitRenewal(t, s, a, "free")
	req := j.Requested.Request
	replay, err := s.submit(t.Context(), a.key, a.actor, req)
	if err != nil || replay.Revision != j.Revision || replay.Requested.ID != j.Requested.ID {
		t.Fatal(replay, err)
	}
	changed := req
	changed.Choice = "annual"
	if _, err = s.submit(t.Context(), a.key, a.actor, changed); !errors.Is(err, errRenewalConflict) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.submit(t.Context(), a.key, a.actor, renewalChoiceRequest{ID: uuid.New(), Choice: "annual", ApprovalRevision: 7, Acceptance: a.authority.Acceptance, ChoiceRevision: j.Revision})
			if e == nil {
				accepted.Add(1)
			} else if !errors.Is(e, errRenewalConflict) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("lost revision fence", accepted.Load())
	}
	a.authority.Revision++
	j, _ = s.status(t.Context(), a.key, a.actor)
	if err = s.reconcile(t.Context(), a.key); !errors.Is(err, errRenewalDisabled) {
		t.Fatal(err)
	}
	_, err = s.submit(t.Context(), a.key, a.actor, renewalChoiceRequest{ID: uuid.New(), Choice: "free", ApprovalRevision: 7, Acceptance: a.authority.Acceptance, ChoiceRevision: j.Revision})
	if !errors.Is(err, errRenewalConflict) {
		t.Fatal("stale authority", err)
	}
}

func TestRenewalChoiceUnknownPreservesConfirmedAndNeverRedispatches(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	j := submitRenewal(t, s, a, "free")
	p := &fixtureRenewalProvider{dispatch: func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
		return renewalChoiceProof{}, errors.New("response lost")
	}}
	p.observe = func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, store.now), nil
	}
	s.Provider = p
	if err := s.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	j, _ = s.status(t.Context(), a.key, a.actor)
	if j.Requested.State != "outcome_unknown" || j.Confirmed.Request.Choice != "annual" {
		t.Fatal(j)
	}
	_, err := s.submit(t.Context(), a.key, a.actor, renewalChoiceRequest{ID: uuid.New(), Choice: "annual", ApprovalRevision: 7, Acceptance: a.authority.Acceptance, ChoiceRevision: j.Revision})
	if !errors.Is(err, errRenewalPending) {
		t.Fatal(err)
	}
	// A later read-only history proof may recover the original write after B.
	store.now = a.key.Boundary.Add(time.Hour)
	if err = s.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	j, _ = s.status(t.Context(), a.key, a.actor)
	if j.Confirmed.Request.Choice != "free" || p.writes.Load() != 1 {
		t.Fatal(j, p.writes.Load())
	}
}

func TestRenewalChoiceLateAndMismatchedProofsRemainUnknown(t *testing.T) {
	for _, kind := range []string{"wrong_boundary", "wrong_terms", "wrong_binding", "future_get_after_boundary", "empty_evidence"} {
		t.Run(kind, func(t *testing.T) {
			s, store, a := newRenewalFixture(t)
			submitRenewal(t, s, a, "free")
			p := &fixtureRenewalProvider{dispatch: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
				proof := fixtureRenewalProof(k, op, store.now)
				switch kind {
				case "wrong_boundary":
					proof.Boundary = proof.Boundary.AddDate(0, 1, 0)
				case "wrong_terms":
					proof.TermsHash = "different"
				case "wrong_binding":
					proof.BindingHash = "different"
				case "empty_evidence":
					proof.Evidence = json.RawMessage(`{}`)
				case "future_get_after_boundary":
					store.now = k.Boundary.Add(time.Second)
				}
				return proof, nil
			}}
			s.Provider = p
			if err := s.reconcile(t.Context(), a.key); err != nil {
				t.Fatal(err)
			}
			j, _ := s.status(t.Context(), a.key, a.actor)
			if j.Requested.State != "outcome_unknown" || j.Confirmed.Request.Choice != "annual" {
				t.Fatal(j)
			}
		})
	}
}

func TestRenewalChoiceBoundaryAndRevocationPreventDispatch(t *testing.T) {
	for _, kind := range []string{"boundary", "revoked", "revision"} {
		t.Run(kind, func(t *testing.T) {
			s, store, a := newRenewalFixture(t)
			submitRenewal(t, s, a, "free")
			p := &fixtureRenewalProvider{dispatch: func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
				t.Fatal("forbidden dispatch")
				return renewalChoiceProof{}, nil
			}}
			s.Provider = p
			switch kind {
			case "boundary":
				store.now = a.key.Boundary
			case "revoked":
				a.revoked = true
			case "revision":
				a.authority.Revision++
			}
			err := s.reconcile(t.Context(), a.key)
			if kind != "boundary" && err == nil {
				t.Fatal("stale authority accepted")
			}
			if p.writes.Load() != 0 {
				t.Fatal("provider mutated")
			}
		})
	}
}

func TestRenewalChoiceConcurrentObservationCannotUndoConfirmation(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	submitRenewal(t, s, a, "free")
	entered, release := make(chan struct{}), make(chan struct{})
	p := &fixtureRenewalProvider{dispatch: func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
		close(entered)
		<-release
		return renewalChoiceProof{}, errors.New("late transport error")
	}, observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, store.now), nil
	}}
	s.Provider = p
	done := make(chan error, 1)
	go func() { done <- s.reconcile(t.Context(), a.key) }()
	<-entered
	if err := s.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	j, _ := s.status(t.Context(), a.key, a.actor)
	if j.Confirmed.Request.Choice != "free" || j.Requested.State != "confirmed" || p.writes.Load() != 1 {
		t.Fatal(j)
	}
}

func TestRenewalChoiceSuccessorUsesLastConfirmedAndPaymentGate(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	submitRenewal(t, s, a, "free")
	p := &fixtureRenewalProvider{dispatch: func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
		return renewalChoiceProof{}, errors.New("unknown")
	}}
	s.Provider = p
	if err := s.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	p.observe = func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, store.now), nil
	}
	successor := &fixtureRenewalSuccessor{state: "payment_pending"}
	s.Successors = successor
	if err := s.reconcileSuccessor(t.Context(), a.key); err != nil || successor.calls != 0 {
		t.Fatal(err, successor.calls)
	}
	store.now = a.key.Boundary
	for range 2 {
		if err := s.reconcileSuccessor(t.Context(), a.key); err != nil {
			t.Fatal(err)
		}
	}
	j, _ := s.status(t.Context(), a.key, a.actor)
	if j.SuccessorState != "payment_pending" || successor.choice != "annual" {
		t.Fatal(j, successor.choice)
	}
	successor.state = "active"
	if err := s.reconcileSuccessor(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	j, _ = s.status(t.Context(), a.key, a.actor)
	if j.SuccessorState != "active" {
		t.Fatal(j)
	}
	a.revoked = true
	before := successor.calls
	if err := s.reconcileSuccessor(t.Context(), a.key); err == nil || successor.calls != before {
		t.Fatal("revoked authority adopted")
	}
}

func TestRenewalChoiceBoundaryProofPreventsStaleFreeAdoption(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	p := &fixtureRenewalProvider{dispatch: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, store.now), nil
	}}
	s.Provider = p
	submitRenewal(t, s, a, "free")
	if err := s.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	a.monthly = true
	submitRenewal(t, s, a, "monthly")
	p.dispatch = func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
		return renewalChoiceProof{}, errors.New("response lost")
	}
	if err := s.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	store.now = a.key.Boundary.Add(time.Hour)
	// The saved Free instruction differs from actual provider boundary history.
	p.observe = func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
		return renewalChoiceProof{}, errors.New("boundary actually billed monthly")
	}
	successor := &fixtureRenewalSuccessor{state: "free"}
	s.Successors = successor
	if err := s.reconcileSuccessor(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	j, _ := s.status(t.Context(), a.key, a.actor)
	if successor.calls != 0 || j.SuccessorState != "review_required" || j.Confirmed.Request.Choice != "free" {
		t.Fatal(j, successor.calls)
	}
	// Recover the unknown operation, then adopt only its exact effective terms.
	p.observe = func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, store.now), nil
	}
	if err := s.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	successor.state = "payment_pending"
	if err := s.reconcileSuccessor(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	if successor.calls != 1 || successor.choice != "monthly" {
		t.Fatal(successor)
	}
}

func TestRenewalChoiceStaleBoundaryFailureCannotUndoActive(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	store.now = a.key.Boundary
	entered, release := make(chan struct{}), make(chan struct{})
	var observations atomic.Int32
	s.Provider = &fixtureRenewalProvider{observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		if observations.Add(1) == 1 {
			close(entered)
			<-release
			return renewalChoiceProof{}, errors.New("old observation failed")
		}
		return fixtureRenewalProof(k, op, store.now), nil
	}}
	s.Successors = &fixtureRenewalSuccessor{state: "active"}
	done := make(chan error, 1)
	go func() { done <- s.reconcileSuccessor(t.Context(), a.key) }()
	<-entered
	if err := s.reconcileSuccessor(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, errRenewalConflict) {
		t.Fatal(err)
	}
	j, _ := s.status(t.Context(), a.key, a.actor)
	if j.SuccessorState != "active" {
		t.Fatal(j)
	}
}

func TestRenewalChoiceCustomerProjectionPreservesPinnedTermsAndHidesEvidence(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	s.Provider = &fixtureRenewalProvider{}
	a.monthly = true
	before := submitRenewal(t, s, a, "monthly")
	view, err := s.view(t.Context(), a.key, a.actor)
	if err != nil {
		t.Fatal(err)
	}
	if view.Requested.Choice != "monthly" || view.Confirmed.Choice != "annual" || view.Requested.Terms.Amount != 120000 || view.Confirmed.Terms.Amount != 1200000 {
		t.Fatal(view)
	}
	raw, _ := json.Marshal(view)
	for _, private := range []string{"cus_fixture", "sub_fee", "acct_fixture", "fixture_verification", "actor_id", "price_monthly"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("private provider field in projection: %s", private)
		}
	}
	if before.Requested.Terms.Price != "price_monthly" {
		t.Fatal("saved execution mapping lost")
	}
	store.now = a.key.Boundary
	view, err = s.view(t.Context(), a.key, a.actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, option := range view.Options {
		if option.Available || option.UnavailableReason != "boundary_passed" {
			t.Fatal(option)
		}
	}
}

func TestRenewalChoiceNoEffectObservationCannotReleaseInflightFence(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	submitRenewal(t, s, a, "free")
	entered, release := make(chan struct{}), make(chan struct{})
	s.Provider = &fixtureRenewalProvider{dispatch: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		close(entered)
		<-release
		return fixtureRenewalProof(k, op, store.now), nil
	}, observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		p := fixtureRenewalProof(k, op, store.now)
		p.Outcome = "no_effect"
		return p, nil
	}}
	done := make(chan error, 1)
	go func() { done <- s.reconcile(t.Context(), a.key) }()
	<-entered
	if err := s.reconcile(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	j, _ := s.status(t.Context(), a.key, a.actor)
	if j.Requested.State != "outcome_unknown" {
		t.Fatal(j)
	}
	_, err := s.submit(t.Context(), a.key, a.actor, renewalChoiceRequest{ID: uuid.New(), Choice: "annual", Acceptance: a.authority.Acceptance, ApprovalRevision: 7, ChoiceRevision: j.Revision})
	if !errors.Is(err, errRenewalPending) {
		t.Fatal(err)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	j, _ = s.status(t.Context(), a.key, a.actor)
	if j.Confirmed.Request.Choice != "free" {
		t.Fatal(j)
	}
}

func TestRenewalChoiceLaterReadFailurePreservesCompletedSuccessor(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	store.now = a.key.Boundary
	s.Provider = &fixtureRenewalProvider{observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, store.now), nil
	}}
	s.Successors = &fixtureRenewalSuccessor{state: "active"}
	if err := s.reconcileSuccessor(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	s.Provider = &fixtureRenewalProvider{observe: func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
		return renewalChoiceProof{}, errors.New("temporary unavailable")
	}}
	if err := s.reconcileSuccessor(t.Context(), a.key); !errors.Is(err, errRenewalPending) {
		t.Fatal(err)
	}
	j, _ := s.status(t.Context(), a.key, a.actor)
	if j.SuccessorState != "active" {
		t.Fatal(j)
	}
}

func TestRenewalChoiceRejectsPreBoundaryHistoryTimestamp(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	store.now = a.key.Boundary.Add(time.Hour)
	s.Provider = &fixtureRenewalProvider{observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		p := fixtureRenewalProof(k, op, store.now)
		p.VerifiedAt = k.Boundary.Add(-time.Second)
		return p, nil
	}}
	successor := &fixtureRenewalSuccessor{state: "active"}
	s.Successors = successor
	if err := s.reconcileSuccessor(t.Context(), a.key); err != nil {
		t.Fatal(err)
	}
	if successor.calls != 0 {
		t.Fatal("pre-boundary proof adopted")
	}
}

type renewalGuardContextKey struct{}
type fixtureContextAuthority struct{ *fixtureRenewalAuthority }

func (a fixtureContextAuthority) Admit(ctx context.Context, k renewalChoiceKey, actor uuid.UUID, f func(context.Context) error) error {
	return a.fixtureRenewalAuthority.Admit(ctx, k, actor, func(ctx context.Context) error {
		guarded, cancel := context.WithCancel(context.WithValue(ctx, renewalGuardContextKey{}, true))
		defer cancel()
		return f(guarded)
	})
}
func (a fixtureContextAuthority) Authorize(ctx context.Context, tx pgx.Tx, k renewalChoiceKey, actor uuid.UUID) (renewalChoiceAuthority, error) {
	if ctx.Value(renewalGuardContextKey{}) != true {
		return renewalChoiceAuthority{}, errors.New("guard context lost")
	}
	return a.fixtureRenewalAuthority.Authorize(ctx, tx, k, actor)
}

type fixtureContextProvider struct{ *fixtureRenewalProvider }

func (p fixtureContextProvider) Dispatch(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	if ctx.Value(renewalGuardContextKey{}) != true {
		return renewalChoiceProof{}, errors.New("dispatch context lost")
	}
	return p.fixtureRenewalProvider.Dispatch(ctx, k, op)
}

type fixtureContextSteps struct{ *fixtureRenewalSteps }

func (p fixtureContextSteps) DispatchStep(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, r renewalChoiceStepRequest) (renewalChoiceStepProof, error) {
	if ctx.Value(renewalGuardContextKey{}) != true {
		return renewalChoiceStepProof{}, errors.New("stage context lost")
	}
	return p.fixtureRenewalSteps.DispatchStep(ctx, k, op, r)
}
func TestRenewalChoiceCarriesGuardContext(t *testing.T) {
	for _, staged := range []bool{false, true} {
		t.Run(fmt.Sprint(staged), func(t *testing.T) {
			s, store, a := newRenewalFixture(t)
			s.Authority = fixtureContextAuthority{a}
			submitRenewal(t, s, a, "free")
			iterations := 1
			if staged {
				s.Provider = fixtureContextSteps{&fixtureRenewalSteps{fixtureRenewalProvider: &fixtureRenewalProvider{}, now: func() renewalChoiceProof { return renewalChoiceProof{VerifiedAt: store.now} }}}
				iterations = 4
			} else {
				s.Provider = fixtureContextProvider{&fixtureRenewalProvider{dispatch: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
					return fixtureRenewalProof(k, op, store.now), nil
				}}}
			}
			for range iterations {
				if err := s.reconcile(t.Context(), a.key); err != nil {
					t.Fatal(err)
				}
			}
			j, err := s.status(t.Context(), a.key, a.actor)
			if err != nil || j.Confirmed.Request.Choice != "free" {
				t.Fatal("guard context not carried through confirmation", err, j)
			}
		})
	}
}

type fixtureCancelStore struct {
	*memoryRenewalStore
	cancel      context.CancelFunc
	afterMarker bool
}

func (s *fixtureCancelStore) Transact(ctx context.Context, k renewalChoiceKey, f func(renewalChoiceTransaction) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	marked := false
	err := s.memoryRenewalStore.Transact(ctx, k, func(tx renewalChoiceTransaction) error {
		if err := f(tx); err != nil {
			return err
		}
		marked = tx.Journal().Requested != nil && tx.Journal().Requested.State == "dispatched"
		return ctx.Err()
	})
	if err == nil && marked && s.afterMarker && s.cancel != nil {
		s.afterMarker = false
		s.cancel()
	}
	return err
}

type fixtureCancelAuthority struct {
	*fixtureRenewalAuthority
	store         *fixtureCancelStore
	beforeMarker  bool
	afterProvider bool
}

func (a *fixtureCancelAuthority) Admit(ctx context.Context, k renewalChoiceKey, actor uuid.UUID, f func(context.Context) error) error {
	return a.fixtureRenewalAuthority.Admit(ctx, k, actor, func(ctx context.Context) error {
		guarded, cancel := context.WithCancel(ctx)
		defer cancel()
		a.store.cancel = cancel
		if a.beforeMarker {
			cancel()
		}
		if err := f(guarded); err != nil {
			return err
		}

		return guarded.Err()
	})
}

type fixtureCancelProvider struct {
	*fixtureRenewalProvider
	accepted atomic.Int32
}

func (p *fixtureCancelProvider) Dispatch(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	if err := ctx.Err(); err != nil {
		return renewalChoiceProof{}, err
	}
	p.accepted.Add(1)
	return p.fixtureRenewalProvider.Dispatch(ctx, k, op)
}
func TestRenewalChoiceGuardCancellationRecovery(t *testing.T) {
	for _, timing := range []string{"before_marker", "after_marker", "after_provider"} {
		t.Run(timing, func(t *testing.T) {
			s, memory, a := newRenewalFixture(t)
			original := submitRenewal(t, s, a, "free")
			store := &fixtureCancelStore{memoryRenewalStore: memory, afterMarker: timing == "after_marker"}
			authority := &fixtureCancelAuthority{fixtureRenewalAuthority: a, store: store, beforeMarker: timing == "before_marker", afterProvider: timing == "after_provider"}
			provider := &fixtureCancelProvider{fixtureRenewalProvider: &fixtureRenewalProvider{dispatch: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
				return fixtureRenewalProof(k, op, memory.now), nil
			}, observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
				p := fixtureRenewalProof(k, op, memory.now)
				if timing == "after_marker" {
					p.Outcome = "no_effect"
				}
				return p, nil
			}}}
			s.Store = store
			s.Authority = authority
			s.Provider = provider
			if err := s.reconcile(t.Context(), a.key); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			s.Authority = a
			j, err := s.status(t.Context(), a.key, a.actor)
			if err != nil {
				t.Fatal(err)
			}
			if j.Requested.ID != original.Requested.ID || j.Confirmed.Request.Choice != "annual" {
				t.Fatal("cancellation changed identity or confirmed choice", j)
			}
			if timing == "before_marker" {
				if j.Requested.State != "prepared" || provider.accepted.Load() != 0 {
					t.Fatal(j)
				}
				return
			}
			if j.Requested.State != "dispatched" && j.Requested.State != "outcome_unknown" {
				t.Fatal("lost guard became definitive outcome", j)
			}
			before := provider.accepted.Load()
			restart := *s
			if err := restart.reconcile(t.Context(), a.key); err != nil {
				t.Fatal(err)
			}
			j, _ = s.status(t.Context(), a.key, a.actor)
			if provider.accepted.Load() != before || j.Requested.ID != original.Requested.ID {
				t.Fatal("restart rewrote operation")
			}
			if timing == "after_provider" && j.Confirmed.Request.Choice != "free" {
				t.Fatal("accepted outcome not recovered", j)
			}
			if timing == "after_marker" && j.Requested.State != "outcome_unknown" {
				t.Fatal("absence released canceled intent", j)
			}
		})
	}
}

func (a *fixtureRenewalAuthority) DispatchGuard(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, f func(context.Context) error) error {
	if op.Request.Acceptance != a.authority.Acceptance || op.Request.ApprovalRevision != a.authority.Revision || renewalHash(op.Binding) != renewalHash(a.authority.Binding) {
		return errRenewalConflict
	}
	return a.Admit(ctx, k, op.Actor, f)
}
func (a fixtureContextAuthority) DispatchGuard(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, f func(context.Context) error) error {
	return a.Admit(ctx, k, op.Actor, f)
}
func (a *fixtureCancelAuthority) DispatchGuard(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, f func(context.Context) error) error {
	return a.fixtureRenewalAuthority.DispatchGuard(ctx, k, op, func(ctx context.Context) error {
		guarded, cancel := context.WithCancel(ctx)
		defer cancel()
		if err := f(guarded); err != nil {
			return err
		}
		if a.afterProvider {
			cancel()
		}
		return guarded.Err()
	})
}

func TestRenewalChoiceMonthlyCalendarAdmissionMatchesDispatch(t *testing.T) {
	s, store, a := newRenewalFixture(t)
	a.monthly = true
	a.authority.Binding.Anchor = time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)
	a.key.Boundary = annualBoundary(a.authority.Binding.Anchor, 12)
	store.now = a.key.Boundary.Add(-time.Hour)
	a.now = store.now
	if err := s.initialize(t.Context(), a.key, a.actor); err != nil {
		t.Fatal(err)
	}
	provider := &fixtureRenewalProvider{}
	s.Provider = provider
	before, err := s.status(t.Context(), a.key, a.actor)
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.view(t.Context(), a.key, a.actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, option := range view.Options {
		if option.Choice == "monthly" {
			if option.Available || option.UnavailableReason != "integration_unavailable" {
				t.Fatal(option)
			}
		} else if !option.Available {
			t.Fatal("unrelated option blocked", option)
		}
	}
	req := renewalChoiceRequest{ID: uuid.New(), Choice: "monthly", ApprovalRevision: a.authority.Revision, Acceptance: a.authority.Acceptance, ChoiceRevision: before.Revision}
	if _, err := s.submit(t.Context(), a.key, a.actor, req); !errors.Is(err, errRenewalDisabled) {
		t.Fatal(err)
	}
	after, err := s.status(t.Context(), a.key, a.actor)
	if err != nil || after.Revision != before.Revision || after.Requested != nil || after.Confirmed.Request.Choice != "annual" || provider.writes.Load() != 0 {
		t.Fatal("unsupported choice changed journal", after, err)
	}
	if _, ok := store.requests[req.ID]; ok {
		t.Fatal("rejected request persisted")
	}
}

type observingRenewalDefault struct {
	*fixtureRenewalAuthority
	observe func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error)
}

func (a *observingRenewalDefault) DefaultProof(_ context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	return a.observe(k, op)
}
func TestRenewalChoiceDefaultObservationReleasesTransactionAndRechecksAuthority(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprint(revoke), func(t *testing.T) {
			_, _, a := newRenewalFixture(t)
			store := &memoryRenewalStore{now: a.now}
			authority := &observingRenewalDefault{fixtureRenewalAuthority: a}
			authority.observe = func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
				if !store.mu.TryLock() {
					t.Fatal("provider observation retained regional transaction")
				}
				store.mu.Unlock()
				a.revoked = revoke
				return fixtureRenewalProof(k, op, store.now), nil
			}
			s := &renewalChoiceService{Enabled: true, Store: store, Authority: authority}
			err := s.initialize(t.Context(), a.key, a.actor)
			if revoke {
				if err == nil || len(store.requests) != 0 || store.journals[a.key].Confirmed != nil {
					t.Fatal("revoked observation became confirmed", err)
				}
			} else if err != nil || store.journals[a.key].Confirmed == nil || len(store.requests) != 1 {
				t.Fatal("valid observation did not initialize", err)
			}
		})
	}
}
