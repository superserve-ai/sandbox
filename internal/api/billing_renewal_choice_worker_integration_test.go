//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRenewalChoiceWorkerPagesPastFailedAndInactiveRows(t *testing.T) {
	s, a, pool := newRenewalPostgresFixture(t)
	j := submitRenewal(t, s, a, "free")
	p := &fixtureRenewalProvider{dispatch: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, a.now), nil
	}, observe: func(renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
		t.Fatal("confirmed operation was observed again by dispatch worker")
		return renewalChoiceProof{}, nil
	}}
	s.Provider = p
	insert := func(journal renewalChoiceJournal) {
		t.Helper()
		raw, err := json.Marshal(journal)
		if err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(t.Context(), `INSERT INTO billing_renewal_choice(team_id,assignment_id,intended_boundary,revision,snapshot) VALUES($1,$2,$3,$4,$5)`, journal.Key.Team, journal.Key.Assignment, journal.Key.Boundary, journal.Revision, raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	// A prepared operation with different assignment authority always fails.
	// Its presence must not keep later keys from being visited on the next page.
	other := j
	other.Key.Assignment = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	insert(other)
	for range renewalChoicePageSize {
		inactive := j
		inactive.Key.Assignment = uuid.New()
		inactive.Requested = nil
		inactive.SuccessorState = "active"
		insert(inactive)
	}
	due := j
	due.Key.Assignment = uuid.New()
	due.Key.Boundary = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	due.Requested = nil
	due.SuccessorState = "scheduled"
	insert(due)
	w := &renewalChoiceWorker{Pool: pool, Service: s}
	page, err := w.page(t.Context())
	if err != nil || len(page) != renewalChoicePageSize {
		t.Fatal("unbounded or missing first page", len(page), err)
	}
	failures := 0
	for range 3 {
		_, failed, err := w.tick(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		failures += failed
	}
	if failures == 0 || w.cursor != nil || p.writes.Load() != 1 {
		t.Fatal("failed work starved progress or end-of-scan did not wrap", failures, w.cursor, p.writes.Load())
	}
	confirmed, err := s.status(t.Context(), a.key, a.actor)
	if err != nil || confirmed.Confirmed.Request.Choice != "free" {
		t.Fatal(confirmed, err)
	}
	var state string
	if err = pool.QueryRow(t.Context(), `SELECT snapshot->>'successor_state' FROM billing_renewal_choice WHERE team_id=$1 AND assignment_id=$2 AND intended_boundary=$3`, due.Key.Team, due.Key.Assignment, due.Key.Boundary).Scan(&state); err != nil || state != "scheduled" {
		t.Fatal("absent benefit port changed successor state", state, err)
	}
	// A fresh scanner may revisit the same journal, but the durable generation
	// fence must prevent another write after the operation was confirmed.
	w.cursor = nil
	if _, _, err = w.tick(t.Context()); err != nil || p.writes.Load() != 1 {
		t.Fatal("restart duplicated provider dispatch", p.writes.Load(), err)
	}
}

func TestRenewalChoiceWorkerCancellationRetainsIncompleteRow(t *testing.T) {
	s, a, pool := newRenewalPostgresFixture(t)
	submitRenewal(t, s, a, "free")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p := &fixtureRenewalProvider{dispatch: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		cancel()
		return fixtureRenewalProof(k, op, a.now), nil
	}, observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, a.now), nil
	}}
	s.Provider = p
	w := &renewalChoiceWorker{Pool: pool, Service: s}
	if _, _, err := w.tick(ctx); !errors.Is(err, context.Canceled) || w.cursor != nil {
		t.Fatal("expired tick advanced past incomplete work", err, w.cursor)
	}
	if _, _, err := w.tick(t.Context()); err != nil || p.writes.Load() != 1 {
		t.Fatal("resume failed or repeated provider write", err, p.writes.Load())
	}
	j, err := s.status(t.Context(), a.key, a.actor)
	if err != nil || j.Confirmed.Request.Choice != "free" {
		t.Fatal(j, err)
	}
}

func TestRenewalChoiceWorkerRecoversConfirmedSuccessorDespitePendingFailure(t *testing.T) {
	s, a, pool := newRenewalPostgresFixture(t)
	j := submitRenewal(t, s, a, "free")
	a.key.Boundary = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	j.Key = a.key
	j.Requested.Actor = uuid.New() // This pending actor no longer has authority.
	j.SuccessorState = "review_required"
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO billing_renewal_choice(team_id,assignment_id,intended_boundary,revision,snapshot) VALUES($1,$2,$3,$4,$5)`, j.Key.Team, j.Key.Assignment, j.Key.Boundary, j.Revision, raw); err != nil {
		t.Fatal(err)
	}
	s.Provider = &fixtureRenewalProvider{observe: func(k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
		return fixtureRenewalProof(k, op, a.now), nil
	}}
	successors := &fixtureRenewalSuccessor{state: "active"}
	s.Successors = successors
	w := &renewalChoiceWorker{Pool: pool, Service: s}
	_, failed, err := w.tick(t.Context())
	if err != nil || failed == 0 || successors.calls != 1 || successors.choice != "annual" {
		t.Fatal("pending actor failure prevented confirmed recovery", failed, successors, err)
	}
	got, err := s.status(t.Context(), a.key, a.actor)
	if err != nil || got.SuccessorState != "active" || got.Confirmed.Request.Choice != "annual" {
		t.Fatal(got, err)
	}
}
