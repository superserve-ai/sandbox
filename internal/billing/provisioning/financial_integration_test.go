//go:build integration

package provisioning

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func financialTestAuthorization(f *fixture) FinancialAuthorization {
	return FinancialAuthorization{ID: uuid.New(), Target: InitialFinancialTarget(f.team, f.assignment), OperationID: f.id, AcceptanceID: f.a.offer.AcceptanceID, ApprovalRevision: 1, HomeRegion: "use", TermsDigest: strings.Repeat("a", 64), TargetTermsDigest: strings.Repeat("a", 64)}
}

func financialTestTx(ctx context.Context, f *fixture, fn func(pgx.Tx) error) error {
	tx, err := f.s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func TestFinancialFenceBeforeOperationBlocksDelayedAdmission(t *testing.T) {
	f := newFixture(t)
	target := InitialFinancialTarget(f.team, uuid.New())
	invalidation := uuid.New()
	if err := financialTestTx(t.Context(), f, func(tx pgx.Tx) error { return RevokeFinancialTarget(t.Context(), tx, target, invalidation, nil) }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Enqueue(t.Context(), target.TeamID, target.AssignmentID); !errors.Is(err, ErrRevoked) {
		t.Fatalf("delayed admission escaped fence: %v", err)
	}
	receipt, err := LoadFinancialRevocationReceipt(t.Context(), f.s.Pool, target, invalidation)
	if err != nil || receipt.FenceID == uuid.Nil || receipt.AcknowledgementID == uuid.Nil {
		t.Fatalf("durable acknowledgement unavailable: %#v %v", receipt, err)
	}
	if err = financialTestTx(t.Context(), f, func(tx pgx.Tx) error { return RevokeFinancialTarget(t.Context(), tx, target, invalidation, nil) }); err != nil {
		t.Fatal(err)
	}
	replay, err := LoadFinancialRevocationReceipt(t.Context(), f.s.Pool, target, invalidation)
	if err != nil || replay != receipt {
		t.Fatal("lost revocation response did not recover same receipt")
	}
	a := financialTestAuthorization(f)
	a.Target = target
	if err = financialTestTx(t.Context(), f, func(tx pgx.Tx) error {
		return FinalizeFinancialAuthorization(t.Context(), tx, a, func(context.Context, pgx.Tx) error { t.Fatal("late finalizer ran"); return nil })
	}); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
}

func TestFinancialFenceFinalizationReplayRevocationAndPhaseIsolation(t *testing.T) {
	f := newFixture(t)
	a := financialTestAuthorization(f)
	materialize := func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO test_finalization(id) VALUES($1)`, a.OperationID)
		return e
	}
	finalize := func() error {
		return financialTestTx(t.Context(), f, func(tx pgx.Tx) error { return FinalizeFinancialAuthorization(t.Context(), tx, a, materialize) })
	}
	if err := finalize(); err != nil {
		t.Fatal(err)
	}
	// Retrying after an intentionally ignored commit result cannot duplicate effects.
	if err := finalize(); err != nil {
		t.Fatal(err)
	}
	changed := a
	changed.ID = uuid.New()
	if err := financialTestTx(t.Context(), f, func(tx pgx.Tx) error { return FinalizeFinancialAuthorization(t.Context(), tx, changed, materialize) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed authorization adopted: %v", err)
	}
	successor := a
	successor.Target.Phase = "successor"
	successor.OperationID = uuid.New()
	successor.Target.TargetID = successor.OperationID
	successor.Boundary = time.Now().UTC().Truncate(time.Second)
	if err := financialTestTx(t.Context(), f, func(tx pgx.Tx) error {
		return FinalizeFinancialAuthorization(t.Context(), tx, successor, func(context.Context, pgx.Tx) error { t.Fatal("initial auth reused for successor"); return nil })
	}); err == nil {
		t.Fatal("same shared receipt reused across phases")
	}
	invalidation := uuid.New()
	if err := financialTestTx(t.Context(), f, func(tx pgx.Tx) error { return RevokeFinancialTarget(t.Context(), tx, a.Target, invalidation, nil) }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("finalized authority was acknowledged without commercial revoke")
	}
	if _, err := LoadFinancialRevocationReceipt(t.Context(), f.s.Pool, a.Target, invalidation); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("failed revocation exposed ack")
	}
	revoke := func(ctx context.Context, tx pgx.Tx, got FinancialAuthorization) error {
		if got != a {
			t.Fatal("wrong finalized authority")
		}
		_, e := tx.Exec(ctx, `DELETE FROM test_finalization WHERE id=$1`, a.OperationID)
		return e
	}
	if err := financialTestTx(t.Context(), f, func(tx pgx.Tx) error { return RevokeFinancialTarget(t.Context(), tx, a.Target, invalidation, revoke) }); err != nil {
		t.Fatal(err)
	}
	if err := finalize(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("late finalizer reopened authority: %v", err)
	}
	status, err := f.s.Status(t.Context(), f.team, f.assignment)
	if err != nil || status.Ready || status.State != "revoked" {
		t.Fatalf("financial tombstone ignored by status: %#v %v", status, err)
	}
}

func TestFinancialFenceFailedMaterializationRollsBackAuthority(t *testing.T) {
	f := newFixture(t)
	a := financialTestAuthorization(f)
	err := financialTestTx(t.Context(), f, func(tx pgx.Tx) error {
		return FinalizeFinancialAuthorization(t.Context(), tx, a, func(ctx context.Context, tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `INSERT INTO test_finalization(id) VALUES($1)`, a.OperationID); e != nil {
				return e
			}
			return ErrUnknown
		})
	})
	if !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	var effects int
	var finalized bool
	if err = f.s.Pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM test_finalization),EXISTS(SELECT 1 FROM billing_offer_financial_fence WHERE finalized_at IS NOT NULL OR authorization_receipt IS NOT NULL)`).Scan(&effects, &finalized); err != nil || effects != 0 || finalized {
		t.Fatalf("partial financial commit: %d %v %v", effects, finalized, err)
	}
}

func TestFinancialFenceSerializesConcurrentFinalizationAndRevocation(t *testing.T) {
	for _, first := range []string{"finalize", "revoke"} {
		t.Run(first, func(t *testing.T) {
			f := newFixture(t)
			a := financialTestAuthorization(f)
			invalidation := uuid.New()
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			work := func(kind string) error {
				return financialTestTx(t.Context(), f, func(tx pgx.Tx) error {
					if _, err := lockFinancialTarget(t.Context(), tx, a.Target); err != nil {
						return err
					}
					if kind == first {
						once.Do(func() { close(entered) })
						<-release
					}
					if kind == "finalize" {
						return FinalizeFinancialAuthorization(t.Context(), tx, a, func(ctx context.Context, tx pgx.Tx) error {
							_, e := tx.Exec(ctx, `INSERT INTO test_finalization(id) VALUES($1)`, a.OperationID)
							return e
						})
					}
					return RevokeFinancialTarget(t.Context(), tx, a.Target, invalidation, func(ctx context.Context, tx pgx.Tx, _ FinancialAuthorization) error {
						_, e := tx.Exec(ctx, `DELETE FROM test_finalization WHERE id=$1`, a.OperationID)
						return e
					})
				})
			}
			one := make(chan error, 1)
			go func() { one <- work(first) }()
			<-entered
			other := "finalize"
			if first == "finalize" {
				other = "revoke"
			}
			two := make(chan error, 1)
			go func() { two <- work(other) }()
			close(release)
			if err := <-one; err != nil {
				t.Fatal(err)
			}
			err := <-two
			if first == "revoke" {
				if !errors.Is(err, ErrRevoked) {
					t.Fatalf("late materialization: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			var count int
			if err = f.s.Pool.QueryRow(t.Context(), `SELECT count(*) FROM test_finalization`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("effective revoke retained eligibility: %d %v", count, err)
			}
			if _, err = LoadFinancialRevocationReceipt(t.Context(), f.s.Pool, a.Target, invalidation); err != nil {
				t.Fatal(err)
			}
		})
	}
}
