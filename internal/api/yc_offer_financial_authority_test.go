package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func financialFixture(t *testing.T) (*YCOfferAcceptanceService, YCAcceptanceRecord) {
	t.Helper()
	s, _, r, _, _ := acceptanceFixture(t)
	ctx := context.Background()
	if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}
func financialParams(r YCAcceptanceRecord) map[string]any {
	p := ycAcceptanceParameters(r)
	p["phase"] = "initial"
	p["operation_id"] = *r.OperationID
	p["target_terms_digest"] = r.TermsDigest
	return p
}
func requireFinancialState(t *testing.T, s *YCOfferAcceptanceService, r YCAcceptanceRecord, state string, pending int) {
	t.Helper()
	v, e := s.FinancialState(context.Background(), r.ClaimID)
	if e != nil || v == nil || v.State != state || v.PendingInvalidations != pending {
		t.Fatalf("financial state %+v: %v; want %s/%d", v, e, state, pending)
	}
}
func TestYCFinancialExactReceiptAndRevocation(t *testing.T) {
	s, r := financialFixture(t)
	ctx := context.Background()
	first, err := s.IssueFinancialAuthorization(ctx, r, "initial", *r.OperationID, r.TermsDigest)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.IssueFinancialAuthorization(ctx, r, "initial", *r.OperationID, r.TermsDigest)
	if err != nil || first.AuthorizationID != replay.AuthorizationID || !first.AuthorizedAt.Equal(replay.AuthorizedAt) {
		t.Fatal("unstable replay", err)
	}
	if _, err = s.IssueFinancialAuthorization(ctx, r, "initial", uuid.New(), r.TermsDigest); err == nil {
		t.Fatal("second initial allowed")
	}
	if _, err = s.IssueFinancialAuthorization(ctx, r, "successor", *r.OperationID, r.RenewalTermsDigest); err == nil {
		t.Fatal("phase reused operation")
	}
	successor := uuid.New()
	if _, err = s.IssueFinancialAuthorization(ctx, r, "successor", successor, r.RenewalTermsDigest); err != nil {
		t.Fatal(err)
	}
	requireFinancialState(t, s, r, "valid", 0)
	if _, err = s.Shared.Exec(ctx, `UPDATE public.yc_claim SET revision=revision+1,billing_state='activation_pending' WHERE id=$1`, r.ClaimID); err != nil {
		t.Fatal(err)
	}
	requireFinancialState(t, s, r, "valid", 0)
	if _, err = s.Shared.Exec(ctx, `UPDATE auth.users SET email_confirmed_at=NULL WHERE id=$1`, r.UserID); err != nil {
		t.Fatal(err)
	}
	requireFinancialState(t, s, r, "revocation_pending", 2)
	if _, err = s.IssueFinancialAuthorization(ctx, r, "initial", *r.OperationID, r.TermsDigest); err == nil {
		t.Fatal("invalid receipt reissued")
	}
	historical, err := s.ReadFinancialAuthorization(ctx, r.ID, "initial", *r.OperationID)
	if err != nil || historical.InvalidatedAt == nil || historical.AuthorizationID != first.AuthorizationID {
		t.Fatal("lost historical receipt", err)
	}
	lease := uuid.New()
	deliveries, err := s.LeaseFinancialInvalidations(ctx, lease, 25)
	if err != nil || len(deliveries) != 2 {
		t.Fatal(deliveries, err)
	}
	for _, d := range deliveries {
		stale := d
		stale.LeaseID = uuid.New()
		if err = s.AcknowledgeFinancialInvalidation(ctx, stale, uuid.New(), uuid.New()); err == nil {
			t.Fatal("stale lease acknowledged")
		}
		wrong := d
		wrong.HomeRegion = "usw"
		if err = s.AcknowledgeFinancialInvalidation(ctx, wrong, uuid.New(), uuid.New()); err == nil {
			t.Fatal("wrong region acknowledged")
		}
		ack, fence := uuid.New(), uuid.New()
		if err = s.AcknowledgeFinancialInvalidation(ctx, d, ack, fence); err != nil {
			t.Fatal(err)
		}
		if err = s.AcknowledgeFinancialInvalidation(ctx, d, ack, fence); err != nil {
			t.Fatal("ack replay", err)
		}
		if err = s.AcknowledgeFinancialInvalidation(ctx, d, ack, uuid.New()); err == nil {
			t.Fatal("changed fence replay")
		}
	}
	requireFinancialState(t, s, r, "revoked", 0)
	if _, err = s.Shared.Exec(ctx, `UPDATE auth.users SET email_confirmed_at=clock_timestamp(),created_at=created_at+interval '1 microsecond' WHERE id=$1`, r.UserID); err != nil {
		t.Fatal(err)
	}
	requireFinancialState(t, s, r, "revoked", 0)
	deliveries, err = s.LeaseFinancialInvalidations(ctx, uuid.New(), 25)
	if err != nil || len(deliveries) != 0 {
		t.Fatal("acknowledged target requeued", err)
	}
}
func TestYCFinancialPendingAndZeroPermitInvalidity(t *testing.T) {
	s, _, r, _, _ := acceptanceFixture(t)
	ctx := context.Background()
	requireFinancialState(t, s, r, "acceptance_pending", 0)
	if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); err != nil {
		t.Fatal(err)
	}
	status, err := s.Status(ctx, r.UserID, r.TeamID, r.ClaimID)
	if err != nil || status.Ready || status.FinancialAuthority == nil || status.FinancialAuthority.State != "acceptance_pending" {
		t.Fatal("confirming became legacy/ready", status, err)
	}
	if _, err = s.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Shared.Exec(ctx, `UPDATE public.yc_claim SET lifecycle_changed=true WHERE id=$1`, r.ClaimID); err != nil {
		t.Fatal(err)
	}
	requireFinancialState(t, s, r, "revoked", 0)
	status, err = s.Status(ctx, r.UserID, r.TeamID, r.ClaimID)
	if err != nil || status.Ready || status.FinancialAuthority.State != "revoked" {
		t.Fatal("revoked status lost", err)
	}
}
func waitFinancialLock(t *testing.T, s *YCOfferAcceptanceService, pid uint32) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := s.Shared.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("transaction never reached the expected lock wait")
}
func TestYCFinancialConcurrentIssueInvalidation(t *testing.T) {
	for _, isolation := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead, pgx.Serializable} {
		for _, existing := range []bool{false, true} {
			t.Run(string(isolation)+map[bool]string{false: "/first-key", true: "/existing-key"}[existing], func(t *testing.T) {
				s, r := financialFixture(t)
				ctx := context.Background()
				if existing {
					if _, err := s.Shared.Exec(ctx, `SELECT public.yc_financial_touch('user/'||$1::text)`, r.UserID.String()); err != nil {
						t.Fatal(err)
					}
				}
				invalidator, err := s.Shared.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
				if err != nil {
					t.Fatal(err)
				}
				defer invalidator.Rollback(ctx)
				var n int
				if err = invalidator.QueryRow(ctx, `SELECT count(*) FROM public.yc_financial_authorization`).Scan(&n); err != nil {
					t.Fatal(err)
				} // establish old snapshot
				issuer, err := s.Shared.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer issuer.Rollback(ctx)
				var receipt YCFinancialAuthorization
				if err = ycFinancialRPC(ctx, issuer, "issue", func() map[string]any {
					p := financialParams(r)
					p["user_id"] = strings.ToUpper(r.UserID.String())
					return p
				}(), &receipt); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					_, e := invalidator.Exec(ctx, `UPDATE auth.users SET email_confirmed_at=NULL WHERE id=$1`, r.UserID)
					done <- e
				}()
				waitFinancialLock(t, s, invalidator.Conn().PgConn().PID())
				if err = issuer.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				err = <-done
				if isolation == pgx.ReadCommitted {
					if err != nil {
						t.Fatal(err)
					}
					if err = invalidator.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					requireFinancialState(t, s, r, "revocation_pending", 1)
				} else {
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != "40001" {
						t.Fatalf("stale snapshot did not serialize-fail: %v", err)
					}
					_ = invalidator.Rollback(ctx)
					if _, err = s.Shared.Exec(ctx, `UPDATE auth.users SET email_confirmed_at=NULL WHERE id=$1`, r.UserID); err != nil {
						t.Fatal(err)
					}
					requireFinancialState(t, s, r, "revocation_pending", 1)
				}
			})
		}
	}
}
func TestYCFinancialInvalidationFirstAndUnrelatedIsolation(t *testing.T) {
	for _, writer := range []string{"claim", "company", "history", "user", "decision"} {
		t.Run(writer, func(t *testing.T) {
			s, r := financialFixture(t)
			ctx := context.Background()
			tx, err := s.Shared.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			query := map[string]string{
				"claim":    `UPDATE public.yc_claim SET lifecycle_changed=true WHERE id=$1`,
				"company":  `UPDATE public.yc_company_activation_authority SET revoked_at=clock_timestamp(),revoked_by=gen_random_uuid(),revision=revision+1 WHERE claim_id=$1`,
				"history":  `INSERT INTO public.yc_claim_identity_history(email_hash,prior_user_id) SELECT encode(sha256(convert_to(lower(btrim(u.email)),'UTF8')),'hex'),u.id FROM auth.users u JOIN public.yc_claim c ON c.claimed_user_id=u.id WHERE c.id=$1 ON CONFLICT(email_hash) DO UPDATE SET changed_at=clock_timestamp()`,
				"user":     `UPDATE auth.users SET email_confirmed_at=NULL WHERE id=(SELECT claimed_user_id FROM public.yc_claim WHERE id=$1)`,
				"decision": `INSERT INTO public.yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference) SELECT id,revision+1,'operator',gen_random_uuid(),'review','synthetic' FROM public.yc_claim WHERE id=$1`,
			}[writer]
			if _, err = tx.Exec(ctx, query, r.ClaimID); err != nil {
				t.Fatal(err)
			}
			issuer, err := s.Shared.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer issuer.Rollback(ctx)
			done := make(chan error, 1)
			go func() {
				var out YCFinancialAuthorization
				done <- ycFinancialRPC(ctx, issuer, "issue", financialParams(r), &out)
			}()
			waitFinancialLock(t, s, issuer.Conn().PgConn().PID())
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err == nil {
				t.Fatal("invalidation-first allowed issuance")
			}
			_ = issuer.Rollback(ctx)
			var count int
			if err = s.Shared.QueryRow(ctx, `SELECT count(*) FROM public.yc_financial_authorization`).Scan(&count); err != nil || count != 0 {
				t.Fatal("invalid permit created", count, err)
			}
		})
	}
	s, _ := financialFixture(t)
	ctx := context.Background()
	unrelated := uuid.New()
	if _, err := s.Shared.Exec(ctx, `INSERT INTO auth.users(id,email,created_at,email_confirmed_at) VALUES($1,$2,now(),now())`, unrelated, uuid.NewString()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	for _, iso := range []pgx.TxIsoLevel{pgx.RepeatableRead, pgx.Serializable} {
		tx, err := s.Shared.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE auth.users SET email=$2 WHERE id=$1`, unrelated, uuid.NewString()+"@example.test"); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("unrelated Auth rejected", err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
func TestYCFinancialLeaseExpiry(t *testing.T) {
	s, r := financialFixture(t)
	ctx := context.Background()
	if _, err := s.IssueFinancialAuthorization(ctx, r, "initial", *r.OperationID, r.TermsDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Shared.Exec(ctx, `UPDATE public.yc_claim SET lifecycle_changed=true WHERE id=$1`, r.ClaimID); err != nil {
		t.Fatal(err)
	}
	ds, err := s.LeaseFinancialInvalidations(ctx, uuid.New(), 1)
	if err != nil || len(ds) != 1 {
		t.Fatal(ds, err)
	}
	old := ds[0]
	if _, err = s.Shared.Exec(ctx, `UPDATE public.yc_financial_invalidation SET lease_until=now()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err = s.AcknowledgeFinancialInvalidation(ctx, old, uuid.New(), uuid.New()); err == nil {
		t.Fatal("expired lease acknowledged")
	}
	ds, err = s.LeaseFinancialInvalidations(ctx, uuid.New(), 1)
	if err != nil || len(ds) != 1 || ds[0].InvalidationID != old.InvalidationID {
		t.Fatal("lease lost target", err)
	}
	if err = s.AcknowledgeFinancialInvalidation(ctx, old, uuid.New(), uuid.New()); err == nil {
		t.Fatal("old lease acknowledged reclaimed target")
	}
	if err = s.AcknowledgeFinancialInvalidation(ctx, ds[0], uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	// Shared projection is always explicit for the automated route.
	var state json.RawMessage
	if err = s.Shared.QueryRow(ctx, `SELECT public.yc_financial_authority_rpc('state',$1::jsonb)`, []byte(`{"claim_id":"`+r.ClaimID.String()+`","automated":true}`)).Scan(&state); err != nil {
		t.Fatal(err)
	}
}

func TestYCFinancialOldSnapshotBeforeFirstCompany(t *testing.T) {
	for _, iso := range []pgx.TxIsoLevel{pgx.RepeatableRead, pgx.Serializable} {
		t.Run(string(iso), func(t *testing.T) {
			ctx := context.Background()
			var stale pgx.Tx
			s, _, r, _, _ := acceptanceFixtureBeforeApproval(t, func(h *Handlers, claim uuid.UUID) {
				var err error
				stale, err = h.PromotionAuthPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
				if err != nil {
					t.Fatal(err)
				}
				var n int
				if err = stale.QueryRow(ctx, `SELECT count(*) FROM public.yc_company_activation_authority WHERE claim_id=$1`, claim).Scan(&n); err != nil || n != 0 {
					t.Fatal(n, err)
				}
			})
			defer stale.Rollback(ctx)
			if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
			r, err := loadYCAcceptance(ctx, s.Pool, r.TeamID, r.ClaimID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.IssueFinancialAuthorization(ctx, r, "initial", *r.OperationID, r.TermsDigest); err != nil {
				t.Fatal(err)
			}
			_, err = stale.Exec(ctx, `INSERT INTO public.yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference) VALUES($1,100,'operator',gen_random_uuid(),'review','synthetic')`, r.ClaimID)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "40001" {
				t.Fatalf("old absent-company snapshot missed permit: %v", err)
			}
			_ = stale.Rollback(ctx)
			if _, err = s.Shared.Exec(ctx, `INSERT INTO public.yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference) VALUES($1,100,'operator',gen_random_uuid(),'review','synthetic')`, r.ClaimID); err != nil {
				t.Fatal(err)
			}
			requireFinancialState(t, s, r, "revocation_pending", 1)
		})
	}
}
func TestYCFinancialAllInvalidationWriters(t *testing.T) {
	writers := map[string]string{
		"claim":        `UPDATE public.yc_claim SET lifecycle_changed=true WHERE id=$1`,
		"company":      `UPDATE public.yc_company_activation_authority SET revoked_at=clock_timestamp(),revoked_by=gen_random_uuid(),revision=revision+1 WHERE claim_id=$1`,
		"history":      `INSERT INTO public.yc_claim_identity_history(email_hash,prior_user_id) SELECT encode(sha256(convert_to(lower(btrim(u.email)),'UTF8')),'hex'),u.id FROM auth.users u JOIN public.yc_claim c ON c.claimed_user_id=u.id WHERE c.id=$1 ON CONFLICT(email_hash) DO UPDATE SET changed_at=clock_timestamp()`,
		"user_id":      `UPDATE auth.users SET id=gen_random_uuid() WHERE id=(SELECT claimed_user_id FROM public.yc_claim WHERE id=$1)`,
		"user_created": `UPDATE auth.users SET created_at=created_at+interval '1 microsecond' WHERE id=(SELECT claimed_user_id FROM public.yc_claim WHERE id=$1)`,
		"user_email":   `UPDATE auth.users SET email='changed@example.test' WHERE id=(SELECT claimed_user_id FROM public.yc_claim WHERE id=$1)`,
		"user_delete":  `DELETE FROM auth.users WHERE id=(SELECT claimed_user_id FROM public.yc_claim WHERE id=$1)`,
		"decision":     `INSERT INTO public.yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference) SELECT id,revision+1,'operator',gen_random_uuid(),'review','synthetic' FROM public.yc_claim WHERE id=$1`,
	}
	for name, query := range writers {
		t.Run(name, func(t *testing.T) {
			s, r := financialFixture(t)
			ctx := context.Background()
			if _, err := s.IssueFinancialAuthorization(ctx, r, "initial", *r.OperationID, r.TermsDigest); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Shared.Exec(ctx, query, r.ClaimID); err != nil {
				t.Fatal(err)
			}
			requireFinancialState(t, s, r, "revocation_pending", 1)
		})
	}
}

func TestYCFinancialOtherWriterLockRaces(t *testing.T) {
	writers := map[string]string{
		"claim":    `UPDATE public.yc_claim SET lifecycle_changed=true WHERE id=$1`,
		"company":  `UPDATE public.yc_company_activation_authority SET revoked_at=clock_timestamp(),revoked_by=gen_random_uuid(),revision=revision+1 WHERE claim_id=$1`,
		"history":  `INSERT INTO public.yc_claim_identity_history(email_hash,prior_user_id) SELECT encode(sha256(convert_to(lower(btrim(u.email)),'UTF8')),'hex'),u.id FROM auth.users u JOIN public.yc_claim c ON c.claimed_user_id=u.id WHERE c.id=$1 ON CONFLICT(email_hash) DO UPDATE SET changed_at=clock_timestamp()`,
		"decision": `INSERT INTO public.yc_claim_decision(claim_id,revision,decision,actor_id,reason,evidence_reference) SELECT id,revision+1,'operator',gen_random_uuid(),'review','synthetic' FROM public.yc_claim WHERE id=$1`,
	}
	for name, query := range writers {
		for _, iso := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead, pgx.Serializable} {
			t.Run(name+"/"+string(iso), func(t *testing.T) {
				s, r := financialFixture(t)
				ctx := context.Background()
				invalidator, err := s.Shared.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
				if err != nil {
					t.Fatal(err)
				}
				defer invalidator.Rollback(ctx)
				var count int
				if err = invalidator.QueryRow(ctx, `SELECT count(*) FROM public.yc_financial_authorization`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				issuer, err := s.Shared.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer issuer.Rollback(ctx)
				var receipt YCFinancialAuthorization
				if err = ycFinancialRPC(ctx, issuer, "issue", financialParams(r), &receipt); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, e := invalidator.Exec(ctx, query, r.ClaimID); done <- e }()
				waitFinancialLock(t, s, invalidator.Conn().PgConn().PID())
				if err = issuer.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				err = <-done
				if iso == pgx.ReadCommitted {
					if err != nil {
						t.Fatal(err)
					}
					if err = invalidator.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				} else {
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != "40001" {
						t.Fatalf("old snapshot missed issuance: %v", err)
					}
					_ = invalidator.Rollback(ctx)
					if _, err = s.Shared.Exec(ctx, query, r.ClaimID); err != nil {
						t.Fatal(err)
					}
				}
				requireFinancialState(t, s, r, "revocation_pending", 1)
			})
		}
	}
}

func TestYCFinancialReadinessRechecksAfterProvider(t *testing.T) {
	s, r := financialFixture(t)
	ctx := context.Background()
	if _, err := s.IssueFinancialAuthorization(ctx, r, "initial", *r.OperationID, r.TermsDigest); err != nil {
		t.Fatal(err)
	}
	provider := s.Provisioning.(*acceptanceProvisioningFixture)
	provider.status = YCAcceptanceProvisioningStatus{OperationID: *r.OperationID, State: "funding_ready", Ready: true}
	provider.statusHook = func() {
		if _, err := s.Shared.Exec(ctx, `UPDATE public.yc_claim SET lifecycle_changed=true WHERE id=$1`, r.ClaimID); err != nil {
			t.Fatal(err)
		}
	}
	status, err := s.Status(ctx, r.UserID, r.TeamID, r.ClaimID)
	if err != nil || status.Ready || status.FinancialAuthority == nil || status.FinancialAuthority.State != "revocation_pending" {
		t.Fatal("combined stale shared validity with later readiness", status, err)
	}
}

func TestYCFinancialSuccessorGuardUsesRequestingActor(t *testing.T) {
	s, r := financialFixture(t)
	ctx := context.Background()
	requester := uuid.New()
	s.Authorize = func(_ context.Context, user, team uuid.UUID) error {
		if user != requester || team != r.TeamID {
			return errYCAcceptanceConflict
		}
		return nil
	}
	invoked := false
	callback := func(guard context.Context) error {
		invoked = true
		if _, ok := guard.Deadline(); !ok {
			t.Fatal("successor guard dropped bounded context")
		}
		return nil
	}
	if err := s.WithGuard(ctx, r, callback); err == nil || invoked {
		t.Fatal("initial guard skipped original permission", err)
	}
	if err := s.WithSuccessorGuard(ctx, r, requester, callback); err != nil || !invoked {
		t.Fatal("authorized successor actor blocked by original regional permission", err)
	}
	invoked = false
	if err := s.WithSuccessorGuard(ctx, r, uuid.New(), callback); err == nil || invoked {
		t.Fatal("unauthorized requester admitted", err)
	}
	if _, err := s.Shared.Exec(ctx, `UPDATE auth.users SET email_confirmed_at=NULL WHERE id=$1`, r.UserID); err != nil {
		t.Fatal(err)
	}
	if err := s.WithSuccessorGuard(ctx, r, requester, callback); err == nil || invoked {
		t.Fatal("successor bypassed original shared authority", err)
	}
}

func TestYCFinancialPendingProjectionRechecksAuthority(t *testing.T) {
	for name, query := range map[string]string{
		"account": `UPDATE auth.users SET email_confirmed_at=NULL WHERE id=$1`,
		"company": `UPDATE public.yc_company_activation_authority SET revoked_at=clock_timestamp(),revoked_by=approved_by,revision=revision+1 WHERE team_id=$1`,
	} {
		for _, confirming := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/offered", true: "/confirming"}[confirming], func(t *testing.T) {
				s, _, r, _, _ := acceptanceFixture(t)
				ctx := context.Background()
				if confirming {
					if _, err := s.Accept(ctx, r.UserID, acceptanceRequest(r)); err != nil {
						t.Fatal(err)
					}
				}
				id := r.UserID
				if name == "company" {
					id = r.TeamID
				}
				if _, err := s.Shared.Exec(ctx, query, id); err != nil {
					t.Fatal(err)
				}
				requireFinancialState(t, s, r, "revoked", 0)
				status, err := s.Status(ctx, r.UserID, r.TeamID, r.ClaimID)
				if err != nil || status.Ready || status.State != "review_required" || status.FinancialAuthority == nil || status.FinancialAuthority.State != "revoked" {
					t.Fatal("invalid pending authority hidden", status, err)
				}
			})
		}
	}
}
