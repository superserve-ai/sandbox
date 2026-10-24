//go:build integration

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestMatchingCreditZeroCashBalanceCarryNeedsNoPaymentIntent(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	ending := int64(40)
	m.endingBalance = &ending
	invoice := m.paidInvoice("paid", usageLine("price_cpu", 40))
	m.paid[invoice] = 0
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	if row := m.row(invoice); row.State != "issued" || row.Paid != 40 {
		t.Fatal("zero-cash carry no longer matches where usage happened", row)
	}
}

func TestMatchingCreditUncertainReversalNeverCreatesAnotherGrant(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(fmt.Sprintf("first post accepted=%t", accepted), func(t *testing.T) {
			m := newMatchingFixture(t, 10000, 8_000_000, 0)
			invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
			var posts atomic.Int32
			var failBeforeAccept atomic.Bool
			failBeforeAccept.Store(!accepted)
			if accepted {
				m.lose = 1
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/billing/credit_grants" {
					posts.Add(1)
					if failBeforeAccept.Swap(false) {
						http.Error(w, "request lost before provider acceptance", http.StatusServiceUnavailable)
						return
					}
				}
				m.serve(w, r)
			}))
			defer srv.Close()
			m.client.baseURL = srv.URL
			if err := m.tick(); err == nil {
				t.Fatal("first request failure not reported")
			}
			if row := m.row(invoice); row.State != "uncertain" {
				t.Fatal("issuance intent not durable", row)
			}
			m.mu.Lock()
			m.refunded = true
			m.mu.Unlock()
			if err := m.tick(); err != nil {
				t.Fatal(err)
			}
			row := m.row(invoice)
			if row.Flag == "" || posts.Load() != 1 {
				t.Fatal("uncertain reversal caused another POST", row, posts.Load())
			}
			if accepted {
				if row.State != "issued" || len(m.grants) != 1 {
					t.Fatal("lost acknowledgement did not recover original grant", row)
				}
				return
			}
			if row.State != "uncertain" || len(m.grants) != 0 {
				t.Fatal("never-accepted reversed request created credit", row)
			}
			var backedOff bool
			if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT next_attempt_at>clock_timestamp() FROM billing_matching_credit WHERE invoice_id=$1`, invoice).Scan(&backedOff); err != nil || !backedOff {
				t.Fatal("held uncertain outcome has no retry backoff", backedOff, err)
			}
			m.mu.Lock()
			m.refunded = false
			m.mu.Unlock()
			if err := m.tick(); err != nil {
				t.Fatal(err)
			}
			if posts.Load() != 1 {
				t.Fatal("a held uncertain match was silently reposted")
			}
			var raw []byte
			var key string
			if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT request_payload,idempotency_key FROM billing_matching_credit WHERE invoice_id=$1`, invoice).Scan(&raw, &key); err != nil {
				t.Fatal(err)
			}
			form, err := matchingGrantForm(raw)
			if err != nil {
				t.Fatal(err)
			}
			late, err := m.client.createCreditGrant(t.Context(), form, key)
			if err != nil {
				t.Fatal(err)
			}
			if err = m.tick(); err != nil {
				t.Fatal(err)
			}
			if row = m.row(invoice); row.State != "issued" || row.Grant != late.ID || row.Flag == "" || posts.Load() != 2 || len(m.grants) != 1 {
				t.Fatal("late prior outcome was lost or duplicated", row, posts.Load())
			}
		})
	}
}

func TestMatchingCreditConcurrentReviewHoldPreventsUncertainDispatch(t *testing.T) {
	m := newMatchingFixture(t, 10000, 8_000_000, 0)
	invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
	var posts atomic.Int32
	var injectHold atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/billing/credit_grants" {
			if posts.Add(1) == 1 {
				http.Error(w, "request lost before provider acceptance", http.StatusServiceUnavailable)
				return
			}
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/charges/ch_match" && injectHold.Swap(false) {
			_, err := m.f.h.Pool.Exec(r.Context(), `UPDATE billing_matching_credit SET flagged_at=clock_timestamp(),flag_reason='concurrent reversal review',flag_evidence='{}' WHERE invoice_id=$1`, invoice)
			if err != nil {
				t.Error(err)
				http.Error(w, "cannot persist review hold", http.StatusInternalServerError)
				return
			}
		}
		m.serve(w, r)
	}))
	defer srv.Close()
	m.client.baseURL = srv.URL
	if err := m.tick(); err == nil {
		t.Fatal("first request failure not reported")
	}
	injectHold.Store(true)
	if err := m.tick(); err != nil {
		t.Fatal(err)
	}
	row := m.row(invoice)
	if injectHold.Load() || row.State != "uncertain" || row.Flag == "" || posts.Load() != 1 || len(m.grants) != 0 {
		t.Fatal("concurrent durable review hold did not prevent dispatch", row, posts.Load())
	}
	var backedOff bool
	if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT next_attempt_at>clock_timestamp() FROM billing_matching_credit WHERE invoice_id=$1`, invoice).Scan(&backedOff); err != nil || !backedOff {
		t.Fatal("held concurrent outcome has no retry backoff", backedOff, err)
	}
}

func TestMatchingCreditUncertainAcknowledgementRequiresExplicitIssue(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(fmt.Sprintf("first post accepted=%t", accepted), func(t *testing.T) {
			m := newMatchingFixture(t, 10000, 8_000_000, 0)
			invoice := m.paidInvoice("paid", usageLine("price_cpu", 70000))
			var posts atomic.Int32
			if accepted {
				m.lose = 1
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/billing/credit_grants" && posts.Add(1) == 1 && !accepted {
					http.Error(w, "request lost before provider acceptance", http.StatusServiceUnavailable)
					return
				}
				m.serve(w, r)
			}))
			defer srv.Close()
			m.client.baseURL = srv.URL
			if err := m.tick(); err == nil {
				t.Fatal("first request failure not reported")
			}
			m.mu.Lock()
			m.refunded = true
			m.mu.Unlock()
			m.exec(`UPDATE billing_matching_credit SET flagged_at=clock_timestamp(),flag_reason='refund review',flag_evidence='{}' WHERE invoice_id=$1`, invoice)
			var id uuid.UUID
			if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT id FROM billing_matching_credit WHERE invoice_id=$1 AND state='uncertain'`, invoice).Scan(&id); err != nil {
				t.Fatal(err)
			}
			for _, resolution := range []string{"", "withhold", "invalid"} {
				if _, _, err := acknowledgeMatchingFlag(t.Context(), m.f.h.Pool, m.f.c.TeamID, id, uuid.New(), "reviewed refund", resolution); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("uncertain acknowledgement granted dispatch authority", resolution, err)
				}
			}
			var acknowledged bool
			if err := m.f.h.Pool.QueryRow(t.Context(), `SELECT acknowledged_at IS NOT NULL FROM billing_matching_credit WHERE id=$1`, id).Scan(&acknowledged); err != nil || acknowledged {
				t.Fatal("rejected acknowledgement changed durable authority", acknowledged, err)
			}
			if err := m.tick(); err != nil {
				t.Fatal(err)
			}
			if posts.Load() != 1 {
				t.Fatal("rejected acknowledgement allowed another provider request", posts.Load())
			}
			if accepted {
				if row := m.row(invoice); row.State != "issued" || row.Flag == "" || len(m.grants) != 1 {
					t.Fatal("held lost acknowledgement did not recover original grant", row)
				}
				if _, state, err := acknowledgeMatchingFlag(t.Context(), m.f.h.Pool, m.f.c.TeamID, id, uuid.New(), "original grant confirmed", ""); err != nil || state != "issued" {
					t.Fatal("completed grant cannot be acknowledged", state, err)
				}
				return
			}
			if row := m.row(invoice); row.State != "uncertain" || len(m.grants) != 0 {
				t.Fatal("unknown provider outcome lost its hold", row)
			}
			if _, state, err := acknowledgeMatchingFlag(t.Context(), m.f.h.Pool, m.f.c.TeamID, id, uuid.New(), "explicitly authorize matching credit despite refund", "issue"); err != nil || state != "uncertain" {
				t.Fatal("explicit issue could not release uncertain hold", state, err)
			}
			if err := m.tick(); err != nil {
				t.Fatal(err)
			}
			if row := m.row(invoice); row.State != "issued" || posts.Load() != 2 || len(m.grants) != 1 {
				t.Fatal("explicit issue failed or duplicated credit", row, posts.Load())
			}
		})
	}
}
