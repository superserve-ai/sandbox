//go:build integration

package api

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type ycCalendarFixture struct {
	h                *Handlers
	o                ycOperation
	sub              invoiceSubscription
	token            uuid.UUID
	oldStart, oldEnd time.Time
}

func newYCCalendarFixture(t *testing.T, monthsAgo int, deferredAnniversary ...bool) *ycCalendarFixture {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("requires migrated disposable test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := &Handlers{Pool: pool, DB: db.New(pool)}
	team, err := h.DB.CreateTeam(t.Context(), "calendar-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// A non-midnight boundary also exercises exact, half-open attribution.
	anchor := time.Date(now.Year(), now.Month(), 1, 4, 34, 43, 0, time.UTC).AddDate(0, -monthsAgo, 0)
	if anchor.After(now) {
		anchor = anchor.AddDate(0, -1, 0)
	}
	sub, params, _ := ycTestSubscription()
	sub.Customer, sub.ID = "cus_"+team.ID.String(), "sub_"+team.ID.String()
	sub.StartDate, sub.BillingCycleAnchor = anchor.Unix(), anchor.Unix()
	sub.Items.Data[0].Start, sub.Items.Data[0].End = anchor.Unix(), ycAnnualEnd(anchor).Unix()
	start, end, _ := billing.AnniversaryPeriod(anchor, now)
	price := storagePrice{ID: "price_cpu"}
	price.Recurring.UsageType, price.Recurring.Interval, price.Recurring.IntervalCount = "metered", "month", 1
	sub.Items.Data = append(sub.Items.Data, invoiceSubscriptionItem{Price: price, Start: start.Unix(), End: end.Unix()})
	terms, _ := json.Marshal(params)
	f := &ycCalendarFixture{h: h, sub: sub, token: uuid.New(), oldStart: anchor.AddDate(0, 0, -13), oldEnd: anchor.AddDate(0, 0, 18)}
	f.exec(t, `INSERT INTO team_billing_account(team_id,stripe_customer_id,commercial_billing_anchor) VALUES($1,$2,$3)`, team.ID, sub.Customer, f.oldStart)
	var savedStart, savedEnd any = anchor, ycAnnualEnd(anchor)
	if len(deferredAnniversary) > 0 && deferredAnniversary[0] {
		savedStart, savedEnd = nil, nil
	}
	f.exec(t, `INSERT INTO billing_yc_operation(team_id,approved_by,evidence_reference,request,resource_terms,customer_id,subscription_id,starts_at,ends_at,state,payment_method_ready,payment_method_checked_at) VALUES($1,'synthetic-operator','synthetic-review',jsonb_build_object('company_identity',$1::uuid::text),$2,$3,$4,$5,$6,'provider_pending',true,clock_timestamp())`, team.ID, terms, sub.Customer, sub.ID, savedStart, savedEnd)
	f.o, err = h.ycOperation(t.Context(), team.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.o.Start = pgtype.Timestamptz{Time: anchor, Valid: true}
	f.o.End = pgtype.Timestamptz{Time: ycAnnualEnd(anchor), Valid: true}
	if _, err = h.DB.ClaimStripeWebhookProcessingLease(t.Context(), db.ClaimStripeWebhookProcessingLeaseParams{CustomerID: sub.Customer, Token: f.token}); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *ycCalendarFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.h.Pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}
func (f *ycCalendarFixture) legacy(t *testing.T) {
	f.exec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, f.o.Team, f.oldStart, f.oldEnd)
}
func (f *ycCalendarFixture) persist(ctx context.Context) error {
	return f.h.persistYCContract(ctx, f.o, f.sub, f.token)
}
func (f *ycCalendarFixture) savePartial(t *testing.T) {
	f.exec(t, `UPDATE team_billing_account SET stripe_subscription_id=$2,stripe_subscription_status='active',commercial_billing_anchor=$3 WHERE team_id=$1`, f.o.Team, f.o.Subscription, f.o.Start.Time)
	f.exec(t, `UPDATE billing_yc_operation SET state='enrolling' WHERE team_id=$1`, f.o.Team)
	f.exec(t, `INSERT INTO billing_commercial_contract(id,team_id,offer_key,starts_at,ends_at,customer_id,subscription_id,base_price_id,charge_amount_cents,charge_interval_months,entitlement_amount_cents,entitlement_cadence,entitlement_anchor) VALUES($1,$2,'yc_2026',$3,$4,$5,$6,$7,1200000,12,100000,'scheduled',$3)`, f.o.Contract, f.o.Team, f.o.Start.Time, f.o.End.Time, f.o.Customer, f.o.Subscription, f.o.Params.BasePriceID)
	f.exec(t, `INSERT INTO billing_contract_entitlement_schedule(team_id,contract_id,month_offset,amount_cents) SELECT $1,$2,m,CASE WHEN m<3 THEN 3000000 ELSE 100000 END FROM generate_series(0,11) m`, f.o.Team, f.o.Contract)
	f.exec(t, `INSERT INTO billing_contract_waiver(id,team_id,contract_id,offer_key,offer_version,customer_id,subscription_id,starts_at,ends_at,collectible_base_cents) VALUES($1,$2,$3,'yc_2026',1,$4,$5,$6,$7,0)`, f.o.ID, f.o.Team, f.o.Contract, f.o.Customer, f.o.Subscription, f.o.Start.Time, f.o.End.Time)
	f.exec(t, `INSERT INTO billing_invoice_account(team_id,customer_id,subscription_id,adjustment_price_id,adjustment_event_name,adjustment_meter_id,enrolled_at) VALUES($1,$2,$3,'price_round','round','meter_round',$4)`, f.o.Team, f.o.Customer, f.o.Subscription, f.o.Start.Time)
	f.exec(t, `UPDATE billing_invoice_enrollment SET completed_at=clock_timestamp() WHERE team_id=$1`, f.o.Team)
}

func TestYCCalendarTransitionAndReplay(t *testing.T) {
	for _, kind := range []string{"none", "adjacent", "overlap", "partial", "delayed", "receipt-retry"} {
		t.Run(kind, func(t *testing.T) {
			months := 0
			if kind == "delayed" || kind == "receipt-retry" {
				months = 3
			}
			f := newYCCalendarFixture(t, months)
			if kind == "adjacent" {
				f.oldEnd = f.o.Start.Time
			}
			if kind == "receipt-retry" {
				f.oldEnd = f.o.Start.Time
			}
			if kind != "none" {
				f.legacy(t)
			}
			if kind == "partial" {
				f.savePartial(t)
			}
			if kind == "receipt-retry" {
				f.savePartial(t)
				// The durable state left by a successful first-month transition,
				// followed by an outage spanning several anniversaries.
				f.exec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, f.o.Team, f.o.Start.Time, f.o.Start.Time.UTC().AddDate(0, 1, 0))
				f.exec(t, `INSERT INTO billing_yc_calendar_transition(operation_id,team_id,anniversary,previous_account,shortened_periods,approved_by,evidence_reference) VALUES($1,$2,$3,'{}','[]','synthetic-operator','prior synthetic commit')`, f.o.ID, f.o.Team, f.o.Start.Time)
			}
			// Non-overlapping financial history must remain byte-for-byte intact.
			f.exec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end,status,finalized_at,gross_charges_usd,credits_applied_usd,net_invoice_amount_usd) VALUES($1,$2,$3,'finalized',clock_timestamp(),8,3,5)`, f.o.Team, f.oldStart.AddDate(0, -1, 0), f.oldStart)
			var before []byte
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(p) FROM team_billing_period p WHERE team_id=$1 AND finalized_at IS NOT NULL`, f.o.Team).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := f.persist(t.Context()); err != nil {
				t.Fatal(err)
			}
			var waiver, receipt []byte
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(w) FROM billing_contract_waiver w WHERE id=$1`, f.o.ID).Scan(&waiver); err != nil {
				t.Fatal(err)
			}
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(r) FROM billing_yc_calendar_transition r WHERE operation_id=$1`, f.o.ID).Scan(&receipt); err != nil {
				t.Fatal(err)
			}
			if err := f.persist(t.Context()); err != nil {
				t.Fatal("replay", err)
			}
			var same bool
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT (SELECT to_jsonb(p)=$2::jsonb FROM team_billing_period p WHERE team_id=$1 AND finalized_at IS NOT NULL) AND (SELECT to_jsonb(w)=$3::jsonb FROM billing_contract_waiver w WHERE team_id=$1) AND (SELECT to_jsonb(r)=$4::jsonb FROM billing_yc_calendar_transition r WHERE team_id=$1)`, f.o.Team, before, waiver, receipt).Scan(&same); err != nil || !same {
				t.Fatal("history, waiver or receipt changed", err)
			}
			rows, err := f.h.Pool.Query(t.Context(), `SELECT period_start,period_end FROM team_billing_period WHERE team_id=$1 AND finalized_at IS NULL ORDER BY period_start`, f.o.Team)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			previous := f.o.Start.Time
			if kind != "none" {
				previous = f.oldStart
			}
			for rows.Next() {
				var s, e time.Time
				if err = rows.Scan(&s, &e); err != nil {
					t.Fatal(err)
				}
				if !s.Equal(previous) {
					t.Fatal("gap or overlap", previous, s)
				}
				previous = e
				count++
			}
			rows.Close()
			want := months + 1
			if kind != "none" {
				want++
			}
			if count != want {
				t.Fatalf("periods=%d want=%d", count, want)
			}
			var amount int64
			if err = f.h.Pool.QueryRow(t.Context(), `SELECT sum(amount_cents) FROM billing_contract_entitlement_schedule WHERE contract_id=$1`, f.o.Contract).Scan(&amount); err != nil || amount != 9900000 {
				t.Fatal("changed credit schedule", amount, err)
			}
		})
	}
}

func TestYCCalendarConflictsPreserveAuthority(t *testing.T) {
	for _, kind := range []string{"usage", "export", "ledger", "incremental", "measurement", "invoice", "close", "approval", "finalized", "anomaly", "withheld", "debt"} {
		t.Run(kind, func(t *testing.T) {
			f := newYCCalendarFixture(t, 0)
			f.legacy(t)
			args := []any{f.o.Team, f.oldStart, f.oldEnd}
			switch kind {
			case "usage":
				f.exec(t, `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds) VALUES($1,$2,$3,12)`, args...)
			case "export":
				f.exec(t, `INSERT INTO billing_usage_export(team_id,period_start,period_end,resource_type,stripe_meter_event_identifier,stripe_event_name,value,status) VALUES($1,$2,$3,'cpu',$1::uuid::text,'cpu',12,'pending')`, args...)
			case "ledger":
				f.exec(t, `INSERT INTO team_credit_ledger(team_id,billing_period_start,billing_period_end,amount_usd,reason) VALUES($1,$2,$3,-1,'synthetic settlement')`, args...)
			case "incremental":
				f.exec(t, `INSERT INTO billing_incremental_period(team_id,period_start,period_end) VALUES($1,$2,$3)`, args...)
			case "measurement":
				f.exec(t, `INSERT INTO billing_export_measurement(team_id,period_start,period_end,hour_start,vcpu_seconds,memory_mib_seconds,storage_mib_seconds) VALUES($1,$2,$3,date_trunc('hour',$2::timestamptz),12,0,0)`, args...)
			case "withheld":
				f.savePartial(t)
				f.exec(t, `INSERT INTO billing_entitlement_withheld(contract_id,period_start,period_end,evidence) VALUES($1,$2,$3,'{"synthetic":true}')`, f.o.Contract, f.o.Start.Time, f.o.Start.Time.UTC().AddDate(0, 1, 0))
			case "debt":
				f.savePartial(t)
				f.exec(t, `INSERT INTO billing_entitlement_debt(contract_id,period_start,invoice_id) VALUES($1,$2,'in_synthetic')`, f.o.Contract, f.o.Start.Time)
			case "invoice":
				f.savePartial(t)
				f.exec(t, `INSERT INTO billing_invoice_calendar(team_id,period_start,period_end,customer_id,subscription_id,invoice_start,invoice_end,billing_cycle_anchor) VALUES($1,$2,$3,$4,$5,$2,$3,extract(epoch FROM $2::timestamptz)::bigint)`, append(args, f.o.Customer, f.o.Subscription)...)
			case "close":
				f.exec(t, `INSERT INTO billing_period_close_work(team_id,period_start,period_end) VALUES($1,$2,$3)`, args...)
			case "approval":
				f.exec(t, `UPDATE team_billing_period SET status='approved',approved_at=clock_timestamp(),approval_source='system' WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, args...)
			case "finalized":
				f.exec(t, `UPDATE team_billing_period SET status='finalized',finalized_at=clock_timestamp(),gross_charges_usd=8,credits_applied_usd=3,net_invoice_amount_usd=5 WHERE team_id=$1 AND period_start=$2 AND period_end=$3`, args...)
			case "anomaly":
				f.exec(t, `INSERT INTO billing_period_anomaly(team_id,period_start,period_end,severity,kind) VALUES($1,$2,$3,'warning','synthetic review')`, args...)
			}
			var before []byte
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(p) FROM team_billing_period p WHERE team_id=$1`, f.o.Team).Scan(&before); err != nil {
				t.Fatal(err)
			}
			err := f.persist(t.Context())
			if err == nil || !strings.Contains(err.Error(), "yc_calendar_conflict") || !strings.Contains(err.Error(), f.o.Team.String()) || !strings.Contains(err.Error(), "yc-calendar-recovery.md") {
				t.Fatal("missing actionable conflict", err)
			}
			var same bool
			if err = f.h.Pool.QueryRow(t.Context(), `SELECT (SELECT to_jsonb(p)=$2::jsonb FROM team_billing_period p WHERE team_id=$1) AND NOT EXISTS(SELECT 1 FROM billing_yc_calendar_transition WHERE team_id=$1) AND NOT EXISTS(SELECT 1 FROM billing_yc_operation WHERE team_id=$1 AND state='active')`, f.o.Team, before).Scan(&same); err != nil || !same {
				t.Fatal("conflict changed authority", err)
			}
		})
	}
}

func TestYCCalendarAdjacentPeriodsDoNotHideLegacyAuthority(t *testing.T) {
	for _, kind := range []string{"usage", "export", "ledger", "future-usage"} {
		t.Run(kind, func(t *testing.T) {
			f := newYCCalendarFixture(t, 0, true)
			// An earlier correction may have changed the period keys without
			// reconciling records that have no period foreign key.
			f.exec(t, `INSERT INTO team_billing_period(team_id,period_start,period_end) VALUES($1,$2,$3),($1,$3,$4)`, f.o.Team, f.oldStart, f.o.Start.Time, f.o.Start.Time.UTC().AddDate(0, 1, 0))
			if kind == "future-usage" {
				f.oldStart = f.oldStart.AddDate(0, 1, 0)
				f.oldEnd = f.oldEnd.AddDate(0, 1, 0)
			}
			// Seed the saved record before provider anniversary persistence, as
			// an older worker could have done before this migration was present.
			args := []any{f.o.Team, f.oldStart, f.oldEnd}
			table := ""
			switch kind {
			case "usage", "future-usage":
				table = "team_billing_usage"
				f.exec(t, `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds) VALUES($1,$2,$3,12)`, args...)
			case "export":
				table = "billing_usage_export"
				f.exec(t, `INSERT INTO billing_usage_export(team_id,period_start,period_end,resource_type,stripe_meter_event_identifier,stripe_event_name,value,status) VALUES($1,$2,$3,'cpu',$1::uuid::text,'cpu',12,'pending')`, args...)
			case "ledger":
				table = "team_credit_ledger"
				f.exec(t, `INSERT INTO team_credit_ledger(team_id,billing_period_start,billing_period_end,amount_usd,reason) VALUES($1,$2,$3,-1,'synthetic settlement')`, args...)
			}
			f.exec(t, `UPDATE billing_yc_operation SET starts_at=$2,ends_at=$3 WHERE team_id=$1`, f.o.Team, f.o.Start.Time, f.o.End.Time)
			var before []byte
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT to_jsonb(r) FROM `+table+` r WHERE team_id=$1`, f.o.Team).Scan(&before); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := f.persist(t.Context()); err == nil || !strings.Contains(err.Error(), "yc_calendar_conflict") {
					t.Fatal("straddling authority accepted", err)
				}
			}
			var preserved bool
			if err := f.h.Pool.QueryRow(t.Context(), `SELECT (SELECT to_jsonb(r)=$2::jsonb FROM `+table+` r WHERE team_id=$1) AND NOT EXISTS(SELECT 1 FROM billing_yc_calendar_transition WHERE team_id=$1)`, f.o.Team, before).Scan(&preserved); err != nil || !preserved {
				t.Fatal("conflict changed authority", err)
			}
		})
	}
}

func TestYCCalendarMissingPeriodWriterRace(t *testing.T) {
	for _, writerFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-anniversary-saved", false: "transition-first"}[writerFirst], func(t *testing.T) {
			f := newYCCalendarFixture(t, 0, writerFirst)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			tx, err := f.h.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			usage := `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds) VALUES($1,$2,$3,12)`
			// A future old-calendar key has no parent or overlapping period to lock.
			s, e := f.oldStart.AddDate(0, 2, 0), f.oldEnd.AddDate(0, 2, 0)
			if writerFirst {
				if _, err = tx.Exec(ctx, usage, f.o.Team, s, e); err != nil {
					t.Fatal(err)
				}
				f.exec(t, `UPDATE billing_yc_operation SET starts_at=$2,ends_at=$3 WHERE team_id=$1`, f.o.Team, f.o.Start.Time, f.o.End.Time)
				result := make(chan error, 1)
				go func() { result <- f.persist(ctx) }()
				select {
				case err = <-result:
					t.Fatal("missing-parent writer was not fenced", err)
				case <-time.After(50 * time.Millisecond):
				}
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err = <-result; err == nil || !strings.Contains(err.Error(), "yc_calendar_conflict") {
					t.Fatal("concurrent authority accepted", err)
				}
			} else {
				if _, err = tx.Exec(ctx, `SELECT reconcile_yc_billing_calendar($1,$2)`, f.o.Team, f.o.ID); err != nil {
					t.Fatal(err)
				}
				if _, err = f.h.Pool.Exec(ctx, usage, f.o.Team, s, e); err == nil || !strings.Contains(err.Error(), "55P03") {
					t.Fatal("missing-parent writer bypassed account fence", err)
				}
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err = f.h.Pool.Exec(ctx, usage, f.o.Team, s, e); err == nil || !strings.Contains(err.Error(), "yc_calendar_conflict") {
					t.Fatal("stale retry accepted", err)
				}
			}
			var count int
			if err = f.h.Pool.QueryRow(ctx, `SELECT count(*) FROM team_billing_usage WHERE team_id=$1`, f.o.Team).Scan(&count); err != nil || count != map[bool]int{true: 1, false: 0}[writerFirst] {
				t.Fatal("lost or stale authority", count, err)
			}
		})
	}
}

func TestYCCalendarConcurrentReconciliation(t *testing.T) {
	f := newYCCalendarFixture(t, 0)
	f.legacy(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- f.persist(t.Context()) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var periods, receipts int
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM team_billing_period WHERE team_id=$1),(SELECT count(*) FROM billing_yc_calendar_transition WHERE team_id=$1)`, f.o.Team).Scan(&periods, &receipts); err != nil || periods != 2 || receipts != 1 {
		t.Fatal(periods, receipts, err)
	}
	_, err := f.h.DB.UpsertTeamBillingPeriod(t.Context(), db.UpsertTeamBillingPeriodParams{TeamID: f.o.Team, PeriodStart: f.oldStart, PeriodEnd: f.oldEnd, Status: "open"})
	if err == nil {
		t.Fatal("stale calendar recreated")
	}
	_, err = f.h.DB.UpsertTeamBillingPeriod(t.Context(), db.UpsertTeamBillingPeriodParams{TeamID: f.o.Team, PeriodStart: f.oldStart.AddDate(0, 4, 0), PeriodEnd: f.oldEnd.AddDate(0, 4, 0), Status: "open"})
	if err == nil || !strings.Contains(err.Error(), "yc_calendar_conflict") {
		t.Fatal("future stale calendar recreated", err)
	}
}

func TestYCCalendarUsageWriterRace(t *testing.T) {
	for _, writerFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "writer-first", false: "transition-first"}[writerFirst], func(t *testing.T) {
			f := newYCCalendarFixture(t, 0)
			f.legacy(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			tx, err := f.h.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			usage := `INSERT INTO team_billing_usage(team_id,period_start,period_end,vcpu_seconds) VALUES($1,$2,$3,12)`
			result := make(chan error, 1)
			if writerFirst {
				if _, err = tx.Exec(ctx, usage, f.o.Team, f.oldStart, f.oldEnd); err != nil {
					t.Fatal(err)
				}
				go func() { result <- f.persist(ctx) }()
			} else {
				if _, err = tx.Exec(ctx, `SELECT reconcile_yc_billing_calendar($1,$2)`, f.o.Team, f.o.ID); err != nil {
					t.Fatal(err)
				}
				go func() { _, e := f.h.Pool.Exec(ctx, usage, f.o.Team, f.oldStart, f.oldEnd); result <- e }()
			}
			// Both paths must block on the period key while the first writer owns it.
			select {
			case err = <-result:
				t.Fatal("writer bypassed fence", err)
			case <-time.After(50 * time.Millisecond):
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = <-result; err == nil || !strings.Contains(err.Error(), "yc_calendar_conflict") {
				t.Fatal("race did not preserve authority", err)
			}
			var count int
			if err = f.h.Pool.QueryRow(ctx, `SELECT count(*) FROM team_billing_usage WHERE team_id=$1`, f.o.Team).Scan(&count); err != nil || count != map[bool]int{true: 1, false: 0}[writerFirst] {
				t.Fatal("lost or stale usage", count, err)
			}
		})
	}
}

func TestYCOperatorLegacyCalendarActivation(t *testing.T) {
	runYCOperatorAdoption(t, false, "card", false, true)
}

func TestYCOperatorPreRolloutActiveCalendar(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "untouched", true: "accounting-conflict"}[conflict], func(t *testing.T) {
			runYCOperatorAdoption(t, false, "card", false, true, true, conflict)
		})
	}
}

func TestYCOperatorPreRolloutRenewalCalendarConflict(t *testing.T) {
	runYCOperatorAdoption(t, false, "card", false, true, true, true, true)
}

func TestYCOperatorCalendarRejectsProviderAnchorDrift(t *testing.T) {
	for _, renewal := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "renewal"}[renewal], func(t *testing.T) {
			runYCOperatorAdoption(t, false, "card", false, true, true, false, renewal, true)
		})
	}
}

func TestYCCalendarUsageBoundary(t *testing.T) {
	f := newYCCalendarFixture(t, 0)
	f.legacy(t)
	sandbox := uuid.New()
	f.exec(t, `INSERT INTO sandbox(id,team_id,name,status,vcpu_count,memory_mib,host_id) VALUES($1,$2,'calendar-fixture','deleted',1,1024,'default')`, sandbox, f.o.Team)
	// Delayed raw measurements remain attributable after changing the calendar.
	if err := f.persist(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO sandbox_compute_billing_interval(sandbox_id,team_id,vcpu_count,memory_mib,started_at,ended_at,end_reason) VALUES($1,$2,1,1024,$3,$4,'deleted')`, sandbox, f.o.Team, f.o.Start.Time.Add(-10*time.Second), f.o.Start.Time.Add(20*time.Second))
	for _, window := range []struct {
		s, e time.Time
		want int64
	}{{f.oldStart, f.o.Start.Time, 10}, {f.o.Start.Time, f.oldEnd, 20}, {f.oldStart, f.oldEnd, 30}} {
		usage, err := f.h.DB.GetTeamBillingChargeableUsage(t.Context(), db.GetTeamBillingChargeableUsageParams{TeamID: f.o.Team, PeriodStart: window.s, PeriodEnd: window.e})
		if err != nil {
			t.Fatal(err)
		}
		got, err := usage.VcpuSeconds.Int64Value()
		if err != nil || got.Int64 != window.want {
			t.Fatal("boundary usage", got, window.want, err)
		}
	}
	var before, after bool
	if err := f.h.Pool.QueryRow(t.Context(), `SELECT billing_yc_covered(c,$2,$3,false),billing_yc_covered(c,$3,billing_anniversary_boundary($3,1),false) FROM billing_commercial_contract c WHERE id=$1`, f.o.Contract, f.oldStart, f.o.Start.Time).Scan(&before, &after); err != nil || before || !after {
		t.Fatal("retroactive or missing YC coverage", before, after, err)
	}
}

func TestYCCalendarBlocksPrematureEnrollment(t *testing.T) {
	for _, state := range []string{"enrolling", "active", "renewal_pending", "renewed", "ended"} {
		t.Run(state, func(t *testing.T) {
			f := newYCCalendarFixture(t, 0)
			f.legacy(t)
			f.savePartial(t)
			f.exec(t, `UPDATE billing_yc_operation SET state=$2 WHERE team_id=$1`, f.o.Team, state)
			f.exec(t, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, f.o.Team)
			f.h.Stripe = &stripeHTTPClient{}
			if err := f.h.enrollInvoiceAccount(t.Context(), f.o.Team, nil); err == nil || !strings.Contains(err.Error(), "YC calendar reconciliation") {
				t.Fatal("enrolled before period reconciliation", err)
			}
		})
	}
}

func TestYCCalendarPreservesExistingEntitlement(t *testing.T) {
	f := newYCCalendarFixture(t, 0)
	f.legacy(t)
	f.savePartial(t)
	ctx := t.Context()
	c, err := f.h.DB.ActivateCommercialContract(ctx, db.ActivateCommercialContractParams{TeamID: f.o.Team, ContractID: f.o.Contract})
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err = f.h.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(map[string]any{"gate": "finalized_invoice_gate_v1", "period_start": f.o.Start.Time, "period_end": f.o.Start.Time.UTC().AddDate(0, 1, 0)})
	_, err = f.h.DB.ObserveCommercialCollection(ctx, db.ObserveCommercialCollectionParams{TeamID: f.o.Team, ContractID: f.o.Contract, ExpectedRevision: c.Revision, HasOverdueBalance: new(bool), CheckedAt: pgtype.Timestamptz{Time: now, Valid: true}, ValidUntil: pgtype.Timestamptz{Time: now.Add(time.Minute), Valid: true}, Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.h.DB.ClaimCurrentUsageEntitlement(ctx, db.ClaimCurrentUsageEntitlementParams{TeamID: f.o.Team, ContractID: f.o.Contract})
	if err != nil {
		t.Fatal(err)
	}
	err = f.persist(ctx)
	if err == nil || !strings.Contains(err.Error(), "usage entitlement") {
		t.Fatal("existing entitlement not reported", err)
	}
	after, err := f.h.DB.GetCurrentUsageEntitlement(ctx, db.GetCurrentUsageEntitlementParams{TeamID: f.o.Team, Kind: "metered_usage"})
	if err != nil || after.ID != e.ID || after.IdempotencyKey != e.IdempotencyKey || after.State != e.State || !after.PeriodStart.Equal(e.PeriodStart) || !after.PeriodEnd.Equal(e.PeriodEnd) {
		t.Fatal("entitlement changed", err)
	}
}

func TestYCCalendarFencesFutureStaleWriter(t *testing.T) {
	f := newYCCalendarFixture(t, 0)
	f.legacy(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tx, err := f.h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT reconcile_yc_billing_calendar($1,$2)`, f.o.Team, f.o.ID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, e := f.h.DB.UpsertTeamBillingPeriod(ctx, db.UpsertTeamBillingPeriodParams{TeamID: f.o.Team, PeriodStart: f.oldStart.AddDate(0, 4, 0), PeriodEnd: f.oldEnd.AddDate(0, 4, 0), Status: "open"})
		result <- e
	}()
	select {
	case err = <-result:
		t.Fatal("future period bypassed transition", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err == nil || !strings.Contains(err.Error(), "yc_calendar_conflict") {
		t.Fatal("stale future authority accepted", err)
	}
}

func TestYCEndedCalendarRequiresOriginalBinding(t *testing.T) {
	for _, replacement := range []string{"", "sub_replacement"} {
		t.Run(replacement, func(t *testing.T) {
			f := newYCCalendarFixture(t, 0)
			f.legacy(t)
			f.savePartial(t)
			f.o.State = "ended"
			if replacement != "" {
				replacement += uuid.NewString()
			}
			f.exec(t, `UPDATE billing_yc_operation SET state='ended' WHERE team_id=$1`, f.o.Team)
			f.exec(t, `UPDATE team_billing_account SET stripe_subscription_id=NULLIF($2,'') WHERE team_id=$1`, f.o.Team, replacement)
			tx, err := f.h.Pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			if err = f.h.lockAndReconcileYCCalendar(t.Context(), tx, f.o, f.token); err == nil || !strings.Contains(err.Error(), "binding changed") {
				t.Fatal("ended recovery accepted missing or replacement binding", err)
			}
			var unchanged bool
			if err = tx.QueryRow(t.Context(), `SELECT NOT EXISTS(SELECT 1 FROM billing_yc_calendar_transition WHERE team_id=$1) AND EXISTS(SELECT 1 FROM team_billing_period WHERE team_id=$1 AND period_start=$2 AND period_end=$3)`, f.o.Team, f.oldStart, f.oldEnd).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("ended recovery changed another billing association", err)
			}
		})
	}
}

func TestYCEndedCalendarDoesNotBlockReplacementEnrollment(t *testing.T) {
	f := newYCCalendarFixture(t, 0)
	f.legacy(t)
	f.savePartial(t)
	f.exec(t, `UPDATE billing_yc_operation SET state='ended' WHERE team_id=$1`, f.o.Team)
	f.exec(t, `UPDATE team_billing_account SET stripe_subscription_id=$2 WHERE team_id=$1`, f.o.Team, "sub_replacement_"+uuid.NewString())
	f.exec(t, `INSERT INTO team_feature_flag(team_id,key,enabled) VALUES($1,'billing_export_enabled',true) ON CONFLICT(team_id,key) DO UPDATE SET enabled=true`, f.o.Team)
	f.h.Stripe = &stripeHTTPClient{}
	// Reach the existing configuration check without provider calls. An old
	// ended operation must not intercept the replacement account's enrollment.
	if err := f.h.enrollInvoiceAccount(t.Context(), f.o.Team, &invoiceAccount{Price: "different"}); err == nil || !strings.Contains(err.Error(), "existing rounding configuration differs") {
		t.Fatal("ended calendar blocked replacement enrollment", err)
	}
}
