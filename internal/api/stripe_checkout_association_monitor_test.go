package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

func TestStripeCheckoutAssociationMonitorScheduleAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	stopped := make(chan struct{})
	type call struct {
		at     time.Time
		cursor db.StripeCheckoutAssociationCursor
	}
	calls := make(chan call, 2)
	done := startStripeCheckoutAssociationMonitor(ctx,
		func(interval time.Duration) (<-chan time.Time, func()) {
			if interval != time.Minute {
				t.Errorf("poll interval = %s, want one minute", interval)
			}
			return ticks, func() { close(stopped) }
		},
		func(tickCtx context.Context, at time.Time, cursor db.StripeCheckoutAssociationCursor) (db.StripeCheckoutAssociationCursor, error) {
			if deadline, ok := tickCtx.Deadline(); !ok || time.Until(deadline) > stripeAssociationTickTimeout {
				t.Errorf("tick context deadline = %v, want timeout at most %s", deadline, stripeAssociationTickTimeout)
			}
			calls <- call{at: at, cursor: cursor}
			return db.StripeCheckoutAssociationCursor{EventID: "evt_next"}, nil
		},
	)

	first := time.Date(2026, 9, 25, 12, 1, 0, 0, time.UTC)
	for i, at := range []time.Time{first, first.Add(time.Minute)} {
		select {
		case ticks <- at:
		case <-time.After(time.Second):
			t.Fatal("monitor did not start")
		}
		select {
		case got := <-calls:
			if !got.at.Equal(at) {
				t.Errorf("tick %d time = %s, want %s", i, got.at, at)
			}
			wantCursor := ""
			if i == 1 {
				wantCursor = "evt_next"
			}
			if got.cursor.EventID != wantCursor {
				t.Errorf("tick %d cursor = %q, want %q", i, got.cursor.EventID, wantCursor)
			}
		case <-time.After(time.Second):
			t.Fatal("scheduled monitor tick did not execute")
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not exit after cancellation")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("monitor did not stop its ticker")
	}
}

func TestStripeCheckoutAssociationMonitorFailureCooldownAndRecovery(t *testing.T) {
	transport := &sentry.MockTransport{}
	previousClient := sentry.CurrentHub().Client()
	if err := sentry.Init(sentry.ClientOptions{Dsn: "https://test@example.com/1", Transport: transport}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sentry.CurrentHub().BindClient(previousClient) })
	var output bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(zerolog.MultiLevelWriter(&output, &sentrylog.Writer{}))
	t.Cleanup(func() { log.Logger = previousLogger })

	steps := []struct {
		minute     int
		failure    string
		wantReport bool
	}{
		{minute: 0, failure: "initial discovery failure", wantReport: true},
		{minute: 1, failure: "repeated discovery failure"},
		{minute: 29, failure: "failure before cooldown expires"},
		{minute: 30, failure: "failure at cooldown boundary", wantReport: true},
		{minute: 31, failure: "failure during renewed cooldown"},
		{minute: 32},
		{minute: 33, failure: "failure after successful tick", wantReport: true},
		{minute: 34, failure: "repeated failure after recovery"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	nextStep := 0
	done := startStripeCheckoutAssociationMonitor(ctx,
		func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} },
		func(_ context.Context, _ time.Time, cursor db.StripeCheckoutAssociationCursor) (db.StripeCheckoutAssociationCursor, error) {
			// A final successful tick cancels only after every preceding tick's
			// failure reporting has completed, including suppressed failures.
			if nextStep == len(steps) {
				cancel()
				return cursor, nil
			}
			failure := steps[nextStep].failure
			nextStep++
			if failure == "" {
				return cursor, nil
			}
			return cursor, errors.New(failure)
		},
	)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("monitor did not exit after cancellation")
		}
	})

	first := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	var wantFailures []string
	for _, step := range steps {
		select {
		case ticks <- first.Add(time.Duration(step.minute) * time.Minute):
		case <-time.After(time.Second):
			t.Fatal("monitor did not accept scheduled tick")
		}
		if step.wantReport {
			wantFailures = append(wantFailures, step.failure)
		}
	}
	select {
	case ticks <- first.Add(35 * time.Minute):
	case <-time.After(time.Second):
		t.Fatal("monitor did not accept final tick")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not exit after final tick")
	}
	sentry.Flush(time.Second)

	entries := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	events := transport.Events()
	if len(entries) != len(wantFailures) || len(events) != len(wantFailures) {
		t.Fatalf("failure reports: logs = %d, Sentry events = %d, want %d; logs: %s", len(entries), len(events), len(wantFailures), output.String())
	}
	for i, failure := range wantFailures {
		var entry map[string]any
		if err := json.Unmarshal(entries[i], &entry); err != nil {
			t.Fatal(err)
		}
		if entry["level"] != "error" || entry["message"] != "Stripe checkout association monitor failed" || entry["error"] != failure {
			t.Errorf("log report %d = %+v, want monitor error with %q", i, entry, failure)
		}
		if events[i].Level != sentry.LevelError || events[i].Message != "Stripe checkout association monitor failed: "+failure || events[i].Contexts["log"]["error"] != failure {
			t.Errorf("Sentry report %d = %+v, want monitor error with %q", i, events[i], failure)
		}
	}
}

func TestStripeAssociationStillPending(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account *db.TeamBillingAccount
		expired bool
		want    bool
	}{
		{name: "missing account remains investigable", want: true},
		{name: "reservation remains pending", account: &db.TeamBillingAccount{CheckoutInitializingAt: pgtype.Timestamptz{Valid: true}}, want: true},
		{name: "later reservation does not prove expiration", account: &db.TeamBillingAccount{CheckoutInitializingAt: pgtype.Timestamptz{Valid: true}, CheckoutSessionID: stringPtr("cs_new")}, want: true},
		{name: "verified expired generation", account: &db.TeamBillingAccount{}, expired: true},
		{name: "verified expired generation with replacement", account: &db.TeamBillingAccount{CheckoutSessionID: stringPtr("cs_new")}, expired: true},
		{name: "associated current subscription recovered", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_current")}},
		{name: "historical subscription does not supersede pending checkout", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_other"), CheckoutInitializingAt: pgtype.Timestamptz{Valid: true}}, want: true},
		{name: "completed checkout for another subscription is obsolete", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_other"), CheckoutSubscriptionID: stringPtr("sub_other"), CheckoutCompletedAt: pgtype.Timestamptz{Valid: true}}},
		{name: "finalized checkout for another subscription is obsolete", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_other"), CheckoutSubscriptionID: stringPtr("sub_other"), StripeSubscriptionEventAt: pgtype.Timestamptz{Valid: true}}},
		{name: "historical lifecycle without checkout association remains pending", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_other"), StripeSubscriptionStatus: stringPtr("canceled"), StripeSubscriptionEventAt: pgtype.Timestamptz{Valid: true}}, want: true},
		{name: "checkout association without accepted lifecycle remains pending", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_other"), CheckoutSubscriptionID: stringPtr("sub_other")}, want: true},
		{name: "mismatched historical association remains pending", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_historical"), CheckoutSubscriptionID: stringPtr("sub_other"), StripeSubscriptionEventAt: pgtype.Timestamptz{Valid: true}}, want: true},
		{name: "completed checkout without subscription is pending", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_other"), CheckoutCompletedAt: pgtype.Timestamptz{Valid: true}}, want: true},
		{name: "retained session alone does not prove expiration", account: &db.TeamBillingAccount{CheckoutSessionID: stringPtr("cs_expired")}, want: true},
		{name: "canceled without association remains pending", account: &db.TeamBillingAccount{StripeSubscriptionStatus: stringPtr("canceled")}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripeAssociationStillPending(tc.account, "sub_current", tc.expired); got != tc.want {
				t.Fatalf("pending = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReportStripeAssociationOverdueForwardsDiagnostics(t *testing.T) {
	transport := &sentry.MockTransport{}
	previousClient := sentry.CurrentHub().Client()
	if err := sentry.Init(sentry.ClientOptions{Dsn: "https://test@example.com/1", Transport: transport}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sentry.CurrentHub().BindClient(previousClient) })
	var output bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(zerolog.MultiLevelWriter(&output, &sentrylog.Writer{}))
	t.Cleanup(func() { log.Logger = previousLogger })

	receivedAt := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	alert := StripeAssociationAlert{
		EventID: "evt_example", EventType: "customer.subscription.created", TeamID: "team_example",
		CustomerID: "cus_example", SubscriptionID: "sub_example", CheckoutSessionID: "cs_example",
		ReceivedAt: receivedAt, Age: 6 * time.Minute,
	}
	if err := reportStripeAssociationOverdue(alert); err != nil {
		t.Fatal(err)
	}
	sentry.Flush(time.Second)
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &entry); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]any{
		"level": "error", "message": "Stripe checkout association overdue",
		"event_id": alert.EventID, "event_type": alert.EventType, "team_id": alert.TeamID,
		"stripe_customer_id": alert.CustomerID, "stripe_subscription_id": alert.SubscriptionID,
		"checkout_session_id": alert.CheckoutSessionID, "received_at": receivedAt.Format(time.RFC3339),
	} {
		if entry[field] != want {
			t.Errorf("%s = %v, want %v", field, entry[field], want)
		}
	}
	if entry["pending_age"] != float64(alert.Age/time.Millisecond) {
		t.Errorf("pending_age = %v, want %v milliseconds", entry["pending_age"], alert.Age/time.Millisecond)
	}
	events := transport.Events()
	if len(events) != 1 || events[0].Level != sentry.LevelError || events[0].Message != "Stripe checkout association overdue" {
		t.Fatalf("Sentry overdue events = %+v", events)
	}
}
