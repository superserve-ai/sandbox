package api

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

func TestStripeAssociationStillPending(t *testing.T) {
	receivedAt := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		account *db.TeamBillingAccount
		want    bool
	}{
		{name: "missing account remains investigable", want: true},
		{name: "reservation remains pending", account: &db.TeamBillingAccount{CheckoutInitializingAt: pgtype.Timestamptz{Time: receivedAt.Add(-time.Minute), Valid: true}}, want: true},
		{name: "later reservation cannot resolve earlier event", account: &db.TeamBillingAccount{CheckoutInitializingAt: pgtype.Timestamptz{Time: receivedAt.Add(time.Minute), Valid: true}, CheckoutSessionID: stringPtr("cs_new")}},
		{name: "associated current subscription recovered", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_current")}},
		{name: "superseded subscription obsolete", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_other")}},
		{name: "expired checkout obsolete", account: &db.TeamBillingAccount{CheckoutSessionID: stringPtr("cs_expired")}},
		{name: "canceled without association remains pending", account: &db.TeamBillingAccount{StripeSubscriptionStatus: stringPtr("canceled")}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripeAssociationStillPending(tc.account, "sub_current", receivedAt); got != tc.want {
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
