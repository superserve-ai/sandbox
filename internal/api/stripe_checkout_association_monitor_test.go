package api

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/superserve-ai/sandbox/internal/db"
)

func TestStripeAssociationStillPending(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account *db.TeamBillingAccount
		want    bool
	}{
		{name: "missing account remains investigable", want: true},
		{name: "reservation remains pending", account: &db.TeamBillingAccount{CheckoutInitializingAt: pgtype.Timestamptz{Valid: true}}, want: true},
		{name: "associated current subscription recovered", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_current")}},
		{name: "superseded subscription obsolete", account: &db.TeamBillingAccount{StripeSubscriptionID: stringPtr("sub_other")}},
		{name: "expired checkout obsolete", account: &db.TeamBillingAccount{CheckoutSessionID: stringPtr("cs_expired")}},
		{name: "canceled without association remains pending", account: &db.TeamBillingAccount{StripeSubscriptionStatus: stringPtr("canceled")}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripeAssociationStillPending(tc.account, "sub_current"); got != tc.want {
				t.Fatalf("pending = %v, want %v", got, tc.want)
			}
		})
	}
}
