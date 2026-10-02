package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
)

func TestStripePromotionActorUsesOnlyOwnedReservationOrCurrentCheckout(t *testing.T) {
	actor, metadataActor := uuid.New(), uuid.New()
	now := time.Now().UTC()
	actorID := pgtype.UUID{Bytes: actor, Valid: true}
	subscription := "sub_current"
	otherSubscription := "sub_other"
	for _, tc := range []struct {
		name    string
		account db.GetTeamBillingAccountByStripeCustomerIDRow
		want    uuid.UUID
	}{
		{"pending reservation", db.GetTeamBillingAccountByStripeCustomerIDRow{
			StripeActivationUserID: actorID, StripeActivationCreditReservedAt: pgtype.Timestamptz{Time: now, Valid: true},
		}, actor},
		{"old subscription becomes active during replacement checkout", db.GetTeamBillingAccountByStripeCustomerIDRow{
			StripeCheckoutActorID: actorID, CheckoutInitializingAt: pgtype.Timestamptz{Time: now, Valid: true}, StripeSubscriptionID: &subscription,
		}, metadataActor},
		{"current checkout generation", db.GetTeamBillingAccountByStripeCustomerIDRow{
			StripeCheckoutActorID: actorID, CheckoutInitializingAt: pgtype.Timestamptz{Time: now, Valid: true},
		}, actor},
		{"verified checkout association", db.GetTeamBillingAccountByStripeCustomerIDRow{
			StripeCheckoutActorID: actorID, CheckoutSubscriptionID: &subscription,
		}, actor},
		{"verified different checkout association", db.GetTeamBillingAccountByStripeCustomerIDRow{
			StripeCheckoutActorID: actorID, CheckoutSubscriptionID: &otherSubscription, CheckoutInitializingAt: pgtype.Timestamptz{Time: now, Valid: true},
		}, metadataActor},
		{"unassociated checkout", db.GetTeamBillingAccountByStripeCustomerIDRow{
			StripeCheckoutActorID: actorID, CheckoutInitializingAt: pgtype.Timestamptz{Time: now, Valid: true},
		}, metadataActor},
		{"completed old checkout", db.GetTeamBillingAccountByStripeCustomerIDRow{
			StripeCheckoutActorID: actorID,
		}, metadataActor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := stripeSubscriptionObject{ID: subscription, Metadata: map[string]string{"activation_user_id": metadataActor.String()}}
			if tc.name == "current checkout generation" || tc.name == "verified different checkout association" {
				obj.Metadata["checkout_generation"] = now.Format(time.RFC3339Nano)
			}
			if got := stripePromotionActorForSubscription(tc.account, obj); got != tc.want {
				t.Fatalf("actor=%s want=%s", got, tc.want)
			}
		})
	}
}

func TestStripePromotionReservationPreservesUnprovenGeneration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation string
		present    bool
		valid      bool
	}{
		{"external subscription", "", false, false},
		{"explicit empty generation", "", true, false},
		{"captured generation", "2026-09-24T18:20:30.123456Z", true, true},
		{"invalid generation", "not-a-timestamp", true, false},
		{"unrepresentable precision", "2026-09-24T18:20:30.123456001Z", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make(map[string]string)
			if tc.present {
				metadata["checkout_generation"] = tc.generation
			}
			params := stripePromotionSubscriptionReservationParams(uuid.New(), uuid.New(), "evt_generation", stripeSubscriptionObject{
				ID: "sub_generation", Metadata: metadata,
			})
			if params.HasCheckoutGeneration != tc.present || params.CheckoutGeneration.Valid != tc.valid {
				t.Fatalf("generation presence=%t valid=%t; want %t/%t", params.HasCheckoutGeneration, params.CheckoutGeneration.Valid, tc.present, tc.valid)
			}
		})
	}
}
