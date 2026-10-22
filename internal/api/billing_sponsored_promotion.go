package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/billing"
	"github.com/superserve-ai/sandbox/internal/db"
)

type sponsoredPromotionRequest struct {
	Key          string    `json:"idempotency_key"`
	Merchant     string    `json:"merchant_account"`
	Live         *bool     `json:"live_mode"`
	Customer     string    `json:"customer_id"`
	Subscription string    `json:"subscription_id"`
	User         uuid.UUID `json:"activation_user_id"`
	Event        string    `json:"reservation_event_id"`
	Grant        string    `json:"grant_id,omitempty"`
	Reason       string    `json:"reason"`
	Reference    string    `json:"reference"`
}

func (h *Handlers) SponsoredPromotionRecovery(c *gin.Context) {
	team, ok := ycTeam(c)
	if !ok {
		return
	}
	sponsor, err := uuid.Parse(c.Param("operation_id"))
	actor, actorOK := c.Get("actor_id")
	var r sponsoredPromotionRequest
	if err != nil || !actorOK || c.ShouldBindJSON(&r) != nil || strings.TrimSpace(r.Key) == "" || len(r.Key) > 200 || !strings.HasPrefix(r.Merchant, "acct_") || r.Live == nil || !strings.HasPrefix(r.Customer, "cus_") || !strings.HasPrefix(r.Subscription, "sub_") || r.User == uuid.Nil || strings.TrimSpace(r.Event) == "" || strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 2000 || strings.TrimSpace(r.Reference) == "" || len(r.Reference) > 2000 {
		respondErrorMsg(c, "bad_request", "exact sponsorship, provider, original activation actor/event, idempotency key and audited reason/reference are required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	if err = h.recoverSponsoredPromotion(ctx, team, sponsor, actor, r); err != nil {
		respondErrorMsg(c, "conflict", err.Error(), 409)
		return
	}
	c.JSON(200, gin.H{"status": "completed", "idempotency_key": r.Key})
}

func (h *Handlers) recoverSponsoredPromotion(ctx context.Context, team, sponsor uuid.UUID, actor any, r sponsoredPromotionRequest) error {
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return errors.New("billing provider unavailable")
	}
	if err := client.ycMerchant(ctx, ycApproval{Merchant: r.Merchant}); err != nil {
		return err
	}
	lease, err := claimStripeWebhookProcessingLease(ctx, h.DB, r.Customer)
	if err != nil {
		return err
	}
	defer func() {
		ack, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = h.DB.ReleaseStripeWebhookProcessingLease(ack, db.ReleaseStripeWebhookProcessingLeaseParams{CustomerID: r.Customer, Token: lease.Token})
	}()
	request, _ := json.Marshal(r)
	// Persist the original request before provider mutation; retries cannot replace
	// the actor, reservation, or financial decision after an ambiguous response.
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := h.DB.WithTx(tx)
	if err = lease.lock(ctx, q); err != nil {
		return err
	}
	if err = q.LockStripePromotion(ctx, db.LockStripePromotionParams{TeamID: team, UserID: r.User}); err != nil {
		return err
	}
	a, err := q.LockTeamBillingAccount(ctx, team)
	if err != nil {
		return err
	}
	var valid bool
	if h.Config == nil {
		return errors.New("home billing region unavailable")
	}
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_sponsored_operation o JOIN team t ON t.id=o.team_id WHERE o.id=$1 AND o.team_id=$2 AND o.state='active' AND o.revoked_at IS NULL AND o.customer_id=$3 AND o.subscription_id=$4 AND t.home_region=$5)`, sponsor, team, r.Customer, r.Subscription, h.Config.TeamCreationRegion).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid || derefString(a.StripeCustomerID) != r.Customer || derefString(a.StripeSubscriptionID) != r.Subscription {
		return errors.New("active sponsorship, customer, subscription or home region differs")
	}
	var recovery uuid.UUID
	var same, completed bool
	var grantID string
	var before []byte
	err = tx.QueryRow(ctx, `SELECT id,request=$3::jsonb AND sponsorship_id=$4,completed_at IS NOT NULL,COALESCE(grant_id,''),before_evidence FROM billing_sponsored_promotion_recovery WHERE team_id=$1 AND idempotency_key=$2 FOR UPDATE`, team, r.Key, request, sponsor).Scan(&recovery, &same, &completed, &grantID, &before)
	if err == nil {
		if !same {
			return errors.New("recovery idempotency key has different terms")
		}
		if completed {
			return tx.Commit(ctx)
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		if !a.StripeActivationUserID.Valid || uuid.UUID(a.StripeActivationUserID.Bytes) != r.User || derefString(a.StripeActivationCreditReservationEventID) != r.Event || (r.Grant != "" && derefString(a.StripeActivationCreditGrantID) != "" && r.Grant != *a.StripeActivationCreditGrantID) {
			return errors.New("original activation reservation or grant differs")
		}
		grantID = derefString(a.StripeActivationCreditGrantID)
		var attempted bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_reserved_team_id=$2 AND stripe_redemption_attempted_at IS NOT NULL)`, r.User, team).Scan(&attempted); err != nil {
			return err
		}
		if grantID != "" || a.StripeActivationCreditGrantedAt.Valid || attempted {
			grant, e := billing.FindStripeActivationGrant(ctx, client.doForm, team, r.Customer, grantID)
			if e != nil {
				return e
			}
			if grant.LiveMode != *r.Live || (r.Grant != "" && r.Grant != grant.ID) {
				return errors.New("activation grant mode or requested identity differs")
			}
			if e = billing.VerifyUnusedStripeActivationGrant(ctx, client.doForm, grant); e != nil {
				return e
			}
			grantID = grant.ID
			before, _ = json.Marshal(gin.H{"grant": grant, "available_cents": 9500, "ledger_cents": 9500})
		} else if !a.StripeActivationCreditReservedAt.Valid || r.Grant != "" {
			return errors.New("no complete unattempted reservation to recover")
		}
		err = tx.QueryRow(ctx, `INSERT INTO billing_sponsored_promotion_recovery(team_id,sponsorship_id,idempotency_key,request,approved_by,reason,reference,customer_id,subscription_id,user_id,event_id,grant_id,before_evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,''),$13) RETURNING id`, team, sponsor, r.Key, request, actor, r.Reason, r.Reference, r.Customer, r.Subscription, r.User, r.Event, grantID, before).Scan(&recovery)
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	// Hold the lease row and original promotion/account locks across the bounded
	// provider call. An expiry cannot let a replacement lease overtake completion.
	tx, err = h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q = h.DB.WithTx(tx)
	if err = lease.lock(ctx, q); err != nil {
		return err
	}
	if err = q.LockStripePromotion(ctx, db.LockStripePromotionParams{TeamID: team, UserID: r.User}); err != nil {
		return err
	}
	a, err = q.LockTeamBillingAccount(ctx, team)
	if err != nil {
		return err
	}
	if grantID == "" && !a.StripeActivationCreditReservedAt.Valid && !a.StripeActivationCreditGrantedAt.Valid && a.StripeActivationCreditGrantID == nil {
		var released bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM stripe_promotion_outcome WHERE event_id=$1 AND team_id=$2 AND user_id=$3 AND reason='sponsored_onboarding')`, r.Event, team, r.User).Scan(&released); err != nil {
			return err
		}
		if released {
			_, err = tx.Exec(ctx, `UPDATE billing_sponsored_promotion_recovery SET after_evidence='{"unattempted_reservation_released":true}',completed_at=clock_timestamp() WHERE id=$1`, recovery)
			if err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
	}
	if derefString(a.StripeCustomerID) != r.Customer || derefString(a.StripeSubscriptionID) != r.Subscription || !a.StripeActivationUserID.Valid || uuid.UUID(a.StripeActivationUserID.Bytes) != r.User || derefString(a.StripeActivationCreditReservationEventID) != r.Event {
		return errors.New("activation ownership changed during recovery")
	}
	if grantID == "" {
		grantID = derefString(a.StripeActivationCreditGrantID)
	}
	if grantID == "" && !a.StripeActivationCreditGrantedAt.Valid {
		var attempted bool
		e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_promotion_entitlement WHERE user_id=$1 AND stripe_redemption_reserved_team_id=$2 AND stripe_redemption_attempted_at IS NOT NULL)`, r.User, team).Scan(&attempted)
		if e != nil {
			return e
		}
		if !attempted {
			if !a.StripeActivationCreditReservedAt.Valid || r.Grant != "" {
				return errors.New("no complete unattempted reservation to recover")
			}
			if err = q.ReleaseStripePromotionForEvent(ctx, db.ReleaseStripePromotionForEventParams{TeamID: team, UserID: r.User, EventID: r.Event}); err != nil {
				return err
			}
			if err = recordStripePromotionDenial(ctx, tx, r.Event, team, r.User, "sponsored_onboarding"); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE billing_sponsored_promotion_recovery SET after_evidence='{"unattempted_reservation_released":true}',completed_at=clock_timestamp() WHERE id=$1`, recovery)
			if err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
	}
	grant, err := billing.FindStripeActivationGrant(ctx, client.doForm, team, r.Customer, grantID)
	if err != nil {
		return err
	}
	if grant.LiveMode != *r.Live || (r.Grant != "" && r.Grant != grant.ID) {
		return errors.New("activation grant mode or requested identity differs")
	}
	if len(before) == 0 {
		return errors.New("unused activation evidence is missing")
	}

	voided, err := billing.VoidUnusedStripeActivationGrant(ctx, client.doForm, team, r.Customer, grant.ID)
	if err != nil {
		return err
	}
	if err = q.FinalizeStripePromotion(ctx, db.FinalizeStripePromotionParams{TeamID: team, UserID: r.User, StripeGrantID: grant.ID}); err != nil {
		return err
	}
	after, _ := json.Marshal(voided)
	if _, err = tx.Exec(ctx, `UPDATE billing_sponsored_promotion_recovery SET after_evidence=$2,completed_at=clock_timestamp() WHERE id=$1`, recovery, after); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
