package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var errProEntryClosed = errors.New("new paid entry is closed")

func lockProAdmission(ctx context.Context, tx pgx.Tx, expected pricingPublicState) error {
	if expected.EntryOpen {
		var epoch uuid.UUID
		return tx.QueryRow(ctx, `SELECT billing_assert_pricing_entry_open($1,$2)`, expected.Epoch, expected.Version).Scan(&epoch)
	}
	if !expected.LegacyOpen {
		return errProEntryClosed
	}
	var raw string
	if err := tx.QueryRow(ctx, `SELECT pricing_version FROM billing_pricing_switch WHERE singleton FOR SHARE`).Scan(&raw); err != nil {
		return err
	}
	if raw != "legacy" {
		return errProEntryClosed
	}
	return nil
}

func respondProAdmission(c *gin.Context, err error) {
	var pe *pgconn.PgError
	if errors.Is(err, errProEntryClosed) || (errors.As(err, &pe) && pe.Code == "55000") {
		proConflict(c)
		return
	}
	respondErrorMsg(c, "service_unavailable", "Plan admission requires verification", http.StatusServiceUnavailable)
}

func (h *Handlers) resumeAcceptedProCheckout(c *gin.Context, choice proChoice, actor uuid.UUID, req billingCheckoutSessionRequest) {
	var p StripeCreateCheckoutSessionParams
	if json.Unmarshal(choice.Payload, &p) != nil {
		respondError(c, ErrInternal)
		return
	}
	if choice.Actor != actor || choice.Offer != req.Offer || p.ClientReferenceID != choice.Team.String() || (req.OperationID != uuid.Nil && req.OperationID != p.OperationID) || req.SuccessURL != p.SuccessURL || req.CancelURL != p.CancelURL {
		proConflict(c)
		return
	}
	if _, err := choice.frozenOffer(); err != nil {
		respondError(c, ErrInternal)
		return
	}
	outcome, err := h.reconcileProCheckout(c.Request.Context(), choice.Team, false)
	if err != nil {
		c.JSON(http.StatusAccepted, gin.H{"outcome": "payment_confirmation_pending"})
		return
	}
	if outcome == "active" {
		c.JSON(http.StatusOK, gin.H{"outcome": outcome})
		return
	}
	stored, err := h.getProChoice(c.Request.Context(), choice.Team)
	if err == nil && stored.Session != nil {
		if client, ok := h.Stripe.(*stripeHTTPClient); ok {
			if session, e := client.RetrieveCheckoutSession(c.Request.Context(), *stored.Session); e == nil && session.ID == *stored.Session && session.CustomerID == p.CustomerID && session.ClientReferenceID == choice.Team.String() && session.Status == "open" && session.URL != "" {
				c.JSON(http.StatusOK, billingSessionResponse{URL: session.URL, ID: session.ID})
				return
			}
		}
	}
	c.JSON(http.StatusAccepted, gin.H{"outcome": outcome})
}

func lockProOffer(ctx context.Context, tx pgx.Tx, offer proOffer) error {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM billing_plan_version WHERE family=$1 AND pricing_version=$2 AND state='published' FOR SHARE`, offer.Family, offer.Pricing).Scan(&id)
	if err != nil {
		return err
	}
	if id != offer.VersionID {
		return errOfferUnavailable
	}
	return nil
}
