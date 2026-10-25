package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

func (h *Handlers) verifyProUpgradePayment(ctx context.Context, conn *pgxpool.Conn, c *stripeHTTPClient, u proUpgrade, s StripeRetrievedCheckoutSession, verifyMethod bool) (string, []byte, error) {
	if u.Session == nil || s.ID != *u.Session || s.CustomerID != u.Customer || s.ClientReferenceID != u.Team.String() || s.Mode != "payment" || s.Metadata["pro_upgrade_id"] != u.ID.String() {
		evidence, _ := json.Marshal(map[string]any{"error": "upgrade payment session association differs", "session": s})
		if _, err := conn.Exec(ctx, `UPDATE billing_pro_upgrade SET payment_review_required=true,payment_review_evidence=$2,payment_review_checked_at=clock_timestamp() WHERE id=$1`, u.ID, evidence); err != nil {
			return "", nil, err
		}
		return "", nil, &proPaymentReviewError{reason: "upgrade payment session association differs", evidence: evidence}
	}
	method, evidence, err := c.verifyProUpgradePayment(ctx, u, s, verifyMethod)
	var review *proPaymentReviewError
	if err != nil && !errors.As(err, &review) {
		return method, evidence, err
	}
	observation := evidence
	if review != nil {
		observation, _ = json.Marshal(map[string]any{"error": err.Error(), "provider": review.evidence, "session": s})
	}
	if _, saveErr := conn.Exec(ctx, `UPDATE billing_pro_upgrade SET payment_review_required=$2,payment_review_evidence=$3,payment_review_checked_at=clock_timestamp() WHERE id=$1`, u.ID, review != nil, observation); saveErr != nil {
		return "", nil, saveErr
	}
	return method, evidence, err
}
