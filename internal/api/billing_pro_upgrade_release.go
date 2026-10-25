package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

type proUpgradeReleaseEvidence struct {
	Upgrade  proUpgrade                     `json:"upgrade"`
	Checkout StripeRetrievedCheckoutSession `json:"checkout"`
}

func (h *Handlers) proUpgradeRelease(ctx context.Context, tx pgx.Tx, c teamPlanChange, current teamPlan, sub invoiceSubscription) (*proUpgradeReleaseEvidence, error) {
	u, err := scanProUpgrade(tx.QueryRow(ctx, `SELECT `+proUpgradeColumns+` FROM billing_pro_upgrade WHERE contract_id=$1 AND team_id=$2 FOR UPDATE`, current.ContractID, c.Team))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u.State != "active" || u.Session == nil || u.Subscription == nil || *u.Subscription != sub.ID || u.Customer != sub.Customer || u.Grant == nil || len(u.Evidence) == 0 {
		return nil, errors.New("the source upgrade is not completely reconciled")
	}
	var params StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(u.Payload, &params); err != nil {
		return nil, err
	}
	if params.OperationID != u.ID || params.Metadata["pro_upgrade_id"] != u.ID.String() || params.ClientReferenceID != c.Team.String() || params.CustomerID != sub.Customer {
		return nil, errors.New("the source upgrade request provenance changed")
	}
	offer, err := frozenProOffer(u.Offer, params)
	if err != nil {
		return nil, err
	}
	offer.Price = params.BasePriceID
	var matches bool
	if err = tx.QueryRow(ctx, `SELECT base_price_id=$2 AND charge_amount_cents=$3 AND charge_interval_months=$4 AND customer_id=$5 AND subscription_id=$6 FROM billing_commercial_contract WHERE id=$1 AND team_id=$7`, current.ContractID, offer.Price, offer.Amount, offer.Months, u.Customer, *u.Subscription, c.Team).Scan(&matches); err != nil {
		return nil, err
	}
	if offer.Price == "" || !matches {
		return nil, errors.New("the source upgrade contract terms changed")
	}
	if _, err = (invoiceBase{Price: offer.Price, Amount: offer.Amount, Months: offer.Months}).stripSubscription(sub); err != nil {
		return nil, err
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return nil, errors.New("the source upgrade requires provider verification")
	}
	session, err := client.RetrieveCheckoutSession(ctx, *u.Session)
	if err != nil {
		return nil, err
	}
	if session.ID != *u.Session || session.Mode != "payment" || session.CustomerID != u.Customer || session.ClientReferenceID != u.Team.String() || session.Status != "complete" || session.Metadata["pro_upgrade_id"] != u.ID.String() {
		return nil, errors.New("the provider payment does not match the source upgrade")
	}
	_, observation, err := client.verifyProUpgradePayment(ctx, u, session, false)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_pro_upgrade SET payment_review_required=false,payment_review_evidence=$2,payment_review_checked_at=clock_timestamp() WHERE id=$1`, u.ID, observation); err != nil {
		return nil, err
	}
	return &proUpgradeReleaseEvidence{Upgrade: u, Checkout: session}, nil
}
