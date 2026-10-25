package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func (h *Handlers) ensureProUpgradePaymentMethod(ctx context.Context, conn *pgxpool.Conn, u proUpgrade, p StripeCreateCheckoutSessionParams, c *stripeHTTPClient) (string, error) {
	var id uuid.UUID
	var raw []byte
	var session *string
	err := conn.QueryRow(ctx, `SELECT id,request_payload,session_id FROM billing_pro_upgrade_setup WHERE upgrade_id=$1 AND state<>'expired'`, u.ID).Scan(&id, &raw, &session)
	if errors.Is(err, pgx.ErrNoRows) {
		id = uuid.New()
		expires := h.nowUTC().Add(23 * time.Hour).Truncate(time.Second)
		params := StripeCreateCheckoutSessionParams{SetupOnly: true, CustomerID: u.Customer, ClientReferenceID: u.Team.String(), SuccessURL: p.SuccessURL, CancelURL: p.CancelURL, ExpiresAt: &expires, IdempotencyKey: "pro-upgrade-setup:" + id.String(), Metadata: map[string]string{"pro_upgrade_id": u.ID.String(), "pro_upgrade_setup_id": id.String()}}
		raw, err = json.Marshal(params)
		if err != nil {
			return "", err
		}
		if _, err = conn.Exec(ctx, `INSERT INTO billing_pro_upgrade_setup(id,upgrade_id,request_payload,created_at) VALUES($1,$2,$3,$4)`, id, u.ID, raw, h.nowUTC()); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	var params StripeCreateCheckoutSessionParams
	if err = json.Unmarshal(raw, &params); err != nil {
		return "", err
	}
	if session == nil {
		var inventory struct {
			Data    []StripeRetrievedCheckoutSession `json:"data"`
			HasMore bool                             `json:"has_more"`
		}
		if err = c.doForm(ctx, http.MethodGet, "/v1/checkout/sessions?"+url.Values{"customer": {u.Customer}, "limit": {"100"}}.Encode(), nil, &inventory, ""); err != nil {
			return "", err
		}
		if inventory.HasMore {
			return "", errors.New("upgrade card setup inventory exceeds supported bound")
		}
		for _, s := range inventory.Data {
			if s.Mode == "setup" && s.Metadata["pro_upgrade_setup_id"] == id.String() {
				if session != nil {
					return "", errors.New("ambiguous upgrade card setup sessions")
				}
				session = stringPtr(s.ID)
			}
		}
		if session == nil && !h.nowUTC().Before(*params.ExpiresAt) {
			_, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade_setup SET state='expired' WHERE id=$1`, id)
			return "", err
		}
		if session == nil {
			s, e := c.CreateCheckoutSession(ctx, params)
			if e != nil {
				return "", e
			}
			if s.ID == "" {
				return "", errors.New("missing upgrade card setup session")
			}
			session = &s.ID
		}
		if _, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade_setup SET session_id=$2 WHERE id=$1`, id, *session); err != nil {
			return "", err
		}
	}
	s, err := c.RetrieveCheckoutSession(ctx, *session)
	if err != nil {
		return "", err
	}
	if s.ID != *session || s.CustomerID != u.Customer || s.ClientReferenceID != u.Team.String() || s.Mode != "setup" || s.Metadata["pro_upgrade_id"] != u.ID.String() || s.Metadata["pro_upgrade_setup_id"] != id.String() {
		return "", errors.New("upgrade card setup association differs")
	}
	if s.Status == "expired" {
		_, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade_setup SET state='expired' WHERE id=$1`, id)
		return "", err
	}
	if s.Status != "complete" {
		return "", nil
	}
	if s.SetupIntentID == "" {
		return "", errors.New("upgrade card setup intent missing")
	}
	var intent struct {
		ID, Customer, Status, Usage string
		PaymentMethod               string            `json:"payment_method"`
		Metadata                    map[string]string `json:"metadata"`
	}
	if err = c.doForm(ctx, http.MethodGet, "/v1/setup_intents/"+url.PathEscape(s.SetupIntentID), nil, &intent, ""); err != nil {
		return "", err
	}
	if intent.ID != s.SetupIntentID || intent.Customer != u.Customer || intent.Status != "succeeded" || intent.Usage != "off_session" || intent.Metadata["pro_upgrade_setup_id"] != id.String() || intent.PaymentMethod == "" {
		return "", errors.New("upgrade card setup intent differs")
	}
	var pm struct{ ID, Customer, Type string }
	if err = c.doForm(ctx, http.MethodGet, "/v1/payment_methods/"+url.PathEscape(intent.PaymentMethod), nil, &pm, ""); err != nil {
		return "", err
	}
	if pm.ID != intent.PaymentMethod || pm.Customer != u.Customer || pm.Type != "card" {
		return "", errors.New("upgrade saved card differs")
	}
	_, err = conn.Exec(ctx, `UPDATE billing_pro_upgrade_setup SET state='complete' WHERE id=$1`, id)
	return intent.PaymentMethod, err
}

func (h *Handlers) proUpgradeSetupURL(ctx context.Context, team uuid.UUID) (string, error) {
	var session string
	if err := h.Pool.QueryRow(ctx, `SELECT s.session_id FROM billing_pro_upgrade_setup s JOIN billing_pro_upgrade u ON u.id=s.upgrade_id WHERE u.team_id=$1 AND u.state NOT IN ('expired','ended') AND s.state='open' AND s.session_id IS NOT NULL`, team).Scan(&session); err != nil {
		return "", err
	}
	client, ok := h.Stripe.(*stripeHTTPClient)
	if !ok {
		return "", errors.New("Pro payment verification unavailable")
	}
	s, err := client.RetrieveCheckoutSession(ctx, session)
	if err != nil {
		return "", err
	}
	if s.Status != "open" {
		return "", errors.New("upgrade card setup is awaiting reconciliation")
	}
	return s.URL, nil
}
