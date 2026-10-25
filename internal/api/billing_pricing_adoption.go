package api

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type pricingPublicState struct {
	Version    string
	EntryOpen  bool
	LegacyOpen bool
	Epoch      uuid.UUID
}

func (h *Handlers) publicPricingState(ctx context.Context) (pricingPublicState, error) {
	state := pricingPublicState{Version: "legacy"}
	var available bool
	if err := h.Pool.QueryRow(ctx, `SELECT to_regprocedure('billing_pricing_public_state()') IS NOT NULL`).Scan(&available); err != nil {
		return state, err
	}
	if !available {
		err := h.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT pricing_version='legacy' FROM billing_pricing_switch WHERE singleton),false)`).Scan(&state.LegacyOpen)
		return state, err
	}
	err := h.Pool.QueryRow(ctx, `SELECT pricing_version,entry_open,epoch,COALESCE((SELECT pricing_version='legacy' FROM billing_pricing_switch WHERE singleton),false) FROM billing_pricing_public_state()`).Scan(&state.Version, &state.EntryOpen, &state.Epoch, &state.LegacyOpen)
	return state, err
}

func lockPricingEntry(ctx context.Context, tx pgx.Tx) (string, bool, error) {
	var available bool
	if err := tx.QueryRow(ctx, `SELECT to_regprocedure('billing_lock_pricing_public_state()') IS NOT NULL`).Scan(&available); err != nil {
		return "", false, err
	}
	var open bool
	if available {
		if err := tx.QueryRow(ctx, `SELECT entry_open FROM billing_lock_pricing_public_state()`).Scan(&open); err != nil {
			return "", false, err
		}
	}
	var raw string
	if err := tx.QueryRow(ctx, `SELECT pricing_version FROM billing_pricing_switch WHERE singleton`).Scan(&raw); err != nil {
		return "", false, err
	}
	return raw, open, nil
}
