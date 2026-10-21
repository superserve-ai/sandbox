package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RevokeProviderPairAuthority runs after the caller locks its permanent regional
// authorization fence, in the same transaction as effective revocation. Existing
// receipts and grants remain history; no provider mutation or new grant occurs.
func RevokeProviderPairAuthority(ctx context.Context, tx pgx.Tx, contract uuid.UUID, identity ProviderPairIdentity) error {
	if tx == nil || contract == uuid.Nil || identity.TeamID == uuid.Nil {
		return errors.New("paired revocation requires its regional fence transaction")
	}
	if err := lockCommercialOfferAccount(ctx, tx, identity.TeamID); err != nil {
		return err
	}
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM billing_commercial_contract WHERE id=$1 AND team_id=$2 FOR UPDATE`, contract, identity.TeamID).Scan(&locked); err != nil {
		return err
	}
	b, err := loadContractProviderBinding(ctx, tx, contract)
	if err != nil {
		return err
	}
	if b.Identity != identity {
		return errors.New("paired revocation differs from finalized authority identity")
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO billing_provider_pair_revocation(contract_id,team_id,identity) VALUES($1,$2,$3) ON CONFLICT(contract_id) DO NOTHING`, contract, identity.TeamID, raw); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_provider_pair_waiver SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE contract_id=$1 AND team_id=$2 AND revoked_at IS NULL`, contract, identity.TeamID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE billing_entitlement_work SET next_check_at=clock_timestamp() WHERE contract_id=$1`, contract)
	return err
}
