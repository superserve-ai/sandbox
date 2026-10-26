package api

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

var errProviderPairDispatchPending = errors.New("paired grant dispatch requires outcome recovery")

// CheckProviderPairDispatchesResolved is a postcommit ACK gate. The caller must
// first commit permanent denial under the same fence used for admission.
func CheckProviderPairDispatchesResolved(ctx context.Context, q db.DBTX, binding ContractProviderBinding) error {
	saved, err := loadContractProviderBinding(ctx, q, binding.ContractID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(saved, binding) {
		return errors.New("dispatch resolution binding differs")
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	var blocked bool
	err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_provider_pair_dispatch WHERE contract_id=$1 AND (binding<>$2::jsonb OR (resolved_at IS NULL AND rejected_at IS NULL) OR sender_finished_at IS NULL))`, binding.ContractID, raw).Scan(&blocked)
	if err != nil {
		return err
	}
	if blocked {
		return errProviderPairDispatchPending
	}
	return nil
}

// Only this invocation's newly committed admission grants send permission.
// A retry must never inherit a paused sender's permission, even after lease expiry.
func (h *Handlers) admitProviderPairDispatch(ctx context.Context, b ContractProviderBinding, e db.BillingUsageEntitlement, form string) (uuid.UUID, error) {
	id := uuid.New()
	raw, err := json.Marshal(b)
	if err != nil {
		return uuid.Nil, err
	}
	err = h.withProviderPairEntitlementAuthority(ctx, b, func(ctx context.Context, tx pgx.Tx) error {
		current, err := h.DB.WithTx(tx).GetReplayableUsageEntitlement(ctx, db.GetReplayableUsageEntitlementParams{TeamID: b.Identity.TeamID, EntitlementID: e.ID})
		if err != nil {
			return err
		}
		if current.ContractID != b.ContractID || current.IdempotencyKey != e.IdempotencyKey || !jsonBytesEqual(current.RequestPayload, e.RequestPayload) {
			return errors.New("dispatch request changed")
		}
		var inserted uuid.UUID
		err = tx.QueryRow(ctx, `INSERT INTO billing_provider_pair_dispatch(id,entitlement_id,contract_id,team_id,binding,request_payload,request_form,idempotency_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(entitlement_id) DO NOTHING RETURNING id`, id, e.ID, b.ContractID, b.Identity.TeamID, raw, e.RequestPayload, form, e.IdempotencyKey).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			return errProviderPairDispatchPending
		}
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func jsonBytesEqual(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}

// Called only after the sole POST has returned; cancellation cannot suppress this
// durable proof that this executor will never send again. A crash leaves it pending.
func (h *Handlers) finishProviderPairDispatch(ctx context.Context, id uuid.UUID, outcome error) error {
	finished, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	var providerErr *stripeRequestError
	if errors.As(outcome, &providerErr) && providerErr.grantRejection != nil {
		rejection := providerErr.grantRejection
		raw, err := json.Marshal(rejection)
		if err != nil {
			return err
		}
		tag, err := h.Pool.Exec(finished, `UPDATE billing_provider_pair_dispatch SET sender_finished_at=statement_timestamp(),rejected_at=statement_timestamp(),rejection_evidence=$2 WHERE id=$1 AND NOT legacy_untracked AND sender_finished_at IS NULL AND request_form=$3 AND idempotency_key=$4`, id, raw, rejection.form, rejection.IdempotencyKey)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errProviderPairDispatchPending
		}
		return nil
	}
	tag, err := h.Pool.Exec(finished, `UPDATE billing_provider_pair_dispatch SET sender_finished_at=COALESCE(sender_finished_at,clock_timestamp()) WHERE id=$1 AND NOT legacy_untracked`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errProviderPairDispatchPending
	}
	return nil
}

func (h *Handlers) confirmEntitlementGrant(ctx context.Context, c db.BillingCommercialContract, e db.BillingUsageEntitlement, grant entitlementGrant) error {
	raw, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	b, pairErr := loadContractProviderBinding(ctx, h.Pool, c.ID)
	if errors.Is(pairErr, pgx.ErrNoRows) {
		_, err = h.DB.ConfirmUsageEntitlementIssued(ctx, db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant.ID, Evidence: raw})
		return err
	}
	if pairErr != nil {
		return pairErr
	}
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = lockCommercialOfferAccount(ctx, tx, c.TeamID); err != nil {
		return err
	}
	var attempt uuid.UUID
	var finished, resolved bool
	var recorded *string
	binding, _ := json.Marshal(b)
	err = tx.QueryRow(ctx, `SELECT id,sender_finished_at IS NOT NULL,resolved_at IS NOT NULL,grant_id FROM billing_provider_pair_dispatch WHERE entitlement_id=$1 AND contract_id=$2 AND binding=$3::jsonb FOR UPDATE`, e.ID, c.ID, binding).Scan(&attempt, &finished, &resolved, &recorded)
	if err != nil {
		return err
	}
	if !finished {
		return errProviderPairDispatchPending
	}
	if resolved {
		if recorded == nil || *recorded != grant.ID {
			return errors.New("resolved dispatch grant changed")
		}
		return tx.Commit(ctx)
	}
	if _, err = h.DB.WithTx(tx).ConfirmUsageEntitlementIssued(ctx, db.ConfirmUsageEntitlementIssuedParams{TeamID: c.TeamID, EntitlementID: e.ID, GrantID: &grant.ID, Evidence: raw}); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_provider_pair_dispatch SET resolved_at=clock_timestamp(),grant_id=$2 WHERE id=$1`, attempt, grant.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
