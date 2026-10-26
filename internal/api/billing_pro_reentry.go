package api

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/superserve-ai/sandbox/internal/db"
)

func proReleaseForReentry(ctx context.Context, q db.DBTX, team uuid.UUID, customer string) (*uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `SELECT r.id
 FROM team_plan_assignment pa
 JOIN team_plan_change ch ON ch.applied_assignment_id=pa.id AND ch.team_id=pa.team_id AND ch.state IN ('applied','completed')
 JOIN billing_plan_release r ON r.plan_change_id=ch.id AND r.team_id=pa.team_id
 JOIN team_plan_assignment source ON source.id=ch.from_assignment_id AND source.team_id=pa.team_id
 JOIN billing_commercial_contract c ON c.id=source.contract_id AND c.team_id=pa.team_id
 JOIN team_billing_account b ON b.team_id=pa.team_id
 WHERE pa.team_id=$1 AND pa.effective_to IS NULL AND pa.kind IN ('free','prepaid','legacy_payg')
 AND r.customer_id=$2 AND b.stripe_customer_id=r.customer_id AND b.stripe_subscription_id IS NULL
 AND c.status='ended' AND c.customer_id=r.customer_id AND c.subscription_id=r.subscription_id
 AND c.offer_key=r.previous_offer AND r.yc_operation_id IS NULL AND r.provider_status='canceled'
 AND ((r.previous_choice->>'state'='committed' AND r.previous_choice->>'subscription_id'=r.subscription_id
 AND r.previous_choice->>'generation' IS NOT NULL AND r.previous_choice->>'session_id' IS NOT NULL
 AND EXISTS(SELECT 1 FROM billing_contract_payment p WHERE p.contract_id=c.id))
 OR EXISTS(SELECT 1 FROM billing_pro_upgrade u WHERE u.contract_id=c.id AND u.team_id=$1
 AND u.customer_id=r.customer_id AND u.subscription_id=r.subscription_id AND u.state='ended'
 AND (u.grant_id IS NOT NULL OR (u.bridge_credit_cents=0
 AND r.provider_evidence#>>'{pro_upgrade,upgrade,BridgeCredit}'='0')) AND u.payment_evidence IS NOT NULL AND NOT u.payment_review_required
 AND r.provider_evidence->'pro_upgrade'->'upgrade'->>'ID'=u.id::text))
 AND NOT EXISTS(SELECT 1 FROM billing_commercial_contract other WHERE other.team_id=$1 AND other.status<>'ended')
 AND NOT EXISTS(SELECT 1 FROM team_plan_change pending WHERE pending.team_id=$1 AND pending.state IN ('scheduled','applied') AND pending.id<>ch.id)
 ORDER BY r.released_at DESC LIMIT 1`, team, customer).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}
