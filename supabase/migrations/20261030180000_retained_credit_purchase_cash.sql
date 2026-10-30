-- A credit-funded subscription can buy credit without changing plan. Once
-- settled under that subscription, such a purchase is funding like an Auto
-- Reload grant, so it does not hold the first cycle's invoice for review.
CREATE OR REPLACE FUNCTION pro_invoice_cash_source_valid(p_invoice text,p_hash text) RETURNS boolean
LANGUAGE sql STABLE AS $$
 SELECT EXISTS(
 SELECT 1 FROM billing_pro_invoice_cash_authority proof
 JOIN billing_invoice_close close ON close.invoice_id=proof.invoice_id
 JOIN billing_pro_upgrade u ON u.id=proof.upgrade_id
 JOIN billing_commercial_contract contract ON contract.id=proof.contract_id
 JOIN team_plan_assignment assignment ON assignment.id=proof.assignment_id
 WHERE proof.invoice_id=p_invoice AND proof.settlement_hash=p_hash
 AND NOT EXISTS(SELECT 1 FROM billing_prepaid_purchase purchase WHERE purchase.team_id=close.team_id
  AND billing_prepaid_funding_unresolved(purchase,close.period_start,close.period_end)
  AND NOT (billing_assignment_prepaid_funded(assignment) AND purchase.created_at>=assignment.effective_from
   AND (purchase.source='auto_recharge' OR (purchase.source='checkout' AND COALESCE(purchase.plan_snapshot->>'retain'='true',false)))
   AND purchase.payment_state='succeeded' AND purchase.credit_state='issued'))
 AND close.state IN ('verified','released') AND billing_invoice_close_matches(close.team_id,close.period_start,close.period_end)
 AND close.team_id=proof.team_id AND close.plan->>'customer'=proof.customer_id AND close.plan->>'subscription'=proof.subscription_id
 AND close.plan->>'credit_version'='1' AND proof.evidence->'plan'=close.plan AND proof.evidence->'finalized_evidence'=close.finalized_evidence
 AND (close.plan->>'base_cents')::bigint=proof.fee_cents
 AND (close.plan->>'base_period_start')::bigint=extract(epoch FROM close.period_end)::bigint
 AND (close.finalized_evidence->>'credit_applied_cents')::bigint=proof.credit_applied_cents
 AND (close.finalized_evidence->>'net_cents')::bigint=proof.usage_net_cents
 AND (close.finalized_evidence->'invoice'->>'total')::numeric=proof.fee_cents::numeric+proof.usage_net_cents
 AND u.team_id=proof.team_id AND u.customer_id=proof.customer_id AND u.subscription_id=proof.subscription_id
 AND u.contract_id=contract.id AND u.period_start=close.period_start AND u.period_end=close.period_end
 AND u.state IN ('active','ended') AND u.payment_evidence IS NOT NULL AND NOT u.payment_review_required
 AND contract.team_id=proof.team_id AND contract.customer_id=proof.customer_id AND contract.subscription_id=proof.subscription_id
 AND contract.starts_at=close.period_end AND contract.charge_interval_months=1 AND contract.charge_amount_cents=proof.fee_cents
 AND contract.base_price_id=u.request_payload->>'BasePriceID'
 AND contract.charge_amount_cents=(u.request_payload->'PlanTerms'->>'Amount')::bigint
 AND contract.entitlement_amount_cents=(u.request_payload->'PlanTerms'->>'Credit')::bigint
 AND contract.entitlement_anchor=u.anchor
 AND (contract.ends_at IS NULL OR contract.ends_at>=to_timestamp((close.plan->>'base_period_end')::bigint))
 AND assignment.team_id=proof.team_id AND assignment.contract_id=contract.id AND assignment.kind='subscription'
 AND assignment.source='checkout' AND assignment.idempotency_key='checkout:'||contract.id::text
 AND assignment.plan_version_id=(u.request_payload->'PlanTerms'->>'VersionID')::uuid
 AND assignment.effective_from>=close.period_start AND assignment.effective_from<close.period_end
 AND COALESCE(assignment.effective_to,'infinity')>=close.period_end
 AND (proof.evidence->>'paid_assignment_from')::timestamptz=assignment.effective_from
 AND NOT EXISTS(SELECT 1 FROM team_plan_assignment other WHERE other.team_id=proof.team_id AND other.id<>assignment.id
  AND other.effective_from<close.period_end AND COALESCE(other.effective_to,'infinity')>assignment.effective_from))
$$;
