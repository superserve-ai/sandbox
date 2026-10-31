-- A prepaid-funded subscription (Developer) is funded by a credit grant that
-- expires when its period ends. The next period's grant is issued only after
-- the prior period's closing invoice is released and the renewal is paid, so
-- each renewal leaves a gap with no covering grant. A first paid month bought
-- through checkout is funded by its bridge grant instead, and its contract
-- stays pending until that renewal is paid. The sponsored roll grace already
-- covers sponsored teams; this widens it to prepaid-funded subscriptions, both
-- for a later renewal and for the first one.
--
-- The grace keeps the team eligible for six hours after the period ends, and
-- until a successful credit read after the next grant was issued. It ends early
-- on debt, on withheld unpaid-invoice evidence, when the contract ends with
-- that period, or once the team is no longer prepaid-funded. A withheld row
-- written only for a platform failure does not end it.
--
-- Usage in the grace is billed on the new period's invoice, which the next
-- grant applies to; the invoice close verifies what Stripe applied.

CREATE OR REPLACE FUNCTION billing_renewal_roll_grace(p_team_id uuid,p_credit_checked_at timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
 WITH roll AS (
  SELECT c.id contract_id, e.period_end
  FROM billing_commercial_contract c
  JOIN team_billing_account a ON a.team_id=c.team_id AND a.stripe_customer_id=c.customer_id AND a.stripe_subscription_id=c.subscription_id
  JOIN billing_usage_entitlement e ON e.team_id=c.team_id AND e.contract_id=c.id AND e.state='issued'
  WHERE c.team_id=p_team_id AND c.status='active'
   AND CASE WHEN e.sponsorship_id IS NULL
    THEN EXISTS(SELECT 1 FROM billing_funding_account f WHERE f.team_id=p_team_id AND f.prepaid)
    ELSE EXISTS(SELECT 1 FROM billing_sponsored_operation o WHERE o.id=e.sponsorship_id AND o.contract_id=c.id AND o.state='active' AND o.revoked_at IS NULL) END
  UNION ALL
  SELECT c.id, u.period_end
  FROM billing_pro_upgrade u
  JOIN billing_commercial_contract c ON c.id=u.contract_id AND c.team_id=u.team_id AND c.status IN ('pending','active') AND c.starts_at=u.period_end
  JOIN team_billing_account a ON a.team_id=c.team_id AND a.stripe_customer_id=c.customer_id AND a.stripe_subscription_id=c.subscription_id
  WHERE u.team_id=p_team_id AND u.state='active' AND u.request_payload->>'FirstPaidProCycle'='true'
   AND EXISTS(SELECT 1 FROM billing_funding_account f WHERE f.team_id=p_team_id AND f.prepaid)
 )
 SELECT EXISTS(SELECT 1 FROM roll r JOIN billing_commercial_contract c ON c.id=r.contract_id
  WHERE r.period_end<=now() AND r.period_end>now()-interval '6 hours'
   AND (c.ends_at IS NULL OR c.ends_at>r.period_end)
   AND NOT EXISTS(SELECT 1 FROM billing_usage_entitlement n WHERE n.team_id=c.team_id AND n.contract_id=c.id AND n.period_start=r.period_end AND n.state='issued' AND n.issued_at<=p_credit_checked_at)
   AND NOT EXISTS(SELECT 1 FROM billing_entitlement_debt d WHERE d.contract_id=c.id AND d.period_start>=r.period_end)
   AND NOT EXISTS(SELECT 1 FROM billing_entitlement_withheld w WHERE w.contract_id=c.id AND w.period_start>=r.period_end AND w.evidence ? 'unpaid_invoice'));
$$;

CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE
 WHEN EXISTS(SELECT 1 FROM abuse_restrictions r WHERE r.subject_team_id=p_team_id AND r.released_at IS NULL
 AND (r.expires_at IS NULL OR r.expires_at>now()) AND r.action IN ('create','resume')) THEN false
 WHEN qm_team_managed_billing(p_team_id) THEN true
 WHEN billing_team_awaiting_plan(p_team_id) THEN billing_team_trial_active(p_team_id)
 WHEN EXISTS(SELECT 1 FROM billing_free_plan(p_team_id)) THEN NOT billing_free_allowance_blocked(p_team_id)
 WHEN NOT COALESCE(f.enforce,false) THEN team_sandbox_billing_eligible_legacy(p_team_id)
 WHEN billing_renewal_roll_grace(p_team_id,CASE WHEN f.observed_generation IS NOT DISTINCT FROM f.generation THEN f.credit_checked_at END) THEN true
 WHEN f.observed_generation IS DISTINCT FROM f.generation
 OR (f.customer_id,f.subscription_id) IS DISTINCT FROM (a.stripe_customer_id,a.stripe_subscription_id) THEN false
 WHEN f.prepaid THEN f.credit_usd>0 AND f.credit_valid_until>now()
 WHEN f.credit_usd>0 AND f.credit_valid_until>now() AND (
 NOT EXISTS(SELECT 1 FROM billing_sponsored_operation WHERE team_id=p_team_id AND state NOT IN ('revoked','expired'))
 OR EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.team_id=p_team_id AND e.sponsorship_id IS NOT NULL AND e.state='issued' AND e.period_start<=now() AND e.period_end>now())) THEN true
 ELSE COALESCE(f.payment_method_ready AND f.collection_ready AND f.provider_valid_until>now()
 AND (billing_funding_fingerprint(p_team_id)='clear' OR f.cash_collected),false) END
 FROM (SELECT p_team_id team_id) t LEFT JOIN billing_funding_account f USING(team_id)
 LEFT JOIN team_billing_account a USING(team_id);
$$;

DROP FUNCTION billing_sponsored_roll_grace(uuid,timestamptz);
