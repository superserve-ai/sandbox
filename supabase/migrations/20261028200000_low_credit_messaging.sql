-- Each warning lifecycle sends at most one email. A trial awaiting its first
-- plan gets one when the trial ends. A prepaid-funded subscription re-arms
-- whenever a period grant or top-off is issued, in the order they land rather
-- than the order they were created. Legacy signup trials keep their existing
-- keys.
CREATE OR REPLACE FUNCTION trial_credit_warning_lifecycle(p_team_id uuid)
RETURNS text LANGUAGE sql STABLE AS $$
 SELECT CASE
  WHEN a.id IS NOT NULL THEN 'prepaid:'||md5(concat_ws(',',a.id,
   (SELECT e.id FROM billing_usage_entitlement e WHERE e.team_id=p_team_id AND e.contract_id=a.contract_id AND e.state='issued'
     ORDER BY e.issued_at DESC,e.id DESC LIMIT 1),
   (SELECT p.id FROM billing_prepaid_purchase p WHERE p.team_id=p_team_id AND p.credit_state='issued'
     ORDER BY p.credited_at DESC,p.id DESC LIMIT 1)))
  WHEN billing_team_awaiting_plan(p_team_id) THEN 'trial:'||grants.key
  ELSE grants.key END
 FROM (SELECT md5(COALESCE(string_agg(id::text,',' ORDER BY id),'')) AS key
   FROM team_credit_grant WHERE team_id=p_team_id AND reason='signup trial credit') grants
 LEFT JOIN team_plan_assignment a ON a.team_id=p_team_id AND a.effective_to IS NULL
  AND a.kind='subscription' AND billing_assignment_prepaid_funded(a);
$$;

-- A prepaid-funded subscription's balance below low_credit_warning_cents is
-- shown and emailed as too low. low_credit_grant_grace is how long a period
-- may run without its included grant before that messaging stops waiting for
-- it: a renewal grant lands only after the closing invoice is finalized, paid
-- and its webhook processed, so it is a backstop for renewals that stall
-- without failing. Both are configuration.
ALTER TABLE billing_funding_policy
 ADD COLUMN low_credit_grant_grace interval NOT NULL DEFAULT interval '24 hours' CHECK(low_credit_grant_grace>interval '0'),
 ADD COLUMN low_credit_warning_cents bigint NOT NULL DEFAULT 100 CHECK(low_credit_warning_cents>0);

-- A prepaid-funded balance is worth warning about once it was read after the
-- period's included grant and after every top-off paid since: the grant lands
-- after checkout and after each renewal invoice is paid, so a reading in that
-- gap shows only leftover credit. A period whose grant has not landed is
-- warned on its current balance once the renewal invoice's collection has
-- failed, or after the grace.
CREATE FUNCTION billing_prepaid_warning_balance_ready(p_team uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public,pg_temp AS $$
 WITH current AS (
  SELECT a.contract_id, a.effective_from, f.credit_checked_at AS checked
  FROM team_plan_assignment a JOIN billing_funding_account f ON f.team_id=a.team_id
  WHERE a.team_id=p_team AND a.effective_to IS NULL AND a.kind='subscription' AND billing_assignment_prepaid_funded(a)
   AND f.observe AND f.observed_generation=f.generation AND f.credit_valid_until>now()
 ), grants AS (
  SELECT e.period_start, e.period_end, e.issued_at AS landed FROM billing_usage_entitlement e, current
  WHERE e.team_id=p_team AND e.contract_id=current.contract_id AND e.state='issued'
  UNION ALL
  SELECT u.period_start, u.period_end, c.observed_at FROM billing_pro_upgrade u
  JOIN billing_provider_credit c ON c.customer_id=u.customer_id AND c.grant_id=u.grant_id, current
  WHERE u.team_id=p_team AND u.contract_id=current.contract_id AND u.state IN ('credited','active')
 ), period AS (
  SELECT current.checked,
   EXISTS(SELECT 1 FROM grants g WHERE g.period_start<=now() AND g.period_end>now()) AS granted,
   GREATEST(current.effective_from,(SELECT max(g.period_end) FROM grants g WHERE g.period_end<=now())) AS started
  FROM current
 )
 SELECT COALESCE(bool_or(
   NOT EXISTS(SELECT 1 FROM grants g WHERE g.landed>=period.checked)
   AND NOT EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.team_id=p_team AND e.state='issued' AND e.issued_at>=period.checked)
   AND NOT EXISTS(SELECT 1 FROM billing_prepaid_purchase p WHERE p.team_id=p_team AND p.payment_state='succeeded'
    AND (p.credit_state<>'issued' OR p.credited_at>=period.checked) AND NOT billing_prepaid_credit_withheld(p))
   AND (period.granted
    OR EXISTS(SELECT 1 FROM billing_invoice_close c JOIN billing_invoice_collection j ON j.invoice_id=c.invoice_id
     WHERE c.team_id=p_team AND c.period_end=period.started AND j.state IN ('requires_action','requires_payment_method','review_required','uncollectible','void'))
    OR period.started+(SELECT low_credit_grant_grace FROM billing_funding_policy WHERE singleton)<period.checked)),false)
 FROM period;
$$;

DO $$ DECLARE r text; BEGIN
 REVOKE ALL ON FUNCTION billing_prepaid_warning_balance_ready(uuid) FROM PUBLIC;
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON FUNCTION billing_prepaid_warning_balance_ready(uuid) FROM %I',r); END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT EXECUTE ON FUNCTION billing_prepaid_warning_balance_ready(uuid) TO service_role;
 END IF;
END $$;
