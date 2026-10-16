-- Managed teams keep normal usage accounting. Their payer is the QM service,
-- rather than an individual signup trial or Superserve subscription.
CREATE FUNCTION qm_team_managed_billing(p_team_id uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 RETURN EXISTS(SELECT 1 FROM public.qm_organization_teams b
 JOIN public.qm_team_service_authority a USING(namespace,authority_id,home_region)
 WHERE b.team_id=p_team_id AND b.deleted_at IS NULL);
END
$$;
-- This read-only policy predicate reveals no organization or authority identity.
GRANT EXECUTE ON FUNCTION qm_team_managed_billing(uuid) TO PUBLIC;

CREATE OR REPLACE FUNCTION grant_signup_trial_credit() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
 IF NOT public.qm_team_managed_billing(NEW.id) THEN
  INSERT INTO public.team_signup_trial_provenance(team_id) VALUES(NEW.id);
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION initialize_billing_signup_choice() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT public.qm_team_managed_billing(NEW.id) THEN
  INSERT INTO public.billing_signup_choice(team_id) VALUES(NEW.id);
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION protect_qm_managed_billing() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF public.qm_team_managed_billing(NEW.team_id) THEN
  IF TG_TABLE_NAME='team_credit_grant' THEN
   IF NEW.reason='signup trial credit' THEN
    RAISE EXCEPTION 'managed teams do not receive signup credits' USING ERRCODE='23514';
   END IF;
  ELSIF TG_TABLE_NAME='team_billing_account' THEN
   IF NEW.stripe_customer_id IS NOT NULL OR NEW.stripe_subscription_id IS NOT NULL THEN
    RAISE EXCEPTION 'managed teams do not enroll individual subscriptions' USING ERRCODE='23514';
   END IF;
  ELSE
   RAISE EXCEPTION 'managed teams do not enroll individual promotions or checkout' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION protect_qm_managed_billing() FROM PUBLIC;
CREATE TRIGGER qm_managed_credit BEFORE INSERT OR UPDATE ON team_credit_grant
 FOR EACH ROW EXECUTE FUNCTION protect_qm_managed_billing();
CREATE TRIGGER qm_managed_subscription BEFORE INSERT OR UPDATE ON team_billing_account
 FOR EACH ROW EXECUTE FUNCTION protect_qm_managed_billing();
CREATE TRIGGER qm_managed_signup BEFORE INSERT OR UPDATE ON team_signup_trial_provenance
 FOR EACH ROW EXECUTE FUNCTION protect_qm_managed_billing();
CREATE TRIGGER qm_managed_checkout BEFORE INSERT OR UPDATE ON billing_signup_choice
 FOR EACH ROW EXECUTE FUNCTION protect_qm_managed_billing();

CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
WITH account AS (
    SELECT trial_ended_at, stripe_subscription_id, stripe_subscription_status
    FROM team_billing_account WHERE team_id = p_team_id
), grant_balance AS (
    SELECT COALESCE(SUM(remaining_usd) FILTER (WHERE expires_at IS NULL OR expires_at > now()), 0)::numeric AS remaining_usd,
           COUNT(*)::int AS historical_count
    FROM team_credit_grant
    WHERE team_id = p_team_id AND reason = 'signup trial credit'
), denial AS (
    SELECT EXISTS (SELECT 1 FROM team_signup_trial_denial WHERE team_id = p_team_id) AS denied
), pending AS (
    SELECT EXISTS (SELECT 1 FROM team_signup_trial_provenance WHERE team_id = p_team_id AND completed_at IS NULL) AS pending
)
SELECT CASE
    WHEN public.qm_team_managed_billing(p_team_id) THEN true
    WHEN EXISTS(SELECT 1 FROM billing_yc_operation o WHERE o.team_id=p_team_id AND (NOT o.payment_method_ready OR o.payment_method_checked_at IS NULL OR o.payment_method_checked_at<now()-interval '5 minutes' OR o.state NOT IN ('active','renewed') OR (o.state='active' AND o.ends_at<=now()))) THEN false
    WHEN EXISTS(SELECT 1 FROM billing_yc_operation o WHERE o.team_id=p_team_id AND o.state='renewed' AND NOT EXISTS(
        SELECT 1 FROM billing_contract_payment p JOIN billing_pro_payment_verification v ON v.invoice_id=p.invoice_id
        WHERE p.team_id=o.team_id AND p.contract_id=o.renewal_contract_id AND p.service_period_start<=now() AND p.service_period_end>now() AND NOT v.review_required)) THEN false
    WHEN lower(coalesce(account.stripe_subscription_status, '')) IN ('active','trialing','past_due') THEN true
    WHEN account.trial_ended_at IS NOT NULL THEN false
    WHEN denial.denied OR pending.pending THEN false
    WHEN grant_balance.historical_count = 0 AND account.stripe_subscription_id IS NULL THEN true
    ELSE grant_balance.remaining_usd > 0 AND COALESCE(cache.eligible, true)
END
FROM grant_balance CROSS JOIN denial CROSS JOIN pending
LEFT JOIN account ON true
LEFT JOIN team_trial_eligibility_cache cache ON cache.team_id = p_team_id;
$$;
