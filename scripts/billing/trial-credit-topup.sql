-- Adds signup trial credit to explicit trial teams. Dry-run unless -v commit=yes.
-- See event-credit.md for inputs, refusals and evidence.
\set ON_ERROR_STOP on
\if :{?commit}
\else
\set commit no
\endif
SELECT :{?grants} AND :{?label} AS topup_inputs_set \gset
\if :topup_inputs_set
\else
DO $$BEGIN RAISE EXCEPTION 'usage: psql -v grants=<uuid>:<usd>,... -v label=<event> [-v commit=yes] -f trial-credit-topup.sql'; END$$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

CREATE FUNCTION pg_temp.trial_credit_topup(p_teams uuid[], p_amounts numeric[], p_label text)
RETURNS TABLE(team_id uuid, amount_usd numeric, outcome text, grant_id uuid,
 before_remaining_usd numeric, before_state text, before_eligible boolean,
 after_remaining_usd numeric, after_state text, after_eligible boolean, sandbox_admitted boolean)
LANGUAGE plpgsql AS $$
DECLARE i int; t uuid; g team_credit_grant; refusal text; existing uuid;
BEGIN
 IF p_teams IS NULL OR cardinality(p_teams) = 0 OR array_position(p_teams, NULL) IS NOT NULL
  OR cardinality(p_amounts) IS DISTINCT FROM cardinality(p_teams)
  OR (SELECT count(DISTINCT u) FROM unnest(p_teams) u) <> cardinality(p_teams) THEN
  RAISE EXCEPTION 'one team:amount pair per team required';
 END IF;
 IF EXISTS(SELECT 1 FROM unnest(p_amounts) a WHERE a IS NULL OR a = 'NaN' OR a <= 0 OR a > 1000 OR a <> round(a, 2)) THEN
  RAISE EXCEPTION 'each amount must be whole cents, above 0 and at most 1000 USD';
 END IF;
 IF p_label IS NULL OR p_label !~ '^[a-z0-9][a-z0-9._-]{0,99}$' THEN
  RAISE EXCEPTION 'label must be 1-100 lowercase letters, digits, dot, dash or underscore';
 END IF;
 -- Paid activation zeroes signup grants and sets trial_ended_at under the
 -- billing account lock; holding it keeps a grant from landing after that.
 -- Checkout locks the billing account before the team; keep that order.
 PERFORM 1 FROM team_billing_account a WHERE a.team_id = ANY(p_teams) ORDER BY a.team_id FOR UPDATE;
 PERFORM 1 FROM team x WHERE x.id = ANY(p_teams) ORDER BY x.id FOR NO KEY UPDATE;
 FOR i IN SELECT o FROM unnest(p_teams) WITH ORDINALITY u(id, o) ORDER BY u.id LOOP
  t := p_teams[i];
  team_id := t;
  amount_usd := p_amounts[i];
  -- The grant id is the idempotency key: reruns for a team and label find it.
  existing := md5('trial-credit-topup:' || p_label || ':' || t::text)::uuid;
  grant_id := existing;
  SELECT b0.remaining_usd, b0.state, b0.eligible INTO before_remaining_usd, before_state, before_eligible
   FROM get_team_trial_balance(t) b0;
  refusal := CASE
   WHEN NOT EXISTS(SELECT 1 FROM team x WHERE x.id = t) THEN 'refused: team not found'
   WHEN qm_team_managed_billing(t) THEN 'refused: managed billing'
   WHEN EXISTS(SELECT 1 FROM team_plan_assignment p WHERE p.team_id = t AND p.effective_to IS NULL) THEN 'refused: has plan assignment'
   WHEN NOT billing_team_awaiting_plan(t) THEN 'refused: not on new-signup trial path'
   WHEN EXISTS(SELECT 1 FROM team_billing_account a WHERE a.team_id = t AND a.trial_ended_at IS NOT NULL) THEN 'refused: trial ended'
   WHEN EXISTS(SELECT 1 FROM team_signup_trial_denial d WHERE d.team_id = t) THEN 'refused: signup trial denied'
   WHEN EXISTS(SELECT 1 FROM team_signup_trial_provenance v WHERE v.team_id = t AND v.completed_at IS NULL) THEN 'refused: signup trial claim pending'
   WHEN NOT EXISTS(SELECT 1 FROM team_credit_grant c WHERE c.team_id = t AND c.reason = 'signup trial credit' AND c.id <> existing)
    THEN 'refused: no signup trial grant'
  END;
  SELECT * INTO g FROM team_credit_grant c WHERE c.id = existing;
  IF FOUND AND (g.team_id <> t OR g.reason IS DISTINCT FROM 'signup trial credit' OR g.amount_usd <> amount_usd) THEN
   outcome := format('REFUSED: label already granted %s USD, not %s', g.amount_usd, amount_usd);
   RAISE WARNING 'team %: %', t, outcome;
  ELSIF FOUND THEN
   outcome := 'already granted';
  ELSIF refusal IS NOT NULL THEN
   outcome := refusal;
   grant_id := NULL;
  ELSE
   INSERT INTO team_credit_grant(id, team_id, amount_usd, remaining_usd, reason, expires_at)
    VALUES(existing, t, amount_usd, amount_usd, 'signup trial credit', NULL);
   outcome := 'granted';
  END IF;
  IF outcome IN ('granted', 'already granted') AND refusal IS NULL THEN
   -- RefreshTeamTrialEligibility, so a cached false verdict cannot outlive the grant.
   INSERT INTO team_trial_eligibility_cache AS c(team_id, eligible, updated_at)
    VALUES(t, refresh_team_trial_eligibility(t), now())
    ON CONFLICT ON CONSTRAINT team_trial_eligibility_cache_pkey
    DO UPDATE SET eligible = EXCLUDED.eligible, updated_at = EXCLUDED.updated_at;
  END IF;
  SELECT b1.remaining_usd, b1.state, b1.eligible INTO after_remaining_usd, after_state, after_eligible
   FROM get_team_trial_balance(t) b1;
  sandbox_admitted := CASE WHEN EXISTS(SELECT 1 FROM team x WHERE x.id = t) THEN team_sandbox_billing_eligible(t) END;
  RETURN NEXT;
 END LOOP;
END $$;

SELECT * FROM pg_temp.trial_credit_topup(
 (SELECT array_agg(split_part(e, ':', 1)::uuid ORDER BY o) FROM unnest(string_to_array(regexp_replace(:'grants', '\s', '', 'g'), ',')) WITH ORDINALITY u(e, o)),
 (SELECT array_agg(split_part(e, ':', 2)::numeric ORDER BY o) FROM unnest(string_to_array(regexp_replace(:'grants', '\s', '', 'g'), ',')) WITH ORDINALITY u(e, o)),
 :'label');

\if :commit
COMMIT;
\echo 'COMMITTED'
\else
ROLLBACK;
\echo 'DRY RUN: rolled back, nothing committed'
\endif
