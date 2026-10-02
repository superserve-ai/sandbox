-- A nullable retained-storage result cannot satisfy the cache's boolean
-- contract.  Fail closed for eligibility while leaving the raw trial balance
-- quantity unavailable to consumers that can surface that distinction.
CREATE OR REPLACE FUNCTION refresh_team_trial_eligibility(p_team_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE((SELECT eligible FROM get_team_trial_balance(p_team_id)), false);
$$;
