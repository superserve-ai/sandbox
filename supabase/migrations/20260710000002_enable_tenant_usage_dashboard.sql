-- Enable the billing summary/pricing API gate for all teams.
--
-- Billing remains informational only; this change removes the rollout gate so
-- existing teams and newly created teams inherit billing page visibility
-- through the global feature flag default. Teams can still opt out with a
-- per-team override, which the API treats as unavailable.
UPDATE feature_flag
SET enabled = true,
    updated_at = now()
WHERE key = 'tenant_usage_dashboard';

UPDATE team_feature_flag
SET enabled = true,
    updated_at = now()
WHERE key = 'tenant_usage_dashboard';
