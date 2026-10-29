SELECT COALESCE(json_agg(json_build_object(
  'team_id', a.team_id, 'trial_ended_at', a.trial_ended_at,
  'trial_grants_usd', pool.grant_usd::text, 'consumed_usd', cost.consumed::text,
  'label_grant_usd', (SELECT g.amount_usd::text FROM team_credit_grant g
    WHERE :'label' <> '' AND g.team_id = a.team_id AND g.reason = 'signup trial credit'
      AND g.id = md5('trial-credit-topup:' || :'label' || ':' || a.team_id::text)::uuid),
  'plan_key', p.plan_key, 'kind', p.kind, 'family', COALESCE(p.terms->>'family', v.family),
  'customer', a.stripe_customer_id, 'subscription_status', a.stripe_subscription_status) ORDER BY a.team_id), '[]')
FROM team_billing_account a
CROSS JOIN LATERAL (
  SELECT COALESCE(sum(g.amount_usd), 0)::numeric AS grant_usd, min(g.created_at) AS started, count(*) AS grants
  FROM team_credit_grant g
  WHERE g.team_id = a.team_id AND g.reason = 'signup trial credit' AND g.created_at <= a.trial_ended_at
    AND (g.expires_at IS NULL OR g.expires_at > a.trial_ended_at)) pool
CROSS JOIN LATERAL (
  SELECT COALESCE(sum(GREATEST(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at, a.trial_ended_at), a.trial_ended_at)
           - GREATEST(i.started_at, pool.started))), 0) * i.vcpu_count), 0)::numeric AS cpu,
         COALESCE(sum(GREATEST(EXTRACT(EPOCH FROM (LEAST(COALESCE(i.ended_at, a.trial_ended_at), a.trial_ended_at)
           - GREATEST(i.started_at, pool.started))), 0) * i.memory_mib / 1024.0), 0)::numeric AS memory
  FROM sandbox_compute_billing_interval i
  WHERE i.team_id = a.team_id AND i.started_at < a.trial_ended_at
    AND COALESCE(i.ended_at, a.trial_ended_at) > pool.started) usage
CROSS JOIN LATERAL (
  SELECT COALESCE(max(r.price_usd) FILTER (WHERE r.resource = 'vcpu'), 0)::numeric AS cpu,
         COALESCE(max(r.price_usd) FILTER (WHERE r.resource = 'memory_gib'), 0)::numeric AS memory,
         COALESCE(max(r.price_usd) FILTER (WHERE r.resource = 'storage_gib'), 0)::numeric AS storage
  FROM (SELECT r.*, row_number() OVER (PARTITION BY r.resource, r.unit
          ORDER BY r.effective_from DESC, r.created_at DESC, r.id DESC) AS rank
        FROM pricing_rate r
        WHERE r.plan_key = COALESCE((SELECT tpp.plan_key FROM team_pricing_plan tpp
            WHERE tpp.team_id = a.team_id AND tpp.effective_from <= a.trial_ended_at
              AND (tpp.effective_to IS NULL OR tpp.effective_to > a.trial_ended_at)
            ORDER BY tpp.effective_from DESC LIMIT 1), 'payg')
          AND r.unit = 'second' AND r.effective_from <= a.trial_ended_at
          AND (r.effective_to IS NULL OR r.effective_to > a.trial_ended_at)) r
  WHERE r.rank = 1) rate
CROSS JOIN LATERAL (
  SELECT round((usage.cpu * rate.cpu + usage.memory * rate.memory
    + CASE WHEN storage_billing_activated(a.team_id, a.trial_ended_at)
           THEN billable_storage_mib_seconds(a.team_id, pool.started, a.trial_ended_at) / 1024.0 * rate.storage
           ELSE 0 END)::numeric, 6) AS consumed) cost
LEFT JOIN team_plan_assignment p ON p.team_id = a.team_id AND p.effective_to IS NULL
LEFT JOIN billing_plan_version v ON v.id = p.plan_version_id
WHERE a.trial_ended_at IS NOT NULL AND pool.grants > 0
  AND (:'team' = '' OR a.team_id::text = :'team');
