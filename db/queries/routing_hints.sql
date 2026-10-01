-- name: GetSandboxWithPreviewPolicyForRouting :one
-- GetSandbox plus the effective preview access, so read endpoints return
-- both in one round-trip.
SELECT sqlc.embed(s), statement_timestamp()::timestamptz AS routing_observed_at,
  COALESCE(p.default_access, p.access, 'legacy_public')::text AS access
FROM sandbox s
LEFT JOIN sandbox_preview_policy p ON p.sandbox_id = s.id
WHERE s.id = $1 AND s.team_id = $2 AND s.destroyed_at IS NULL;


-- name: PruneRoutingRevocations :exec
SELECT routing_private.prune_revocations($1::timestamptz);
