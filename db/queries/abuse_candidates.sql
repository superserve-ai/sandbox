-- name: ListComputePauseCandidates :many
-- Pages one team's live candidates in key order.
SELECT team_id, id, status
FROM sandbox
WHERE team_id = sqlc.arg(team_id)
  AND destroyed_at IS NULL
  AND status IN ('active', 'starting', 'resuming')
  AND id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(page_limit);
