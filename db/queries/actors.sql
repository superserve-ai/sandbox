-- Actor runtime queries (Epic 5). The lease operations are the single-writer
-- invariant: each is one atomic UPDATE whose WHERE clause is the compare;
-- "granted" is signalled by whether a row comes back. lease_token only
-- increments on (re)grant — the monotonic fence.

-- name: CreateActorIfAbsent :one
-- Insert-or-nothing on (team_id, name). Returns the new row when this call
-- created it; returns no rows when the Actor already existed (caller then reads
-- it with GetActorByName). Together these give idempotent wake-on-reference.
INSERT INTO actor (team_id, name, template_id, state_id, tier)
VALUES ($1, $2, $3, $4, 'cold')
ON CONFLICT (team_id, name) DO NOTHING
RETURNING *;

-- name: GetActorByName :one
SELECT * FROM actor WHERE team_id = $1 AND name = $2;

-- name: GetActor :one
SELECT * FROM actor WHERE id = $1;

-- name: TryAcquireActorLease :one
-- Atomically grant the lease to $2 (holder) iff it is free, expired
-- (lease_expires_at < $4 = now), or already held by $2. On grant, increment the
-- fence and set expiry to $3 (= now + ttl). Returns the row when granted; no
-- rows when a valid foreign holder blocks it.
UPDATE actor
SET lease_holder = $2,
    lease_token = lease_token + 1,
    lease_expires_at = $3,
    tier = 'live',
    updated_at = now()
WHERE id = $1
  AND (lease_holder IS NULL
       OR lease_holder = ''
       OR lease_expires_at IS NULL
       OR lease_expires_at < $4
       OR lease_holder = $2)
RETURNING *;

-- name: RenewActorLease :one
-- Extend the lease (to $4 = now + ttl) iff $2 still holds it with token $3 and
-- it has not lapsed as of $5 (= now). Does NOT change the token. No rows = the
-- lease was lost (caller is fenced).
UPDATE actor
SET lease_expires_at = $4, updated_at = now()
WHERE id = $1 AND lease_holder = $2 AND lease_token = $3 AND lease_expires_at >= $5
RETURNING *;

-- name: ReleaseActorLease :exec
-- Relinquish iff $2 holds it with token $3 (idempotent otherwise). Enables a
-- clean cross-host handoff without waiting for TTL expiry.
UPDATE actor
SET lease_holder = NULL, lease_expires_at = NULL, updated_at = now()
WHERE id = $1 AND lease_holder = $2 AND lease_token = $3;

-- name: CheckActorFence :one
-- The write-path gate: true iff $2 is the current, unexpired lease token as of
-- $3 (= now). The /state write layer calls this before mutating to enforce
-- fencing-as-backstop.
SELECT EXISTS (
  SELECT 1 FROM actor
  WHERE id = $1 AND lease_token = $2
    AND lease_holder IS NOT NULL AND lease_holder != ''
    AND lease_expires_at >= $3
) AS valid;

-- name: SetActorTier :exec
-- Record hibernation tier + current host (host stickiness for same-host wakes).
UPDATE actor
SET tier = $2, home_host = COALESCE(NULLIF($3, ''), home_host), updated_at = now()
WHERE id = $1;

-- name: CreateActorAlarm :one
INSERT INTO actor_alarm (actor_id, fire_at) VALUES ($1, $2) RETURNING *;

-- name: DueActorAlarms :many
-- Alarms whose fire time has arrived ($1 = now) — the scheduler wakes these
-- Actors. $2 bounds the batch size per tick.
SELECT a.id, a.actor_id, a.fire_at, act.team_id, act.name, act.home_host
FROM actor_alarm a JOIN actor act ON act.id = a.actor_id
WHERE a.fire_at <= $1
ORDER BY a.fire_at
LIMIT $2;

-- name: DeleteActorAlarm :exec
DELETE FROM actor_alarm WHERE id = $1;
