-- Quota alerts now fan out to more than one delivery channel (a Slack webhook and
-- an email). The de-dup row becomes per (team, resource, channel) so a transient
-- failure on one channel retries without re-sending the others, and so each
-- channel is claimed independently across replicas. Existing rows predate the
-- split and are Slack alerts, hence the 'slack' default.
--
-- Apply before rolling out the matching build: the PK widens to include channel,
-- so a still-running previous build's `ON CONFLICT (team_id, quota_type)` stops
-- matching a unique index and its watcher logs a benign claim error until the
-- rollout finishes (a new replica covers the tick).

BEGIN;

ALTER TABLE quota_alert_state
  ADD COLUMN IF NOT EXISTS channel text NOT NULL DEFAULT 'slack';

-- Repoint the primary key to include channel. Idempotent: only swaps the PK when
-- the current one doesn't already cover channel.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'quota_alert_state'::regclass
      AND contype = 'p'
      AND pg_get_constraintdef(oid) LIKE '%channel%'
  ) THEN
    ALTER TABLE quota_alert_state DROP CONSTRAINT IF EXISTS quota_alert_state_pkey;
    ALTER TABLE quota_alert_state ADD PRIMARY KEY (team_id, quota_type, channel);
  END IF;
END $$;

COMMIT;
