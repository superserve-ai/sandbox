-- sandbox_active_interval records each contiguous period a sandbox spent in
-- the 'active' running state. One row is opened when a sandbox transitions
-- into active (created or resumed) and closed when it leaves active (paused,
-- timeout_paused, deleted, or failed). This is the source of truth for WAU /
-- weekly-active-sandbox reporting; sandbox.status alone is point-in-time and
-- cannot answer "was sandbox X active during week W".
--
-- Closure semantics: ended_at is set EXACTLY ONCE — at the first transition
-- out of active. A later 'deleted' that follows a 'paused' is a no-op on this
-- table because the close-query filters WHERE ended_at IS NULL. This avoids
-- the "paused-for-a-month, then deleted" case inflating the active interval
-- by a month. Time spent in 'paused' / 'pausing' / 'resuming' is, by design,
-- NOT counted as active.

CREATE TABLE sandbox_active_interval (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sandbox_id  uuid NOT NULL REFERENCES sandbox(id) ON DELETE CASCADE,
    team_id     uuid NOT NULL REFERENCES team(id),
    actor_id    uuid REFERENCES profile(id),     -- null when system-initiated (reaper, etc.)
    started_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz,                     -- null = currently active
    end_reason  text,                            -- 'paused' | 'timeout_paused' | 'deleted' | 'failed'

    CONSTRAINT sandbox_active_interval_end_after_start
        CHECK (ended_at IS NULL OR ended_at >= started_at),
    CONSTRAINT sandbox_active_interval_reason_with_end
        CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
    CONSTRAINT sandbox_active_interval_reason_valid
        CHECK (end_reason IS NULL
               OR end_reason IN ('paused', 'timeout_paused', 'deleted', 'failed'))
);

ALTER TABLE public.sandbox_active_interval ENABLE ROW LEVEL SECURITY;

-- Range queries against (started_at, ended_at) for "active in week W".
CREATE INDEX idx_sai_started ON sandbox_active_interval(started_at);
CREATE INDEX idx_sai_team_started ON sandbox_active_interval(team_id, started_at DESC);
CREATE INDEX idx_sai_actor_started ON sandbox_active_interval(actor_id, started_at DESC)
    WHERE actor_id IS NOT NULL;

-- At most one open interval per sandbox at any time.
CREATE UNIQUE INDEX idx_sai_one_open_per_sandbox
    ON sandbox_active_interval(sandbox_id)
    WHERE ended_at IS NULL;

-- Seed an open interval for every sandbox currently in 'active' state at
-- migration time. Without this, live sandboxes at migration time would be
-- invisible to WAU until their next state transition, and their eventual
-- pause/delete would no-op because there's no open interval to close.
--
-- actor_id resolution is best-effort, in priority order:
--   1. the most-recent actor_id from activity for this sandbox (accurate
--      when present — only populated post-ce1fdd1);
--   2. fallback: whoever created the team's most recent API key
--      (heuristic, but typically the team owner — better than NULL since
--      the analytics view drops NULL actors).
-- If both subqueries miss, actor_id stays NULL and the sandbox simply
-- won't count toward WAU until a user action transitions it through a new
-- open/close cycle.
--
-- started_at = now() is honest about what we know ("active as of
-- migration"); pre-migration active duration is genuinely unrecoverable
-- from this table.
INSERT INTO sandbox_active_interval (sandbox_id, team_id, actor_id, started_at)
SELECT
    s.id,
    s.team_id,
    COALESCE(
        (SELECT a.actor_id FROM activity a
         WHERE a.sandbox_id = s.id AND a.actor_id IS NOT NULL
         ORDER BY a.created_at DESC LIMIT 1),
        (SELECT k.created_by FROM api_key k
         WHERE k.team_id = s.team_id AND k.created_by IS NOT NULL
         ORDER BY k.created_at DESC LIMIT 1)
    ),
    now()
FROM sandbox s
WHERE s.status = 'active' AND s.destroyed_at IS NULL;
