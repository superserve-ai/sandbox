-- Per-team max concurrent template builds. Default 5 — generous enough that
-- normal users never hit it, low enough to bound queue depth and prevent a
-- runaway client from flooding the build pipeline. Raise per-team for
-- enterprise customers without a code change.
ALTER TABLE team ADD COLUMN build_concurrency int NOT NULL DEFAULT 5
    CONSTRAINT team_build_concurrency_positive CHECK (build_concurrency > 0);
