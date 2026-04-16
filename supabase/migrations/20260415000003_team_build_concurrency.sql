-- Per-team max concurrent template builds. Overridable per team.
ALTER TABLE team ADD COLUMN build_concurrency int NOT NULL DEFAULT 5
    CONSTRAINT team_build_concurrency_positive CHECK (build_concurrency > 0);
