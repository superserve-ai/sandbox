-- A periodic sweep that every replica runs independently does the same
-- work N times and, with its page position held in process memory, never
-- shares progress or keeps it across a restart. One row per sweep carries
-- both: the lease that elects a single runner, and the cursor that runner
-- advances, so a handover resumes where the last holder stopped.
CREATE TABLE IF NOT EXISTS sweep_lease (
    name         text PRIMARY KEY,
    locked_by    text NOT NULL,
    locked_until timestamptz NOT NULL,
    cursor_id    uuid,
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sweep_lease_name_nonempty CHECK (name <> ''),
    CONSTRAINT sweep_lease_locked_by_nonempty CHECK (locked_by <> '')
);

ALTER TABLE public.sweep_lease ENABLE ROW LEVEL SECURITY;
