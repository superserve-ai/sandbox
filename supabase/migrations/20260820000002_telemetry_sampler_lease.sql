-- Single-writer election for control-plane telemetry samplers. The
-- fleet-scan samplers (backup coverage first) must run on exactly one
-- replica per cell: every replica running them would multiply identical
-- database load and publish competing copies of every gauge series.
-- Advisory locks cannot elect here because the control plane reaches
-- Postgres through transaction pooling, where the backend that took a
-- session lock and the backend that runs the next statement need not be
-- the same one; a TTL lease row (the billing rollup scheduler's
-- pattern) works through any pooler. One row per sampler name: a claim
-- succeeds when the lease is expired or already held by the claimant,
-- so the leader renews in place and a dead leader is replaced as soon
-- as its lease lapses.

CREATE TABLE telemetry_sampler_lease (
    name          text PRIMARY KEY,
    locked_by     text NOT NULL,
    locked_until  timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT telemetry_sampler_lease_name_nonempty CHECK (name <> ''),
    CONSTRAINT telemetry_sampler_lease_locked_by_nonempty CHECK (locked_by <> '')
);

ALTER TABLE public.telemetry_sampler_lease ENABLE ROW LEVEL SECURITY;
