-- Per-create capacity reservations: the atomic fence between concurrent
-- control-plane replicas and the once-per-30s pressure report. Admission
-- inserts a row here (ReserveHostCapacity) BEFORE dispatching the create
-- to vmd; every later admission on the same host charges the live rows
-- on top of the newest pressure report, so two replicas racing between
-- reports cannot both spend the same headroom.
--
-- One row per attempted create, keyed by the sandbox id (idempotent:
-- a control-plane retry of the same create cannot double-reserve).
--
-- Rows retire on their own evidence, never by report-generation resets:
--
--   * create failed (vmd rejected, insert failed, handler aborted)
--       -> row deleted immediately, capacity back on the next admission;
--   * create succeeded -> materialized_at stamped when the vmd RPC
--       returned, i.e. when the VM provably entered vmd's instance map.
--       The row keeps charging until a pressure report lands whose
--       reported_at exceeds materialized_at by a slack window — only
--       then is the VM provably inside the report's own counters. A
--       report can be SAMPLED before the VM materialized and ARRIVE
--       after, so retiring on arrival order alone would double-free the
--       capacity; the slack covers that in-flight window. Retiring late
--       merely double-counts a VM for a few seconds (under-places,
--       safe); retiring early over-places — which is the bug this table
--       exists to prevent.
--   * create crashed between reserve and dispatch -> the row stops
--       charging once created_at falls outside the reservation lease
--       (admission ignores it) and is deleted by report-time hygiene.
--
-- Both the charge predicate and the deletes live in db/queries/hosts.sql;
-- the slack and lease constants live with the scheduler.
CREATE TABLE IF NOT EXISTS host_reservation (
    sandbox_id      uuid PRIMARY KEY,
    host_id         text NOT NULL REFERENCES host(id) ON DELETE CASCADE,
    memory_mib      integer NOT NULL,
    vcpus           integer NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    materialized_at timestamptz,

    CONSTRAINT host_reservation_positive CHECK (memory_mib > 0 AND vcpus > 0)
);

-- Admission and report-time hygiene both scan per host.
CREATE INDEX IF NOT EXISTS idx_host_reservation_host ON host_reservation(host_id);

-- Internal table (only the control plane touches it, over the direct DB
-- connection): RLS on with no policies, so the anon/authenticated roles
-- get no access. Same pattern as host_pressure.
ALTER TABLE host_reservation ENABLE ROW LEVEL SECURITY;

-- The admission fence's serialization point. These counters live ON the
-- host_pressure row (not derived from host_reservation at admission
-- time) because that is the only way a single statement can be safe
-- under READ COMMITTED: an UPDATE that blocks on this row re-evaluates
-- its WHERE clause against the COMMITTED version after acquiring the
-- lock, so a replica that loses the race sees the winner's charge. A
-- COUNT over host_reservation cannot do that — the statement's snapshot
-- predates the winner's INSERT, so both replicas would pass the same
-- limit check and over-place. host_reservation remains the identity
-- ledger (idempotency, drain visibility, and the source these counters
-- are recomputed from); these columns are the concurrency fence.
--
-- Ownership: vmd owns every other column here (last-write-wins per
-- report); the control plane owns these three. Each report RECOMPUTES
-- them from the ledger rather than preserving them, so any drift from a
-- missed decrement self-heals within one heartbeat interval.
ALTER TABLE host_pressure
    ADD COLUMN IF NOT EXISTS charged_count      integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS charged_memory_mib bigint  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS charged_vcpus      bigint  NOT NULL DEFAULT 0;
