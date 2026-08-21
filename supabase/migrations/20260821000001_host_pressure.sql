-- Live capacity pressure per host, reported by vmd after each successful
-- heartbeat via PUT /internal/hosts/:id/pressure. One row per host,
-- last-write-wins: each report OVERWRITES the previous one wholesale,
-- which is the reconciliation contract — any control-plane-side
-- reservation (admission control, later work) is an ephemeral delta on
-- top of the newest report, valid only when created AFTER reported_at,
-- so drift between reserved and real state self-corrects within one
-- heartbeat interval.
--
-- Deliberately a separate table, not columns on host: host is stable
-- identity an operator manages; this is ephemeral telemetry a machine
-- overwrites every 30 seconds, absent entirely for hosts that predate
-- publication, and safe to delete whenever its host identity is
-- reclaimed (the old machine's numbers mean nothing for the new one).
--
-- reported_at is CONTROL-PLANE DATABASE time, never the vmd clock:
-- freshness comparisons (staleness gates, reservation ordering) must
-- all run on one clock.
--
-- The two limit pairs are kept distinct on purpose:
--   max_network_slots  operator's schedulable slot limit (0 = unset)
--   net_slot_ceiling   kernel/IP-scheme hard bound on prepared slots
--   max_sandboxes      operator's sandbox admission limit (0 = unset)
-- Collapsing operator limits into technical ceilings would make "can I
-- place here" and "can this host prepare another slot" indistinguishable.
CREATE TABLE host_pressure (
    host_id                 text PRIMARY KEY REFERENCES host(id) ON DELETE CASCADE,
    running_sandboxes       int NOT NULL,
    provisioning_sandboxes  int NOT NULL,
    paused_sandboxes        int NOT NULL,
    allocated_memory_mib    bigint NOT NULL,
    allocated_vcpus         bigint NOT NULL,
    used_net_slots          int NOT NULL,
    provisioning_net_slots  int NOT NULL,
    warm_net_slots          int NOT NULL,
    net_slot_ceiling        int NOT NULL,
    max_network_slots       int NOT NULL DEFAULT 0,
    max_sandboxes           int NOT NULL DEFAULT 0,
    reported_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT host_pressure_non_negative CHECK (
        running_sandboxes >= 0 AND provisioning_sandboxes >= 0
        AND paused_sandboxes >= 0 AND allocated_memory_mib >= 0
        AND allocated_vcpus >= 0 AND used_net_slots >= 0
        AND provisioning_net_slots >= 0 AND warm_net_slots >= 0
        AND net_slot_ceiling >= 0 AND max_network_slots >= 0
        AND max_sandboxes >= 0
    )
);

-- Internal table (only the control plane touches it, over the direct DB
-- connection): RLS on with no policies, so the anon/authenticated roles
-- get no access. Same pattern as backup_generation.
ALTER TABLE host_pressure ENABLE ROW LEVEL SECURITY;
