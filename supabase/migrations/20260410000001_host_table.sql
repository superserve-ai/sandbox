-- Host table: models bare-metal machines running VMD. One row per host.
-- Multi-host-ready from day one — adding a second host is an ops task
-- (insert a row, deploy VMD), not an engineering project.

CREATE TABLE host (
    id                  text PRIMARY KEY,
    vmd_addr            text NOT NULL,
    proxy_addr          text NOT NULL,
    region              text NOT NULL,
    status              text NOT NULL DEFAULT 'active',
    capacity_memory_mib int  NOT NULL,
    capacity_vcpus      int  NOT NULL,
    last_heartbeat_at   timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT host_status_valid CHECK (status IN ('active', 'draining', 'unhealthy')),
    CONSTRAINT host_capacity_memory_positive CHECK (capacity_memory_mib > 0),
    CONSTRAINT host_capacity_vcpus_positive CHECK (capacity_vcpus > 0)
);

ALTER TABLE public.host ENABLE ROW LEVEL SECURITY;

-- Backfill any sandbox rows with NULL host_id so we can add NOT NULL.
UPDATE sandbox SET host_id = 'default' WHERE host_id IS NULL;

ALTER TABLE sandbox ALTER COLUMN host_id SET NOT NULL;
