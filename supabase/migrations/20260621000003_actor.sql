-- Actor runtime (Epic 5): durable, addressable, single-writer identities on top
-- of sandboxes. One row per (team, name). The lease columns implement the
-- single-writer invariant — each lease transition is a single atomic UPDATE
-- (see db/queries/actors.sql), and lease_token is a monotonic fencing token so
-- a writer that lost the lease is rejected before it can corrupt /state.
CREATE TABLE actor (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id          uuid NOT NULL REFERENCES team(id) ON DELETE CASCADE,
    name             text NOT NULL,
    template_id      uuid REFERENCES template(id),
    -- state_id is the durable /state provider key (state.Provider identity):
    -- state is addressed by this, not by VM instance, so it follows the Actor
    -- across hosts.
    state_id         text,
    home_host        text,                       -- last/current host (stickiness)
    tier             text NOT NULL DEFAULT 'cold', -- cold|live|tier1|tier2|tier3

    -- Single-writer lease. lease_token only ever increments (the fence).
    lease_holder     text,
    lease_token      bigint NOT NULL DEFAULT 0,
    lease_expires_at timestamptz,

    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    UNIQUE (team_id, name)
);

-- Per-Actor alarms (Epic 5.5): wake the Actor at fire_at. Indexed by due time
-- so the scheduler can scan "what's due now" cheaply (extends the reaper).
CREATE TABLE actor_alarm (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   uuid NOT NULL REFERENCES actor(id) ON DELETE CASCADE,
    fire_at    timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX actor_alarm_due_idx ON actor_alarm (fire_at);
