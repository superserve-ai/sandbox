-- identity_bound: set once a host id's holder has ever proven a complete
-- self-description (self-registration, an address reclaim, or an explicit
-- opt-in heartbeat with a matching address). Once bound, description-less
-- heartbeats for the id are rejected: the shared internal token cannot
-- distinguish daemons, so after a reclaim the previous holder's legacy
-- heartbeats must not keep refreshing liveness or capabilities on a row
-- that now belongs to another machine. Deliberately independent of status —
-- the marker survives activation and health transitions.
ALTER TABLE host ADD COLUMN IF NOT EXISTS identity_bound boolean NOT NULL DEFAULT false;
