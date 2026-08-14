-- Host maintenance window: the next announced restart/termination window for
-- the machine, as reported by the host's own heartbeat from the cloud
-- provider's metadata. NULL means none announced. The control plane drains
-- the host (status -> 'draining', active sandboxes paused) as the window
-- approaches, so announced host restarts stop destroying running sandboxes.
ALTER TABLE host ADD COLUMN IF NOT EXISTS maintenance_window_start timestamptz;
