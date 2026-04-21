-- Rename the 'idle' sandbox status to 'paused'. The old name was a holdover
-- from an earlier design where idle-detection was meant to drive auto-pause;
-- the state itself just means "VM stopped, memory+disk snapshotted". Align
-- the name with the actual semantics and with the /pause, /resume endpoints.

ALTER TYPE sandbox_status RENAME VALUE 'idle' TO 'paused';
