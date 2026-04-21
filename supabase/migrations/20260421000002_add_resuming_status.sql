-- Add 'resuming' to the sandbox_status enum so resume operations can claim
-- a sandbox atomically (paused -> resuming) before calling VMD, preventing
-- concurrent resume requests from racing.
ALTER TYPE sandbox_status ADD VALUE IF NOT EXISTS 'resuming';
