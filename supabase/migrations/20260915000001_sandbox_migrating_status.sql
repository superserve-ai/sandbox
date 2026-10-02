-- 'migrating' marks a paused sandbox an operator has claimed to bring up on
-- another host from restored artifacts. Resume claims only 'paused' rows, so
-- the owner cannot start a second copy beside the operator's boot; the row
-- becomes 'active' once that boot is up and returns to 'paused' through the
-- ordinary pause path (or directly, if the boot fails).
ALTER TYPE sandbox_status ADD VALUE IF NOT EXISTS 'migrating';
