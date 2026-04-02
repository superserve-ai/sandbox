-- 002_add_stopped_status.sql
-- Adds STOPPED state to the VM lifecycle for graceful shutdown without snapshot.

ALTER TYPE vm_status ADD VALUE IF NOT EXISTS 'stopped' AFTER 'sleeping';
