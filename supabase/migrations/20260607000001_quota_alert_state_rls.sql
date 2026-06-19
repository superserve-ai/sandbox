-- Internal table (only the quota watcher touches it): RLS on, no policies, so
-- the anon/authenticated roles get no access. Idempotent if already enabled.
ALTER TABLE public.quota_alert_state ENABLE ROW LEVEL SECURITY;
