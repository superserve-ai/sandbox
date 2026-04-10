-- Enable Row Level Security on all public tables. The control plane
-- connects as service role (BYPASSRLS) so backend access is unaffected.
-- Idempotent.

ALTER TABLE public.profile               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.team_member           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_key               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sandbox               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.snapshot              ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity              ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_code           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.early_access_request  ENABLE ROW LEVEL SECURITY;
