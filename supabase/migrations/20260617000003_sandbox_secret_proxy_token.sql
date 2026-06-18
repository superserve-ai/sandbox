-- Persist the per-binding proxy (stand-in) token. NOT NULL: every binding is
-- created with a minted token, so the proxy can always revoke one by token.
ALTER TABLE public.sandbox_secret ADD COLUMN IF NOT EXISTS proxy_token text;

-- Backfill any stray rows so the NOT NULL constraint holds.
UPDATE public.sandbox_secret
SET proxy_token = 'ssrv_proxy_' || replace(gen_random_uuid()::text, '-', '')
WHERE proxy_token IS NULL;

ALTER TABLE public.sandbox_secret ALTER COLUMN proxy_token SET NOT NULL;
