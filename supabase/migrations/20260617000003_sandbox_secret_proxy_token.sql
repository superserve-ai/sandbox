-- Persist the per-binding proxy (stand-in) token. Nullable: rows created before
-- this kept their token only in the live JWT.

ALTER TABLE public.sandbox_secret ADD COLUMN IF NOT EXISTS proxy_token text;
