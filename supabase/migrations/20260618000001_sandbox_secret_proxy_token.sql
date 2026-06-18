-- Persist the per-binding proxy (stand-in) token so re-minting a JWT reuses the
-- same token instead of rotating it. Nullable: bindings created before this
-- column keep their token only in their live JWT.
ALTER TABLE public.sandbox_secret ADD COLUMN IF NOT EXISTS proxy_token text;
