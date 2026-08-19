-- Destroy revokes every sandbox, but a revocation is only ever consulted after
-- a secrets JWT authenticates at the proxy, and a JWT is minted only for
-- sandboxes with secret bindings — so most entries revoke a credential that was
-- never issued and then sit for the 90-day JWT lifetime. Destroy now gates on
-- this marker.

BEGIN;

SET LOCAL lock_timeout = '5s';

ALTER TABLE sandbox
    ADD COLUMN IF NOT EXISTS had_secret_bindings boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN sandbox.had_secret_bindings IS
    'True once any secret binding has existed for this sandbox. Never cleared: '
    'a detached or failure-cleared binding may still have had a JWT minted '
    'against it, and destroy gates revocation on this column.';

-- Backfill, or an already-bound sandbox would destroy without a revocation.
-- Detached bindings are caught via revoked_proxy_token, which a detach writes.
UPDATE sandbox s
SET had_secret_bindings = true
WHERE NOT s.had_secret_bindings
  AND (EXISTS (SELECT 1 FROM sandbox_secret ss WHERE ss.sandbox_id = s.id)
       OR EXISTS (SELECT 1 FROM revoked_proxy_token rt WHERE rt.sandbox_id = s.id));

COMMIT;
