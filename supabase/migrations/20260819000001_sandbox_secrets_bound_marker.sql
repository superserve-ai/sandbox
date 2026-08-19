-- Destroy revokes every sandbox, but a revocation is only ever consulted after
-- a secrets JWT authenticates at the proxy, and a JWT is minted only for
-- sandboxes with secret bindings — so most entries revoke a credential that was
-- never issued and then sit for the 90-day JWT lifetime. Destroy now gates on
-- this marker.
--
-- Nullable with no default, and no backfill: NULL means the row predates the
-- marker, where binding history cannot be reconstructed (the mark-failed paths
-- clear bindings without leaving a revoked_proxy_token). Destroy treats NULL as
-- "may have had a credential" and still revokes, so no existing sandbox loses
-- its revocation. Both properties matter: guessing would leave a leaked JWT
-- valid, and a backfilling UPDATE would hold this statement's ACCESS EXCLUSIVE
-- lock across the whole table.

BEGIN;

SET LOCAL lock_timeout = '5s';

ALTER TABLE sandbox
    ADD COLUMN IF NOT EXISTS had_secret_bindings boolean;

COMMENT ON COLUMN sandbox.had_secret_bindings IS
    'True once any secret binding has existed for this sandbox; false when the '
    'sandbox was created without one; NULL for rows predating the column. Never '
    'cleared — a detached or failure-cleared binding may still have had a JWT '
    'minted against it. Destroy revokes unless this is false.';

COMMIT;
