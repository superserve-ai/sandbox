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

-- The marker is stamped by a trigger, not by the writing statement, so it holds
-- for every writer: a previous API revision still serving during a rolling
-- deploy, a rolled-back revision, or manual SQL. An application-side stamp would
-- be a convention only the current code follows, and a binding written without
-- it would let destroy skip the revocation for a credential that was issued.
-- Statement-level over a transition table, not per row: a create with secrets
-- writes up to the binding cap in one statement, and a per-row trigger would
-- probe the parent once per binding inside the synchronous create.
CREATE OR REPLACE FUNCTION sandbox_mark_secret_bound() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
  UPDATE sandbox s SET had_secret_bindings = true
  WHERE s.id IN (SELECT DISTINCT i.sandbox_id FROM inserted i)
    AND s.had_secret_bindings IS DISTINCT FROM true;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS sandbox_secret_marks_bound ON sandbox_secret;
CREATE TRIGGER sandbox_secret_marks_bound
    AFTER INSERT ON sandbox_secret
    REFERENCING NEW TABLE AS inserted
    FOR EACH STATEMENT EXECUTE FUNCTION sandbox_mark_secret_bound();

COMMIT;
