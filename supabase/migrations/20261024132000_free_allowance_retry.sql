CREATE TABLE billing_free_allowance_retry (
 team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 attempts bigint NOT NULL DEFAULT 0 CHECK(attempts>=0)
);
CREATE INDEX billing_free_allowance_retry_due ON billing_free_allowance_retry(next_attempt_at,team_id);
ALTER TABLE billing_free_allowance_retry ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_free_allowance_retry FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
  IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('REVOKE ALL ON billing_free_allowance_retry FROM %I',r); END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT,INSERT,UPDATE,DELETE ON billing_free_allowance_retry TO service_role;
  CREATE POLICY allowance_retry_backend ON billing_free_allowance_retry TO service_role USING(true) WITH CHECK(true);
 END IF;
END $$;
