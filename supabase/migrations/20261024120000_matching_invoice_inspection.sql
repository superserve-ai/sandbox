CREATE TABLE billing_matching_invoice_inspection (
 invoice_id text PRIMARY KEY REFERENCES billing_invoice_close(invoice_id),
 failures integer NOT NULL DEFAULT 1 CHECK (failures > 0),
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '5 minutes',
 last_error text
);
ALTER TABLE billing_matching_invoice_inspection ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON billing_matching_invoice_inspection FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN
   EXECUTE format('REVOKE ALL ON billing_matching_invoice_inspection FROM %I',r);
  END IF;
 END LOOP;
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
  GRANT SELECT, INSERT, UPDATE ON billing_matching_invoice_inspection TO service_role;
  CREATE POLICY backend_access ON billing_matching_invoice_inspection TO service_role USING (true) WITH CHECK (true);
 END IF;
END $$;
