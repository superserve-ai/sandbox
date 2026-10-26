-- Existing NULL quotes retain their accepted fee-based bridge credit.
ALTER TABLE billing_pro_upgrade ADD COLUMN bridge_credit_cents bigint CHECK (bridge_credit_cents >= 0);

ALTER TABLE billing_pro_upgrade DROP CONSTRAINT billing_pro_upgrade_check2;
ALTER TABLE billing_pro_upgrade ADD CONSTRAINT billing_pro_upgrade_credit_proof
 CHECK (state NOT IN ('credited','active') OR grant_id IS NOT NULL OR COALESCE(bridge_credit_cents=0,false));

CREATE FUNCTION guard_pro_upgrade_bridge_credit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.bridge_credit_cents IS DISTINCT FROM OLD.bridge_credit_cents THEN
  RAISE EXCEPTION 'accepted upgrade bridge credit is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER pro_upgrade_bridge_credit_guard BEFORE UPDATE ON billing_pro_upgrade
 FOR EACH ROW EXECUTE FUNCTION guard_pro_upgrade_bridge_credit();
REVOKE ALL ON FUNCTION guard_pro_upgrade_bridge_credit() FROM PUBLIC;
