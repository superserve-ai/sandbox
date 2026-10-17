-- Regional billing database only. No approval or financial history is rewritten.
-- A wake racing a leased worker must survive that worker's acknowledgement.
ALTER TABLE billing_entitlement_work ADD COLUMN wake_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE billing_entitlement_work ADD COLUMN lease_generation bigint NOT NULL DEFAULT 0;
CREATE FUNCTION guard_entitlement_wakeup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.lease_token IS NOT NULL AND NEW.lease_token IS DISTINCT FROM OLD.lease_token THEN
  NEW.lease_generation := OLD.wake_generation;
 ELSIF NEW.lease_token IS NULL AND OLD.lease_token IS NOT NULL AND OLD.lease_generation<>OLD.wake_generation THEN
  NEW.next_check_at := least(NEW.next_check_at,clock_timestamp());
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER billing_entitlement_wakeup_guard BEFORE UPDATE ON billing_entitlement_work FOR EACH ROW EXECUTE FUNCTION guard_entitlement_wakeup();
CREATE OR REPLACE FUNCTION enqueue_billing_entitlement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='active' AND NEW.offer_key IN ('pro_monthly','pro_annual','yc_2026') AND (TG_OP='INSERT' OR OLD.status IS DISTINCT FROM NEW.status) THEN
  INSERT INTO billing_entitlement_work(contract_id) VALUES(NEW.id)
  ON CONFLICT(contract_id) DO UPDATE SET next_check_at=least(billing_entitlement_work.next_check_at,clock_timestamp()),wake_generation=billing_entitlement_work.wake_generation+1;
 END IF;
 RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION guard_entitlement_wakeup() FROM PUBLIC;

-- Recover activations that committed before the new trigger was installed.
INSERT INTO billing_entitlement_work(contract_id)
 SELECT c.id FROM billing_commercial_contract c
 WHERE c.status='active' AND c.offer_key IN ('pro_monthly','pro_annual','yc_2026')
 AND c.starts_at<=clock_timestamp() AND (c.ends_at IS NULL OR c.ends_at>clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM billing_usage_entitlement e WHERE e.contract_id=c.id
  AND e.state='issued' AND e.period_start<=clock_timestamp() AND e.period_end>clock_timestamp())
 ON CONFLICT(contract_id) DO UPDATE SET
 next_check_at=least(billing_entitlement_work.next_check_at,clock_timestamp()),
 wake_generation=billing_entitlement_work.wake_generation+1;
