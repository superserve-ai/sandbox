CREATE OR REPLACE FUNCTION prepaid_funding_follow_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind <> 'prepaid' THEN
  UPDATE billing_funding_account SET prepaid=false WHERE team_id=NEW.team_id AND prepaid;
  UPDATE billing_prepaid_auto_recharge SET enabled=false,disabled_reason='team left prepaid',disabled_at=clock_timestamp(),notified_at=NULL
   WHERE team_id=NEW.team_id AND enabled;
 END IF;
 RETURN NULL;
END $$;
