CREATE FUNCTION prepaid_funding_follow_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind <> 'prepaid' THEN
  UPDATE billing_funding_account SET prepaid=false WHERE team_id=NEW.team_id AND prepaid;
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER team_plan_assignment_prepaid_funding AFTER INSERT ON team_plan_assignment
 FOR EACH ROW EXECUTE FUNCTION prepaid_funding_follow_assignment();
REVOKE ALL ON FUNCTION prepaid_funding_follow_assignment() FROM PUBLIC;
