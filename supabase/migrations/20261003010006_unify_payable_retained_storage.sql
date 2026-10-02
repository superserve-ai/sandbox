-- Payable readers share physical accounting with observational readers, clipped
-- to activation. Keep fractional legacy artifact usage additive across windows.
CREATE OR REPLACE FUNCTION billable_storage_mib_seconds(p_team_id uuid, p_start timestamptz, p_end timestamptz)
RETURNS numeric LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_start timestamptz;
    v_end timestamptz := LEAST(p_end, now());
BEGIN
    SELECT GREATEST(p_start, effective_at) INTO v_start
    FROM team_storage_billing_activation WHERE team_id = p_team_id;
    IF v_start IS NULL OR v_start >= v_end THEN
        RETURN 0;
    END IF;
    RETURN storage_mib_seconds(p_team_id, v_start, v_end, false);
END;
$$;
