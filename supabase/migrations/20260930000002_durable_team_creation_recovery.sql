-- A nullable locator preserves legacy attempts without reconstructing history.
ALTER TABLE team_promotion_creation_attempt ADD COLUMN operation_id uuid UNIQUE;
CREATE INDEX team_promotion_creation_discovery
    ON team_promotion_creation_attempt(user_id, home_region, operation_id)
    WHERE operation_id IS NOT NULL;

CREATE FUNCTION recover_team_promotion_creation(p_operation_id uuid, p_user_id uuid, p_home_region text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_attempt team_promotion_creation_attempt;
BEGIN
    SELECT * INTO v_attempt FROM team_promotion_creation_attempt a WHERE a.operation_id=p_operation_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF v_attempt.user_id IS DISTINCT FROM p_user_id OR v_attempt.home_region IS DISTINCT FROM p_home_region THEN
        RAISE EXCEPTION 'team creation binding conflict' USING ERRCODE='23505';
    END IF;
    RETURN to_jsonb(v_attempt) || jsonb_build_object('state', CASE
        WHEN v_attempt.outcome IS NULL THEN 'prepared'
        WHEN EXISTS(SELECT 1 FROM team WHERE id=v_attempt.team_id) THEN 'completed'
        ELSE 'deleted' END);
END $$;

CREATE FUNCTION prepare_team_promotion_creation(p_operation_id uuid, p_user_id uuid,
    p_name text, p_home_region text, p_authority_unavailable boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_attempt team_promotion_creation_attempt;
BEGIN
    IF p_operation_id IS NULL OR p_operation_id='00000000-0000-0000-0000-000000000000'::uuid
       OR p_user_id IS NULL OR p_user_id='00000000-0000-0000-0000-000000000000'::uuid
       OR NULLIF(BTRIM(p_name),'') IS NULL OR octet_length(p_name)>256
       OR p_home_region IS NULL OR p_home_region NOT IN ('use','usw')
       OR p_authority_unavailable IS NULL THEN
        RAISE EXCEPTION 'invalid team creation preparation' USING ERRCODE='22023';
    END IF;
    INSERT INTO team_promotion_creation_attempt(attempt_id,team_id,user_id,name,home_region,authority_unavailable,operation_id)
        VALUES(gen_random_uuid(),gen_random_uuid(),p_user_id,p_name,p_home_region,p_authority_unavailable,p_operation_id)
        ON CONFLICT (operation_id) DO NOTHING;
    SELECT * INTO STRICT v_attempt FROM team_promotion_creation_attempt a
        WHERE a.operation_id=p_operation_id FOR UPDATE;
    IF v_attempt.user_id<>p_user_id OR v_attempt.name<>p_name OR v_attempt.home_region<>p_home_region
       OR v_attempt.authority_unavailable<>p_authority_unavailable THEN
        RAISE EXCEPTION 'team creation binding conflict' USING ERRCODE='23505';
    END IF;
    RETURN recover_team_promotion_creation(p_operation_id,p_user_id,p_home_region);
END $$;

CREATE FUNCTION complete_team_promotion_creation(p_operation_id uuid, p_attempt_id uuid, p_team_id uuid,
    p_user_id uuid, p_name text, p_home_region text, p_authority_unavailable boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_attempt team_promotion_creation_attempt;
BEGIN
    SELECT * INTO v_attempt FROM team_promotion_creation_attempt a
        WHERE a.operation_id=p_operation_id FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF v_attempt.attempt_id IS DISTINCT FROM p_attempt_id OR v_attempt.team_id IS DISTINCT FROM p_team_id
       OR v_attempt.user_id IS DISTINCT FROM p_user_id OR v_attempt.name IS DISTINCT FROM p_name
       OR v_attempt.home_region IS DISTINCT FROM p_home_region
       OR v_attempt.authority_unavailable IS DISTINCT FROM p_authority_unavailable THEN
        RAISE EXCEPTION 'team creation binding conflict' USING ERRCODE='23505';
    END IF;
    -- The existing writer locks this same row and retains its result after deletion.
    PERFORM create_team_with_promotion_attempt(p_attempt_id,p_team_id,p_user_id,p_name,p_home_region,p_authority_unavailable);
    RETURN recover_team_promotion_creation(p_operation_id,p_user_id,p_home_region);
END $$;

CREATE FUNCTION discover_team_promotion_creations(p_user_id uuid, p_home_region text, p_after uuid)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    WITH page AS (
        SELECT a.*, CASE WHEN a.outcome IS NULL THEN 'prepared'
            WHEN EXISTS(SELECT 1 FROM team WHERE id=a.team_id) THEN 'completed' ELSE 'deleted' END AS state
        FROM team_promotion_creation_attempt a
        WHERE a.user_id=p_user_id AND a.home_region=p_home_region AND a.operation_id IS NOT NULL
          AND a.operation_id>COALESCE(p_after,'00000000-0000-0000-0000-000000000000'::uuid)
        ORDER BY a.operation_id LIMIT 51
    ), visible AS (SELECT * FROM page ORDER BY operation_id LIMIT 50)
    SELECT jsonb_build_object('state','selection_required',
        'operations',COALESCE((SELECT jsonb_agg(to_jsonb(v) ORDER BY v.operation_id) FROM visible v),'[]'::jsonb),
        'next_cursor',CASE WHEN (SELECT count(*) FROM page)>50
            THEN (SELECT operation_id::text FROM visible ORDER BY operation_id DESC LIMIT 1) ELSE NULL END)
$$;

DO $$ DECLARE f text; r text; BEGIN
    FOREACH f IN ARRAY ARRAY[
        'recover_team_promotion_creation(uuid,uuid,text)',
        'prepare_team_promotion_creation(uuid,uuid,text,text,boolean)',
        'complete_team_promotion_creation(uuid,uuid,uuid,uuid,text,text,boolean)',
        'discover_team_promotion_creations(uuid,text,uuid)'
    ] LOOP
        EXECUTE 'REVOKE ALL ON FUNCTION ' || f || ' FROM PUBLIC';
        FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
            IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r) THEN
                EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f,r);
            END IF;
        END LOOP;
        IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='service_role') THEN
            EXECUTE 'GRANT EXECUTE ON FUNCTION ' || f || ' TO service_role';
        END IF;
    END LOOP;
END $$;
