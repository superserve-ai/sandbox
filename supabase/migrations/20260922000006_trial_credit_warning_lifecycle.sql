BEGIN;

-- The balance aggregates signup grants. Keep their identity stable as credit is
-- consumed or expires; adding a grant starts a new warning lifecycle.
CREATE FUNCTION trial_credit_warning_lifecycle(p_team_id uuid)
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT md5(COALESCE(string_agg(id::text, ',' ORDER BY id), ''))
    FROM team_credit_grant
    WHERE team_id = p_team_id AND reason = 'signup trial credit';
$$;

ALTER TABLE trial_credit_warning_state ADD COLUMN lifecycle_key text;
UPDATE trial_credit_warning_state
SET lifecycle_key = trial_credit_warning_lifecycle(team_id);
ALTER TABLE trial_credit_warning_state ALTER COLUMN lifecycle_key SET NOT NULL;

ALTER TABLE trial_credit_warning_delivery ADD COLUMN lifecycle_key text;
UPDATE trial_credit_warning_delivery d
SET lifecycle_key = s.lifecycle_key
FROM trial_credit_warning_state s WHERE s.team_id = d.team_id;
ALTER TABLE trial_credit_warning_delivery ALTER COLUMN lifecycle_key SET NOT NULL;

ALTER TABLE trial_credit_warning_delivery
    DROP CONSTRAINT trial_credit_warning_delivery_team_id_fkey,
    DROP CONSTRAINT trial_credit_warning_delivery_pkey;
ALTER TABLE trial_credit_warning_state
    DROP CONSTRAINT trial_credit_warning_state_pkey,
    ADD PRIMARY KEY (team_id, lifecycle_key);
ALTER TABLE trial_credit_warning_delivery
    ADD PRIMARY KEY (team_id, lifecycle_key, recipient),
    ADD FOREIGN KEY (team_id, lifecycle_key)
        REFERENCES trial_credit_warning_state(team_id, lifecycle_key) ON DELETE CASCADE;

COMMIT;
