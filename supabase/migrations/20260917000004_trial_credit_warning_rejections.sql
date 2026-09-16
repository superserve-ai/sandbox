BEGIN;

ALTER TABLE trial_credit_warning_delivery
    ALTER COLUMN sent_at DROP NOT NULL,
    ADD COLUMN rejected_at timestamptz,
    ADD CONSTRAINT trial_credit_warning_delivery_outcome_check
        CHECK ((sent_at IS NOT NULL) <> (rejected_at IS NOT NULL));

ALTER TABLE trial_credit_warning_state
    DROP CONSTRAINT trial_credit_warning_state_status_check,
    ADD CONSTRAINT trial_credit_warning_state_status_check
        CHECK (status IN ('pending', 'claimed', 'sent', 'unknown', 'suppressed'));

COMMIT;
