CREATE INDEX promotion_signup_device_evidence_fingerprint_idx
    ON promotion_signup_device_evidence(fingerprint, user_id);

ALTER TABLE user_promotion_entitlement ADD COLUMN stripe_device_fingerprint text
    CHECK(stripe_device_fingerprint IS NULL OR length(stripe_device_fingerprint) BETWEEN 1 AND 256);
UPDATE user_promotion_entitlement u
SET stripe_device_fingerprint = e.fingerprint
FROM promotion_signup_device_evidence e
WHERE e.user_id = u.user_id AND u.stripe_redemption_reserved_team_id IS NOT NULL;
CREATE INDEX user_promotion_entitlement_pending_device_idx
    ON user_promotion_entitlement(stripe_device_fingerprint)
    WHERE stripe_redemption_reserved_team_id IS NOT NULL AND stripe_device_fingerprint IS NOT NULL;

CREATE OR REPLACE FUNCTION promotion_device_decision(p_user_id uuid, p_promotion text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_policy promotion_device_policy; v_evidence promotion_signup_device_evidence; v_owner uuid; v_canonical boolean;
BEGIN
    IF p_user_id IS NULL OR p_promotion IS NULL OR p_promotion NOT IN ('signup', 'stripe') THEN
        RAISE EXCEPTION 'invalid promotion device decision' USING ERRCODE = '22023';
    END IF;
    v_canonical := canonical_promotion_identity_enabled();
    SELECT * INTO STRICT v_policy FROM promotion_device_policy WHERE singleton FOR SHARE;
    IF NOT v_canonical AND (v_policy.device_enforced OR v_policy.evidence_required) THEN
        RAISE EXCEPTION 'invalid promotion device configuration' USING ERRCODE = '55000';
    END IF;
    SELECT * INTO v_evidence FROM promotion_signup_device_evidence WHERE user_id = p_user_id;
    IF NOT FOUND THEN
        IF v_policy.evidence_required THEN RETURN 'evidence_missing'; END IF;
        RETURN 'eligible';
    END IF;
    IF v_policy.device_enforced THEN
        SELECT user_id INTO v_owner FROM promotion_device_owner WHERE fingerprint = v_evidence.fingerprint;
        IF v_owner IS NULL THEN RAISE EXCEPTION 'promotion device owner unavailable' USING ERRCODE = '55000'; END IF;
        IF v_owner <> p_user_id THEN RETURN 'owner_conflict'; END IF;
        IF EXISTS (SELECT 1 FROM promotion_device_grant WHERE promotion = p_promotion
            AND fingerprint = v_evidence.fingerprint AND user_id <> p_user_id) THEN
            RETURN 'device_already_redeemed';
        END IF;
        IF p_promotion = 'stripe' AND EXISTS (
            SELECT 1 FROM promotion_signup_device_evidence e
            JOIN user_promotion_entitlement u ON u.user_id = e.user_id
            WHERE e.fingerprint = v_evidence.fingerprint AND e.user_id <> p_user_id
              AND u.stripe_redemption_at IS NOT NULL
        ) THEN
            RETURN 'device_already_redeemed';
        END IF;
        IF p_promotion = 'stripe' AND EXISTS (
            SELECT 1 FROM user_promotion_entitlement u
            WHERE u.stripe_device_fingerprint = v_evidence.fingerprint AND u.user_id <> p_user_id
              AND u.stripe_redemption_reserved_team_id IS NOT NULL
        ) THEN
            RETURN 'device_reservation_pending';
        END IF;
    END IF;
    RETURN 'eligible';
END $$;
