-- Promotional entitlements are independent: the signup trial belongs to the
-- user creating a team, while the Stripe credit belongs to the activating user
-- and the receiving team.  Both tables are local to this database authority.
CREATE TABLE user_promotion_entitlement (
    user_id uuid PRIMARY KEY REFERENCES profile(id) ON DELETE CASCADE,
    signup_trial_claimed_at timestamptz,
    -- Keep the user-level claim marker if its historical team is removed.
    signup_trial_team_id uuid REFERENCES team(id) ON DELETE SET NULL,
    stripe_redemption_at timestamptz,
    -- Keep the user-level redemption marker if its receiving team is removed.
    stripe_redemption_team_id uuid REFERENCES team(id) ON DELETE SET NULL,
    -- Pending external grants reserve the user without consuming the entitlement.
    stripe_redemption_reserved_team_id uuid REFERENCES team(id) ON DELETE SET NULL,
    stripe_redemption_reserved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT signup_trial_claim_pair CHECK (
        (signup_trial_claimed_at IS NULL AND signup_trial_team_id IS NULL)
        OR signup_trial_claimed_at IS NOT NULL
    ),
    CONSTRAINT stripe_redemption_claim_pair CHECK (
        (stripe_redemption_at IS NULL AND stripe_redemption_team_id IS NULL)
        OR stripe_redemption_at IS NOT NULL
        OR stripe_redemption_reserved_team_id IS NOT NULL
    )
);

-- Pending reservations must survive team deletion until reconciliation can
-- determine whether Stripe accepted the external grant.
ALTER TABLE user_promotion_entitlement
    DROP CONSTRAINT IF EXISTS user_promotion_entitlement_stripe_redemption_reserved_team_id_fkey;

CREATE INDEX user_promotion_entitlement_signup_team_idx
    ON user_promotion_entitlement(signup_trial_team_id)
    WHERE signup_trial_team_id IS NOT NULL;

ALTER TABLE user_promotion_entitlement ENABLE ROW LEVEL SECURITY;

CREATE TABLE user_signup_trial_claim (
    user_id uuid PRIMARY KEY REFERENCES profile(id) ON DELETE CASCADE,
    claimed_at timestamptz NOT NULL DEFAULT now(),
    -- A deleted team must not erase the user's consumed entitlement.
    team_id uuid REFERENCES team(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX user_signup_trial_claim_team_idx
    ON user_signup_trial_claim(team_id);

ALTER TABLE user_signup_trial_claim ENABLE ROW LEVEL SECURITY;

ALTER TABLE team_billing_account
    ADD COLUMN stripe_activation_user_id uuid REFERENCES profile(id) ON DELETE SET NULL,
    ADD COLUMN stripe_activation_credit_reserved_at timestamptz,
    ADD COLUMN stripe_activation_credit_reservation_event_id text,
    ADD COLUMN stripe_checkout_actor_id uuid REFERENCES profile(id) ON DELETE SET NULL,
    ADD COLUMN stripe_checkout_actor_claimed_at timestamptz;

CREATE OR REPLACE FUNCTION lock_stripe_promotion(p_team_id uuid, p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    -- Serialize the user/team reservation and finalization mutations so
    -- concurrent activations cannot deadlock while taking both pair locks.
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || COALESCE(p_user_id::text, ''))::bigint);
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-team:' || p_team_id::text)::bigint);
END;
$$;

CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_event(p_team_id uuid, p_user_id uuid, p_event_id text)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE reserved boolean;
BEGIN
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    IF EXISTS (SELECT 1 FROM team_billing_account WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id AND stripe_activation_credit_grant_id IS NULL AND stripe_activation_credit_reservation_event_id IS NOT NULL) THEN
        RETURN true;
    END IF;
    reserved := reserve_stripe_promotion(p_team_id, p_user_id);
    IF reserved THEN
        UPDATE team_billing_account SET stripe_activation_credit_reservation_event_id = p_event_id, updated_at = now()
        WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id AND stripe_activation_credit_grant_id IS NULL;
    END IF;
    RETURN reserved;
END;
$$;

CREATE OR REPLACE FUNCTION release_stripe_promotion_for_event(p_team_id uuid, p_user_id uuid, p_event_id text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    IF EXISTS (SELECT 1 FROM team_billing_account WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id AND stripe_activation_credit_reservation_event_id = p_event_id) THEN
        PERFORM release_stripe_promotion(p_team_id, p_user_id);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION reserve_stripe_promotion(p_team_id uuid, p_user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
    changed_rows integer;
BEGIN
    -- Keep the lock timeout short because this fence runs before webhook
    -- processing and contention is retried by Stripe.
    SET LOCAL lock_timeout = '100ms';
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    -- The reservation is committed before any external Stripe grant call, so
    -- a process crash cannot roll the fence back after Stripe succeeds.
    UPDATE team_billing_account
    SET stripe_activation_user_id = p_user_id,
        stripe_activation_credit_reserved_at = now(),
        updated_at = now()
    WHERE team_id = p_team_id
      AND stripe_activation_credit_grant_id IS NULL
      AND stripe_activation_credit_granted_at IS NULL
      AND (stripe_activation_user_id IS NULL OR stripe_activation_user_id = p_user_id);
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    INSERT INTO user_promotion_entitlement(user_id, stripe_redemption_reserved_team_id)
    VALUES (p_user_id, p_team_id)
    ON CONFLICT (user_id) DO UPDATE
    SET stripe_redemption_reserved_team_id = p_team_id, updated_at = now()
    WHERE user_promotion_entitlement.stripe_redemption_at IS NULL
      AND (user_promotion_entitlement.stripe_redemption_reserved_team_id IS NULL
           OR user_promotion_entitlement.stripe_redemption_reserved_team_id = p_team_id);
    UPDATE user_promotion_entitlement
    SET stripe_redemption_reserved_at = now(), updated_at = now()
    WHERE user_id = p_user_id
      AND stripe_redemption_reserved_team_id = p_team_id
      AND stripe_redemption_at IS NULL;
    GET DIAGNOSTICS changed_rows = ROW_COUNT;
    IF changed_rows = 0 THEN
        UPDATE team_billing_account
        SET stripe_activation_user_id = NULL,
            stripe_activation_credit_reserved_at = NULL,
            updated_at = now()
        WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id;
    END IF;
    RETURN changed_rows > 0;
EXCEPTION
    WHEN lock_not_available THEN
        -- Contention is retryable, not evidence that the promotion is
        -- ineligible. Propagate the lock error so the webhook is retried.
        RAISE;
END;
$$;

CREATE OR REPLACE FUNCTION release_stripe_promotion(p_team_id uuid, p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    UPDATE user_promotion_entitlement
    SET stripe_redemption_reserved_team_id = NULL,
        stripe_redemption_reserved_at = NULL,
        updated_at = now()
    WHERE user_id = p_user_id
      AND stripe_redemption_reserved_team_id = p_team_id
      AND stripe_redemption_at IS NULL;
    UPDATE team_billing_account
    SET stripe_activation_user_id = NULL,
        stripe_activation_credit_reserved_at = NULL,
        updated_at = now()
    WHERE team_id = p_team_id
      AND stripe_activation_user_id = p_user_id
      AND stripe_activation_credit_grant_id IS NULL
      AND stripe_activation_credit_granted_at IS NULL;
END;
$$;

-- Team creation callers that know the authenticated creator should use this
-- function.  The claim and grant are in the same transaction as the team
-- insert, so a failed provisioning transaction leaves the entitlement unused.
CREATE OR REPLACE FUNCTION create_team_with_signup_trial(
    p_name text,
    p_user_id uuid,
    p_home_region text
)
RETURNS team
LANGUAGE plpgsql
AS $$
DECLARE
    created_team team;
    claimed boolean;
BEGIN
    INSERT INTO team(name, home_region)
    VALUES (p_name, p_home_region)
    RETURNING * INTO created_team;
    claimed := false;
    -- Claim uniqueness is keyed by the signup entitlement itself. A shared
    -- entitlement row may already exist because this user redeemed Stripe,
    -- so it must not decide whether the independent $5 claim can proceed.
    INSERT INTO user_signup_trial_claim(user_id, team_id)
    VALUES (p_user_id, created_team.id)
    ON CONFLICT (user_id) DO NOTHING
    RETURNING true INTO claimed;
    IF claimed THEN
        -- The shared row may already exist because this user redeemed Stripe.
        -- Establish it independently, then mutate only the signup columns.
        INSERT INTO user_promotion_entitlement(user_id)
        VALUES (p_user_id)
        ON CONFLICT (user_id) DO NOTHING;
        UPDATE user_promotion_entitlement
        SET signup_trial_claimed_at = now(),
            signup_trial_team_id = created_team.id,
            updated_at = now()
        WHERE user_id = p_user_id
          AND signup_trial_claimed_at IS NULL;
        INSERT INTO team_credit_grant(team_id, amount_usd, remaining_usd, reason, created_by)
        VALUES (created_team.id, 5, 5, 'signup trial credit', p_user_id);
        INSERT INTO team_trial_eligibility_cache(team_id, eligible)
        VALUES (created_team.id, true)
        ON CONFLICT (team_id) DO UPDATE SET eligible = true, updated_at = now();
    END IF;
    RETURN created_team;
END;
$$;

-- Keep the control-plane query contract stable for callers that do not route
-- teams by region; console provisioning uses the region-aware overload above.
CREATE OR REPLACE FUNCTION create_team_with_signup_trial(p_name text, p_user_id uuid)
RETURNS team
LANGUAGE sql
AS $$ SELECT create_team_with_signup_trial(p_name, p_user_id, 'use'); $$;

-- The former trigger granted a trial to every team, including invited-team
-- membership flows.  New grants are now explicit and user-keyed.
DROP TRIGGER IF EXISTS team_signup_trial_credit ON team;

-- Backfill historical ownership, including users who already own multiple
-- teams. Existing duplicate grants remain untouched; this merely prevents
-- future claims by already-served users while retaining the earliest grant as
-- the audit record for each user.
INSERT INTO user_signup_trial_claim(user_id, claimed_at, team_id)
SELECT DISTINCT ON (created_by)
    created_by, created_at, team_id
FROM (
    SELECT DISTINCT ON (team_id) created_by, created_at, team_id, id
    FROM team_credit_grant
    WHERE reason = 'signup trial credit'
      AND created_by IS NOT NULL
    ORDER BY team_id, created_at, id
) g
ORDER BY created_by, created_at, id
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO user_promotion_entitlement(user_id, signup_trial_claimed_at, signup_trial_team_id)
SELECT user_id, claimed_at, team_id
FROM user_signup_trial_claim
ON CONFLICT (user_id) DO UPDATE
SET signup_trial_claimed_at = EXCLUDED.signup_trial_claimed_at,
    signup_trial_team_id = EXCLUDED.signup_trial_team_id,
    updated_at = now()
WHERE user_promotion_entitlement.signup_trial_claimed_at IS NULL;

-- Some historical teams have no signup-trial grant row. Use immutable
-- membership provenance (the earliest immutable membership timestamp), rather
-- than the mutable current RBAC owner role, to identify the creating user.
-- Users with exactly one such team are backfilled to that team. A user who is
-- the earliest member of multiple teams is an explicit migration exception:
-- consume the entitlement without choosing a potentially incorrect team.
WITH earliest_team_members AS (
    SELECT team_id, user_id, created_at,
           row_number() OVER (
               PARTITION BY team_id
               ORDER BY created_at, id
           ) AS member_rank
    FROM team_memberships
), provenance_creators AS (
    SELECT etm.user_id, etm.team_id, t.created_at AS team_created_at
    FROM earliest_team_members etm
    JOIN team t ON t.id = etm.team_id
    WHERE etm.member_rank = 1
), creator_counts AS (
    SELECT user_id, COUNT(*) AS team_count
    FROM provenance_creators
    GROUP BY user_id
), one_team_creators AS (
    SELECT pc.user_id, pc.team_id, pc.team_created_at
    FROM provenance_creators pc
    JOIN creator_counts cc ON cc.user_id = pc.user_id
    WHERE cc.team_count = 1
), multi_team_creators AS (
    SELECT pc.user_id, MIN(pc.team_created_at) AS first_team_created_at
    FROM provenance_creators pc
    JOIN creator_counts cc ON cc.user_id = pc.user_id
    WHERE cc.team_count > 1
    GROUP BY pc.user_id
)
INSERT INTO user_signup_trial_claim(user_id, claimed_at, team_id)
SELECT user_id, team_created_at, team_id
FROM one_team_creators otc
WHERE NOT EXISTS (
    SELECT 1 FROM user_signup_trial_claim existing
    WHERE existing.user_id = otc.user_id
)
UNION ALL
SELECT user_id, first_team_created_at, NULL
FROM multi_team_creators mtc
WHERE NOT EXISTS (
    SELECT 1 FROM user_signup_trial_claim existing
    WHERE existing.user_id = mtc.user_id
)
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO user_promotion_entitlement(user_id, signup_trial_claimed_at, signup_trial_team_id)
SELECT user_id, claimed_at, team_id
FROM user_signup_trial_claim
ON CONFLICT (user_id) DO UPDATE
SET signup_trial_claimed_at = EXCLUDED.signup_trial_claimed_at,
    signup_trial_team_id = EXCLUDED.signup_trial_team_id,
    updated_at = now()
WHERE user_promotion_entitlement.signup_trial_claimed_at IS NULL;

-- Legacy Stripe grant rows retain the activation actor in created_by even
-- though the billing account did not persist it. Copy that evidence onto the
-- team marker (including grant-ledger-only history) before seeding user-level
-- redemption state below.
INSERT INTO team_billing_account (team_id)
SELECT DISTINCT g.team_id
FROM team_credit_grant g
WHERE g.reason = 'stripe promotional credit'
ON CONFLICT (team_id) DO NOTHING;

UPDATE team_billing_account tba
SET stripe_activation_credit_granted_at = COALESCE(
        tba.stripe_activation_credit_granted_at,
        g.created_at
    ),
    stripe_activation_user_id = CASE WHEN EXISTS (SELECT 1 FROM team_member tm WHERE tm.team_id = g.team_id AND tm.profile_id = g.created_by) THEN g.created_by ELSE NULL END,
    stripe_activation_credit_grant_id = COALESCE(
        tba.stripe_activation_credit_grant_id,
        g.id::text
    ),
    updated_at = now()
FROM (
    SELECT DISTINCT ON (team_id) team_id, created_by, id, created_at
    FROM team_credit_grant
    WHERE reason = 'stripe promotional credit'
    ORDER BY team_id, created_at, id
) g
WHERE g.team_id = tba.team_id
  AND (tba.stripe_activation_credit_grant_id IS NULL
       OR tba.stripe_activation_credit_granted_at IS NULL
       OR (tba.stripe_activation_user_id IS NULL AND g.created_by IS NOT NULL));

-- Seed the user-level redemption directly from legacy Stripe grant rows as
-- well. Older rows may not have a team_billing_account marker, but their
-- recorded actor is still sufficient evidence that the user's entitlement
-- was consumed.
INSERT INTO user_promotion_entitlement(
    user_id,
    stripe_redemption_at,
    stripe_redemption_team_id
)
SELECT DISTINCT ON (g.created_by)
    g.created_by,
    g.created_at,
    g.team_id
FROM team_credit_grant g
WHERE g.reason = 'stripe promotional credit'
  AND g.created_by IS NOT NULL
  AND EXISTS (
      SELECT 1 FROM team_member tm
      WHERE tm.team_id = g.team_id
        AND tm.profile_id = g.created_by
  )
ORDER BY g.created_by, g.created_at, g.id
ON CONFLICT (user_id) DO UPDATE
SET stripe_redemption_at = EXCLUDED.stripe_redemption_at,
    stripe_redemption_team_id = EXCLUDED.stripe_redemption_team_id,
    updated_at = now()
WHERE user_promotion_entitlement.stripe_redemption_at IS NULL;

-- Seed the user-level redemption directly from any historical activation
-- actor already recorded on the billing account. This remains idempotent and
-- covers legacy rows even when no corresponding grant ledger row exists.
INSERT INTO user_promotion_entitlement(
    user_id,
    stripe_redemption_at,
    stripe_redemption_team_id
)
SELECT
    historical.user_id,
    historical.redeemed_at,
    historical.team_id
FROM (
    SELECT DISTINCT ON (tba.stripe_activation_user_id)
        tba.stripe_activation_user_id AS user_id,
        COALESCE(tba.stripe_activation_credit_granted_at, now()) AS redeemed_at,
        tba.team_id
    FROM team_billing_account tba
    WHERE tba.stripe_activation_user_id IS NOT NULL
      AND (tba.stripe_activation_credit_grant_id IS NOT NULL
           OR tba.stripe_activation_credit_granted_at IS NOT NULL)
    ORDER BY tba.stripe_activation_user_id,
             tba.stripe_activation_credit_granted_at NULLS LAST,
             tba.team_id
) historical
ON CONFLICT (user_id) DO UPDATE
SET stripe_redemption_at = EXCLUDED.stripe_redemption_at,
    stripe_redemption_team_id = EXCLUDED.stripe_redemption_team_id,
    updated_at = now()
WHERE user_promotion_entitlement.stripe_redemption_at IS NULL;

-- Historical Stripe grants predate the user-level marker. Prefer the recorded
-- activation actor, then the recorded team owner, when available. If neither
-- exists, active membership is conservative evidence that one user may have
-- been the recipient; a grant creator is not necessarily the payer. The
-- ranking below records only one best-supported user per historical team so
-- one team-level grant cannot consume every member's independent entitlement.
WITH historical_team_members AS (
    SELECT tm.team_id, tm.profile_id AS user_id
    FROM team_member tm
    UNION
    SELECT tm.team_id, tm.user_id
    FROM team_memberships tm
    WHERE tm.status = 'active'
), historical_team_owners AS (
    SELECT tm.team_id, tm.profile_id AS user_id
    FROM team_member tm
    WHERE tm.role IN ('owner', 'team_owner')
), historical_redemptions AS (
    SELECT
        tba.team_id,
        tba.stripe_activation_user_id AS user_id,
        COALESCE(tba.stripe_activation_credit_granted_at, now()) AS redeemed_at,
        1 AS evidence_priority
    FROM team_billing_account tba
    WHERE (tba.stripe_activation_credit_grant_id IS NOT NULL
           OR tba.stripe_activation_credit_granted_at IS NOT NULL)
      AND tba.stripe_activation_user_id IS NOT NULL
    UNION ALL
    -- Older grant rows retain the actor who created the grant even though the
    -- billing account did not persist the activating user.
    SELECT
        g.team_id,
        g.created_by AS user_id,
        g.created_at AS redeemed_at,
        2 AS evidence_priority
    FROM team_credit_grant g
    WHERE g.reason = 'stripe promotional credit'
      AND g.created_by IS NOT NULL
      AND EXISTS (
          SELECT 1
          FROM historical_team_members member
          WHERE member.team_id = g.team_id
            AND member.user_id = g.created_by
      )
    UNION ALL
    -- When the historical activation actor was not persisted, the recorded
    -- team owner is the strongest available identity evidence. This covers
    -- the legacy single-recipient promotion without consuming every invitee's
    -- future user-level entitlement.
    SELECT
        tba.team_id,
        owner.user_id,
        COALESCE(tba.stripe_activation_credit_granted_at, now()) AS redeemed_at,
        2 AS evidence_priority
    FROM team_billing_account tba
    JOIN historical_team_owners owner ON owner.team_id = tba.team_id
    WHERE (tba.stripe_activation_credit_grant_id IS NOT NULL
           OR tba.stripe_activation_credit_granted_at IS NOT NULL)
      AND tba.stripe_activation_user_id IS NULL
    UNION ALL
    SELECT
        tba.team_id,
        tm.user_id,
        COALESCE(tba.stripe_activation_credit_granted_at, now()) AS redeemed_at,
        3 AS evidence_priority
    FROM team_billing_account tba
    JOIN historical_team_members tm ON tm.team_id = tba.team_id
    WHERE (tba.stripe_activation_credit_grant_id IS NOT NULL
           OR tba.stripe_activation_credit_granted_at IS NOT NULL)
      AND tba.stripe_activation_user_id IS NULL
    UNION ALL
    -- The RBAC membership table is also historical identity evidence. Keep
    -- this path explicit so users represented only there are seeded even when
    -- the legacy team_member row is absent.
    SELECT
        tba.team_id,
        membership.user_id,
        COALESCE(tba.stripe_activation_credit_granted_at, now()) AS redeemed_at,
        3 AS evidence_priority
    FROM team_billing_account tba
    JOIN team_memberships membership ON membership.team_id = tba.team_id
    WHERE (tba.stripe_activation_credit_grant_id IS NOT NULL
           OR tba.stripe_activation_credit_granted_at IS NOT NULL)
      AND tba.stripe_activation_user_id IS NULL
      AND membership.status = 'active'
      AND NOT EXISTS (
          SELECT 1
          FROM team_member legacy_membership
          WHERE legacy_membership.team_id = membership.team_id
            AND legacy_membership.profile_id = membership.user_id
      )
    UNION ALL
    SELECT
        g.team_id,
        tm.user_id,
        g.created_at AS redeemed_at,
        3 AS evidence_priority
    FROM team_credit_grant g
    JOIN historical_team_members tm ON tm.team_id = g.team_id
    WHERE g.reason = 'stripe promotional credit'
      AND NOT EXISTS (
          SELECT 1
          FROM team_billing_account tba
          WHERE tba.team_id = g.team_id
            AND (tba.stripe_activation_credit_grant_id IS NOT NULL
                 OR tba.stripe_activation_credit_granted_at IS NOT NULL)
      )
), one_redemption_per_team AS (
    SELECT team_id, user_id, redeemed_at, evidence_priority,
           row_number() OVER (
               PARTITION BY team_id
               ORDER BY evidence_priority, redeemed_at, user_id
           ) AS team_redemption_rank
    FROM historical_redemptions
    WHERE user_id IS NOT NULL
), one_redemption_per_user AS (
    SELECT team_id, user_id, redeemed_at, evidence_priority,
           row_number() OVER (
               PARTITION BY user_id
               ORDER BY evidence_priority, redeemed_at, team_id
           ) AS redemption_rank
    FROM one_redemption_per_team
    WHERE team_redemption_rank = 1
)
INSERT INTO user_promotion_entitlement(
    user_id,
    stripe_redemption_at,
    stripe_redemption_team_id
)
SELECT user_id, redeemed_at, team_id
FROM one_redemption_per_user
WHERE redemption_rank = 1
ON CONFLICT (user_id) DO UPDATE
SET stripe_redemption_at = EXCLUDED.stripe_redemption_at,
    stripe_redemption_team_id = EXCLUDED.stripe_redemption_team_id,
    updated_at = now()
WHERE user_promotion_entitlement.stripe_redemption_at IS NULL;

-- Historical Stripe activations retain their team-side marker and are seeded
-- into user-level redemption state above using recorded actors where present
-- and conservative team-membership evidence otherwise. New successful
-- activations record the actor directly below.
CREATE OR REPLACE FUNCTION activate_team_billing(
    p_team_id uuid,
    p_user_id uuid,
    p_stripe_grant_id text
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    user_marked boolean;
    affected_rows integer;
    had_signup_trial boolean;
BEGIN
    user_marked := false;
    -- Keep direct callers serialized with the eligibility check that precedes
    -- external Stripe grant creation. This prevents a concurrent activation
    -- from consuming either identity between that check and this write.
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-user:' || COALESCE(p_user_id::text, ''))::bigint);
    PERFORM pg_advisory_xact_lock(hashtext('stripe-promo-team:' || p_team_id::text)::bigint);
    -- Serialize activations for this team. Ending the local trial is part of
    -- normal billing activation; the pending user reservation is finalized
    -- only after the external grant succeeds.
    PERFORM 1 FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    UPDATE team_billing_account
    SET trial_ended_at = COALESCE(trial_ended_at, now()),
        updated_at = now()
    WHERE team_id = p_team_id
      AND lower(coalesce(stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due');

    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM team_credit_grant
        WHERE team_id = p_team_id AND reason = 'signup trial credit'
    ) INTO had_signup_trial;

    UPDATE team_credit_grant
    SET remaining_usd = 0, updated_at = now()
    WHERE team_id = p_team_id AND reason = 'signup trial credit';

    IF p_user_id IS NULL THEN
        -- An activation without an identified actor cannot redeem the
        -- promotion. Keep normal billing activation, but do not consume the
        -- team's promotion entitlement when no external grant was issued.
        IF NULLIF(BTRIM(p_stripe_grant_id), '') IS NULL THEN
            RETURN;
        END IF;
        UPDATE team_billing_account
        SET stripe_activation_credit_granted_at = COALESCE(stripe_activation_credit_granted_at, now()),
            stripe_activation_credit_grant_id = COALESCE(stripe_activation_credit_grant_id, p_stripe_grant_id),
            stripe_activation_credit_reserved_at = NULL,
            updated_at = now()
        WHERE team_id = p_team_id;
        RETURN;
    END IF;

    -- A paid activation that did not reserve an eligible promotion must not
    -- consume the activating user's entitlement.
    IF NULLIF(BTRIM(p_stripe_grant_id), '') IS NULL THEN
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM team_billing_account
               WHERE team_id = p_team_id
                 AND (stripe_activation_credit_grant_id IS NOT NULL
                      OR stripe_activation_credit_granted_at IS NOT NULL)) THEN
        RETURN;
    END IF;

    INSERT INTO user_promotion_entitlement(user_id, stripe_redemption_at, stripe_redemption_team_id)
    VALUES (p_user_id, now(), p_team_id)
    ON CONFLICT (user_id) DO UPDATE
       SET stripe_redemption_at = EXCLUDED.stripe_redemption_at,
           stripe_redemption_team_id = EXCLUDED.stripe_redemption_team_id,
           stripe_redemption_reserved_team_id = NULL,
           stripe_redemption_reserved_at = NULL,
           updated_at = now()
     WHERE user_promotion_entitlement.stripe_redemption_at IS NULL
       AND (user_promotion_entitlement.stripe_redemption_reserved_team_id IS NULL
            OR user_promotion_entitlement.stripe_redemption_reserved_team_id = p_team_id);
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    user_marked := affected_rows > 0;
    IF user_marked THEN
        UPDATE team_billing_account
        SET stripe_activation_credit_granted_at = now(),
            stripe_activation_credit_grant_id = p_stripe_grant_id,
            stripe_activation_user_id = p_user_id,
            stripe_activation_credit_reserved_at = NULL,
            updated_at = now()
        WHERE team_id = p_team_id;

        -- Keep an auditable local record for teams that did not have the
        -- signup trial ledger entry. Stripe remains authoritative for the
        -- spendable $95 balance, so this row is deliberately exhausted.
        IF NOT had_signup_trial THEN
            INSERT INTO team_credit_grant(
                team_id, amount_usd, remaining_usd, reason, created_by
            )
            VALUES (p_team_id, 95, 0, 'stripe promotional credit', p_user_id);
        END IF;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION activate_team_billing(p_team_id uuid, p_stripe_grant_id text)
RETURNS void
LANGUAGE sql
AS $$ SELECT activate_team_billing(p_team_id, NULL::uuid, p_stripe_grant_id); $$;
