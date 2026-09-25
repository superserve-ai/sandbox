-- Hold legacy creation writes across the snapshot and trigger replacement.
BEGIN;

LOCK TABLE team, team_member, team_memberships, user_role_assignments,
    team_credit_grant IN SHARE ROW EXCLUSIVE MODE;

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
    -- An ambiguous external grant must keep its team fence durable; reject
    -- deletion until the reservation is finalized or explicitly released.
    stripe_redemption_reserved_team_id uuid REFERENCES team(id) ON DELETE RESTRICT,
    stripe_redemption_reserved_at timestamptz,
    stripe_redemption_attempted_at timestamptz,
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

CREATE INDEX user_promotion_entitlement_signup_team_idx
    ON user_promotion_entitlement(signup_trial_team_id)
    WHERE signup_trial_team_id IS NOT NULL;

ALTER TABLE user_promotion_entitlement ENABLE ROW LEVEL SECURITY;

-- A durable lease coordinates the split-phase webhook across transaction
-- pooler backends without relying on connection-local advisory locks.
CREATE TABLE stripe_webhook_processing_lease (
    customer_id text PRIMARY KEY,
    token uuid NOT NULL,
    expires_at timestamptz NOT NULL
);
ALTER TABLE stripe_webhook_processing_lease ENABLE ROW LEVEL SECURITY;

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

-- Keep a durable team-side marker for teams created after the owner's one-time
-- signup claim was already consumed. Without this marker those teams look like
-- legacy no-grant teams and remain eligible for unrestricted sandbox usage.
CREATE TABLE team_signup_trial_denial (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE team_signup_trial_denial ENABLE ROW LEVEL SECURITY;

-- The first legacy owner insertion identifies the creator. Completion is
-- retained to fence ambiguous-success cleanup while its signup grant exists.
CREATE TABLE team_signup_trial_provenance (
    team_id uuid PRIMARY KEY REFERENCES team(id) ON DELETE CASCADE,
    creator_user_id uuid REFERENCES profile(id) ON DELETE SET NULL,
    creator_bound_at timestamptz,
    completed_at timestamptz,
    -- Keep the issuance identity even if an administrator removes the grant.
    legacy_grant_id uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE team_signup_trial_provenance ENABLE ROW LEVEL SECURITY;

ALTER TABLE team_billing_account
    ADD COLUMN checkout_subscription_id text,
    ADD COLUMN checkout_completed_at timestamptz,
    ADD COLUMN checkout_request_key text,
    ADD COLUMN checkout_pending_attempt_ids uuid[] NOT NULL DEFAULT '{}',
    ADD COLUMN checkout_may_exist boolean NOT NULL DEFAULT false,
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

CREATE OR REPLACE FUNCTION prevent_pending_stripe_promotion_actor_deletion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- DELETE already holds the profile row, whereas promotion reservations
    -- take the user lock before checking profile foreign keys. Do not wait
    -- here and invert that lock order.
    IF NOT pg_try_advisory_xact_lock(hashtext('stripe-promo-user:' || OLD.id::text)::bigint) THEN
        RAISE EXCEPTION 'cannot delete profile during a Stripe promotion transition'
            USING ERRCODE = 'lock_not_available';
    END IF;
    IF EXISTS (
        SELECT 1 FROM user_promotion_entitlement
        WHERE user_id = OLD.id AND stripe_redemption_reserved_team_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM team_billing_account
        WHERE stripe_activation_user_id = OLD.id
          AND stripe_activation_credit_reserved_at IS NOT NULL
          AND stripe_activation_credit_grant_id IS NULL
          AND stripe_activation_credit_granted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'cannot delete profile with a pending Stripe promotion'
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER profile_pending_stripe_promotion_guard
    BEFORE DELETE ON profile
    FOR EACH ROW EXECUTE FUNCTION prevent_pending_stripe_promotion_actor_deletion();

-- An elapsed session deadline does not prove abandonment: completion may have
-- occurred before expiry while its webhook is still awaiting delivery.
CREATE OR REPLACE FUNCTION establish_billing_cutover(
    p_cutover timestamptz,
    p_preserved_team_ids uuid[] DEFAULT '{}'
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_count integer;
    v_team_id uuid;
BEGIN
    IF p_cutover IS NULL THEN
        RAISE EXCEPTION 'billing cutover cannot be null';
    END IF;
    p_cutover := date_trunc('second', p_cutover);
    IF p_cutover > now() THEN
        RAISE EXCEPTION 'billing cutover cannot be in the future';
    END IF;
    INSERT INTO team_billing_account (team_id)
    SELECT t.id
    FROM team t
    WHERE NOT (t.id = ANY(COALESCE(p_preserved_team_ids, '{}')))
    ON CONFLICT (team_id) DO NOTHING;
    FOR v_team_id IN
        SELECT a.team_id
        FROM team_billing_account a
        WHERE NOT (a.team_id = ANY(COALESCE(p_preserved_team_ids, '{}')))
        ORDER BY a.team_id
        FOR UPDATE
    LOOP
        NULL;
    END LOOP;
    IF EXISTS (
        SELECT 1
        FROM unnest(COALESCE(p_preserved_team_ids, '{}')) AS preserved(team_id)
        LEFT JOIN team_billing_account a ON a.team_id = preserved.team_id
        WHERE a.commercial_billing_anchor IS NULL
    ) THEN
        RAISE EXCEPTION 'preserved teams must have an established commercial billing anchor';
    END IF;
    IF EXISTS (
        SELECT 1 FROM team_billing_account a
        WHERE a.commercial_billing_anchor IS NULL
          AND (a.checkout_initializing_at IS NOT NULL
               OR a.checkout_completed_at IS NOT NULL)
          AND NOT (a.team_id = ANY(COALESCE(p_preserved_team_ids, '{}')))
    ) THEN
        RAISE EXCEPTION 'cannot establish billing cutover while checkout is initializing';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM team_billing_period p
        WHERE p.team_id <> ALL(COALESCE(p_preserved_team_ids, '{}'))
          AND NOT EXISTS (
              SELECT 1 FROM team_billing_account existing
              WHERE existing.team_id = p.team_id
                AND existing.commercial_billing_anchor IS NOT NULL
          )
          AND p.status = 'exporting'
          AND EXISTS (
              SELECT 1 FROM billing_usage_export e
              WHERE e.team_id = p.team_id AND e.period_start = p.period_start
                AND e.period_end = p.period_end AND e.sent_at IS NOT NULL
          )
    ) THEN
        RAISE EXCEPTION 'cannot discard partially exported billing periods during cutover';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM team_billing_period p
        WHERE p.team_id <> ALL(COALESCE(p_preserved_team_ids, '{}'))
          AND EXISTS (
              SELECT 1 FROM team_billing_account a
              WHERE a.team_id = p.team_id
                AND a.commercial_billing_anchor IS NULL
          )
          AND p.status = 'exporting'
    ) THEN
        RAISE EXCEPTION 'cannot cut over while billing periods are exporting';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM team_billing_period p
        JOIN team_billing_account a ON a.team_id = p.team_id
        WHERE a.commercial_billing_anchor = p_cutover
          AND p.status = 'exported'
          AND tstzrange(p.period_start, p.period_end, '[)') &&
              tstzrange(p_cutover, p_cutover + interval '1 month', '[)')
    ) THEN
        RAISE EXCEPTION 'billing cutover overlaps an exported period';
    END IF;

    UPDATE team_billing_period p
    SET status = 'finalized', blocked_reason = 'discarded_before_billing_cutover', blocked_at = NULL,
        gross_charges_usd = 0, credits_applied_usd = 0, net_invoice_amount_usd = 0,
        finalized_at = now(), updated_at = now()
    WHERE p.team_id <> ALL(COALESCE(p_preserved_team_ids, '{}'))
      AND NOT EXISTS (
          SELECT 1 FROM team_billing_account existing
          WHERE existing.team_id = p.team_id
            AND existing.commercial_billing_anchor IS NOT NULL
      )
      AND p.finalized_at IS NULL
      AND p.status IN ('open', 'validating', 'blocked', 'approved', 'exporting')
      AND NOT (
          p.status = 'exporting'
          AND EXISTS (
              SELECT 1 FROM billing_usage_export e
              WHERE e.team_id = p.team_id
                AND e.period_start = p.period_start
                AND e.period_end = p.period_end
                AND e.sent_at IS NOT NULL
          )
      );

    SELECT count(*) INTO v_count
    FROM team t
    LEFT JOIN team_billing_account a ON a.team_id = t.id
    WHERE NOT (t.id = ANY(COALESCE(p_preserved_team_ids, '{}')))
      AND a.commercial_billing_anchor IS NULL
      AND a.checkout_initializing_at IS NULL;

    UPDATE team_billing_account a
    SET commercial_billing_anchor = p_cutover, updated_at = now()
    WHERE a.commercial_billing_anchor IS NULL
      AND a.checkout_initializing_at IS NULL
      AND NOT (a.team_id = ANY(COALESCE(p_preserved_team_ids, '{}')));

    INSERT INTO team_billing_account (team_id, commercial_billing_anchor)
    SELECT t.id, p_cutover
    FROM team t
    LEFT JOIN team_billing_account a ON a.team_id = t.id
    WHERE a.team_id IS NULL
      AND NOT (t.id = ANY(COALESCE(p_preserved_team_ids, '{}')))
    ON CONFLICT (team_id) DO NOTHING;

    INSERT INTO team_billing_period (team_id, period_start, period_end, status)
    SELECT a.team_id, p_cutover, p_cutover + interval '1 month', 'open'
    FROM team_billing_account a
    WHERE a.commercial_billing_anchor = p_cutover
      AND NOT (a.team_id = ANY(COALESCE(p_preserved_team_ids, '{}')))
    ON CONFLICT (team_id, period_start, period_end) DO NOTHING;
    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_event_state(p_team_id uuid, p_user_id uuid, p_event_id text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE reserved boolean;
BEGIN
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    IF EXISTS (SELECT 1 FROM team_billing_account WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id AND stripe_activation_credit_grant_id IS NULL AND stripe_activation_credit_reservation_event_id IS NOT NULL) THEN
        IF EXISTS (SELECT 1 FROM team_billing_account WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id AND stripe_activation_credit_reservation_event_id = p_event_id) THEN
            RETURN 'existing';
        END IF;
        RETURN 'blocked';
    END IF;
    IF EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = p_user_id AND stripe_redemption_at IS NOT NULL) THEN
        RETURN 'ineligible';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM profile WHERE id = p_user_id) THEN
        RETURN 'ineligible';
    END IF;
    IF EXISTS (SELECT 1 FROM user_promotion_entitlement WHERE user_id = p_user_id AND stripe_redemption_reserved_team_id IS NOT NULL AND stripe_redemption_reserved_team_id <> p_team_id) THEN
        RETURN 'blocked';
    END IF;
    reserved := reserve_stripe_promotion(p_team_id, p_user_id);
    IF NOT reserved THEN
        RETURN 'blocked';
    END IF;
    UPDATE team_billing_account SET stripe_activation_credit_reservation_event_id = p_event_id, updated_at = now()
    WHERE team_id = p_team_id AND stripe_activation_user_id = p_user_id AND stripe_activation_credit_grant_id IS NULL;
    RETURN 'acquired';
END;
$$;

CREATE OR REPLACE FUNCTION reserve_stripe_promotion_for_event(p_team_id uuid, p_user_id uuid, p_event_id text)
RETURNS boolean LANGUAGE sql AS $$
    SELECT reserve_stripe_promotion_for_event_state(p_team_id, p_user_id, p_event_id) IN ('acquired', 'existing');
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
    -- Webhook deliveries for one activation serialize through this fence;
    -- allow the bounded webhook transaction enough time to finish its
    -- idempotent external call before treating contention as a failure.
    SET LOCAL lock_timeout = '5s';
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
    WHEN foreign_key_violation THEN
        -- A deleted checkout actor cannot receive a user-scoped entitlement;
        -- continue subscription bookkeeping without reserving the promotion.
        RETURN false;
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
        stripe_redemption_attempted_at = NULL,
        updated_at = now()
    WHERE user_id = p_user_id
      AND stripe_redemption_reserved_team_id = p_team_id
      AND stripe_redemption_at IS NULL;
    UPDATE team_billing_account
    SET stripe_activation_user_id = NULL,
        stripe_activation_credit_reserved_at = NULL,
        stripe_activation_credit_reservation_event_id = NULL,
        updated_at = now()
    WHERE team_id = p_team_id
      AND stripe_activation_user_id = p_user_id
      AND stripe_activation_credit_grant_id IS NULL
      AND stripe_activation_credit_granted_at IS NULL;
END;
$$;

CREATE OR REPLACE FUNCTION grant_signup_trial_credit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
    INSERT INTO team_signup_trial_provenance(team_id)
    VALUES (NEW.id);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION claim_team_signup_trial(p_team_id uuid, p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
DECLARE
    provenance team_signup_trial_provenance;
    claimed boolean;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'signup trial requires a creator';
    END IF;
    -- Raw legacy writes already hold membership/assignment rows. Fail with a
    -- retryable lock error instead of waiting in the opposite lock order.
    PERFORM 1 FROM team WHERE id = p_team_id FOR NO KEY UPDATE NOWAIT;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT * INTO provenance FROM team_signup_trial_provenance
    WHERE team_id = p_team_id FOR UPDATE;
    IF NOT FOUND OR provenance.completed_at IS NOT NULL THEN
        RETURN;
    END IF;
    IF provenance.creator_bound_at IS NOT NULL
       AND provenance.creator_user_id IS DISTINCT FROM p_user_id THEN
        RAISE EXCEPTION 'signup trial creator cannot change';
    END IF;
    claimed := false;
    -- Claim uniqueness is keyed by the signup entitlement itself. A shared
    -- entitlement row may already exist because this user redeemed Stripe,
    -- so it must not decide whether the independent $5 claim can proceed.
    INSERT INTO user_signup_trial_claim(user_id, team_id)
    VALUES (p_user_id, p_team_id)
    ON CONFLICT (user_id) DO NOTHING
    RETURNING true INTO claimed;
    IF claimed OR EXISTS (
        SELECT 1 FROM user_signup_trial_claim
        WHERE user_id = p_user_id AND team_id = p_team_id
    ) THEN
        -- The shared row may already exist because this user redeemed Stripe.
        -- Establish it independently, then mutate only the signup columns.
        INSERT INTO user_promotion_entitlement(user_id)
        VALUES (p_user_id)
        ON CONFLICT (user_id) DO NOTHING;
        UPDATE user_promotion_entitlement
        SET signup_trial_claimed_at = now(),
            signup_trial_team_id = p_team_id,
            updated_at = now()
        WHERE user_id = p_user_id
          AND signup_trial_claimed_at IS NULL;
        IF provenance.legacy_grant_id IS NULL THEN
            INSERT INTO team_credit_grant(team_id, amount_usd, remaining_usd, reason, created_by)
            VALUES (p_team_id, 5, 5, 'signup trial credit', p_user_id);
        ELSE
            -- Adoption attributes the original issuance without replenishing it.
            UPDATE team_credit_grant SET created_by = p_user_id
            WHERE id = provenance.legacy_grant_id AND team_id = p_team_id
              AND reason = 'signup trial credit' AND created_by IS NULL;
        END IF;
        INSERT INTO team_trial_eligibility_cache(team_id, eligible)
        VALUES (p_team_id, true)
        ON CONFLICT (team_id) DO UPDATE SET eligible = true, updated_at = now();
    ELSE
        INSERT INTO team_signup_trial_denial(team_id)
        VALUES (p_team_id)
        ON CONFLICT (team_id) DO NOTHING;
    END IF;
    UPDATE team_signup_trial_provenance
    SET creator_user_id = p_user_id,
        creator_bound_at = COALESCE(creator_bound_at, now()),
        completed_at = now()
    WHERE team_id = p_team_id;
END;
$$;

-- The explicit creator path claims in the provisioning transaction; its
-- pending marker is unnecessary once the transaction succeeds.
CREATE OR REPLACE FUNCTION create_team_with_signup_trial(
    p_name text,
    p_user_id uuid,
    p_home_region text
)
RETURNS team
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
DECLARE
    created_team team;
BEGIN
    INSERT INTO team(name, home_region)
    VALUES (p_name, p_home_region)
    RETURNING * INTO created_team;
    PERFORM claim_team_signup_trial(created_team.id, p_user_id);
    DELETE FROM team_signup_trial_provenance WHERE team_id = created_team.id;
    RETURN created_team;
END;
$$;

CREATE OR REPLACE FUNCTION bind_legacy_signup_trial_creator()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
    IF LOWER(NEW.role) NOT IN ('owner', 'team_owner') OR NOT EXISTS (
        SELECT 1 FROM team_signup_trial_provenance
        WHERE team_id = NEW.team_id AND creator_bound_at IS NULL AND completed_at IS NULL
    ) THEN
        RETURN NEW;
    END IF;
    PERFORM 1 FROM team WHERE id = NEW.team_id FOR NO KEY UPDATE NOWAIT;
    UPDATE team_signup_trial_provenance
    SET creator_user_id = NEW.profile_id, creator_bound_at = now()
    WHERE team_id = NEW.team_id AND creator_bound_at IS NULL
      AND completed_at IS NULL;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_member_signup_trial_creator
    AFTER INSERT ON team_member
    FOR EACH ROW EXECUTE FUNCTION bind_legacy_signup_trial_creator();

CREATE OR REPLACE FUNCTION complete_legacy_signup_trial()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
    IF NEW.scope_type <> 'team' OR NEW.revoked_at IS NOT NULL
       OR NOT EXISTS (
           SELECT 1 FROM team_signup_trial_provenance
           WHERE team_id = NEW.team_id AND completed_at IS NULL
       )
       OR NOT EXISTS (
           SELECT 1 FROM roles
           WHERE id = NEW.role_id AND name = 'team_owner' AND scope_type = 'team'
       ) THEN
        RETURN NEW;
    END IF;
    PERFORM 1 FROM team WHERE id = NEW.team_id FOR NO KEY UPDATE NOWAIT;
    IF EXISTS (
        SELECT 1 FROM team_signup_trial_provenance
        WHERE team_id = NEW.team_id AND creator_user_id = NEW.user_id
          AND creator_bound_at IS NOT NULL AND completed_at IS NULL
    ) AND EXISTS (
        SELECT 1 FROM team_member
        WHERE team_id = NEW.team_id AND profile_id = NEW.user_id
          AND LOWER(role) IN ('owner', 'team_owner')
    ) AND EXISTS (
        SELECT 1 FROM team_memberships
        WHERE team_id = NEW.team_id AND user_id = NEW.user_id AND status = 'active'
    ) THEN
        PERFORM claim_team_signup_trial(NEW.team_id, NEW.user_id);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER user_role_assignments_signup_trial_completion
    AFTER INSERT OR UPDATE ON user_role_assignments
    FOR EACH ROW EXECUTE FUNCTION complete_legacy_signup_trial();

CREATE OR REPLACE FUNCTION guard_legacy_signup_trial_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
DECLARE
    protected_team uuid;
    departing_user uuid;
BEGIN
    protected_team := OLD.team_id;
    IF NOT EXISTS (
        SELECT 1 FROM team_signup_trial_provenance WHERE team_id = protected_team
    ) THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;
    IF TG_TABLE_NAME = 'team_member' THEN
        departing_user := OLD.profile_id;
        IF LOWER(OLD.role) NOT IN ('owner', 'team_owner') THEN
            IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
        END IF;
        IF TG_OP = 'UPDATE' AND NEW.team_id = OLD.team_id
           AND NEW.profile_id = OLD.profile_id
           AND LOWER(NEW.role) IN ('owner', 'team_owner') THEN
            RETURN NEW;
        END IF;
    ELSIF TG_TABLE_NAME = 'team_memberships' THEN
        departing_user := OLD.user_id;
        IF OLD.status <> 'active' THEN
            IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
        END IF;
        IF TG_OP = 'UPDATE' AND NEW.status = 'active' THEN
            RETURN NEW;
        END IF;
    ELSE
        departing_user := OLD.user_id;
        -- Membership DELETE/deactivation may already have removed the active
        -- row before its existing trigger revokes this OLD assignment.
        IF OLD.scope_type <> 'team' OR OLD.revoked_at IS NOT NULL
           OR NOT EXISTS (
               SELECT 1 FROM roles
               WHERE id = OLD.role_id AND name = 'team_owner' AND scope_type = 'team'
           ) THEN
            IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
        END IF;
        IF TG_OP = 'UPDATE' AND NEW.user_id = OLD.user_id
           AND NEW.team_id = OLD.team_id AND NEW.scope_type = 'team'
           AND NEW.role_id = OLD.role_id AND NEW.revoked_at IS NULL THEN
            RETURN NEW;
        END IF;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM profile WHERE id = departing_user) THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;
    PERFORM 1 FROM team WHERE id = protected_team FOR NO KEY UPDATE NOWAIT;
    IF FOUND AND EXISTS (
           SELECT 1 FROM team_signup_trial_provenance
           WHERE team_id = protected_team AND completed_at IS NOT NULL
       ) AND EXISTS (
           SELECT 1 FROM team_credit_grant
           WHERE team_id = protected_team AND reason = 'signup trial credit'
       ) THEN
        IF TG_TABLE_NAME = 'team_member' THEN
            IF NOT EXISTS (
                SELECT 1 FROM team_member
                WHERE team_id = protected_team AND profile_id <> departing_user
                  AND LOWER(role) IN ('owner', 'team_owner')
            ) THEN
                RAISE EXCEPTION 'cannot remove last legacy owner while signup trial grant exists'
                    USING ERRCODE = 'check_violation';
            END IF;
        ELSIF (TG_TABLE_NAME = 'user_role_assignments' OR EXISTS (
            SELECT 1 FROM user_role_assignments a JOIN roles r ON r.id = a.role_id
            WHERE a.team_id = protected_team AND a.user_id = departing_user
              AND a.scope_type = 'team' AND a.revoked_at IS NULL
              AND r.name = 'team_owner' AND r.scope_type = 'team'
        )) AND NOT EXISTS (
            SELECT 1 FROM user_role_assignments a JOIN roles r ON r.id = a.role_id
            JOIN team_memberships m ON m.team_id = a.team_id AND m.user_id = a.user_id
            WHERE a.team_id = protected_team AND a.user_id <> departing_user
              AND a.scope_type = 'team' AND a.revoked_at IS NULL
              AND r.name = 'team_owner' AND r.scope_type = 'team' AND m.status = 'active'
        ) THEN
            RAISE EXCEPTION 'cannot remove last active owner while signup trial grant exists'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER team_member_signup_trial_owner_guard
    BEFORE DELETE OR UPDATE ON team_member
    FOR EACH ROW EXECUTE FUNCTION guard_legacy_signup_trial_owner();

CREATE TRIGGER team_memberships_signup_trial_owner_guard
    BEFORE DELETE OR UPDATE ON team_memberships
    FOR EACH ROW EXECUTE FUNCTION guard_legacy_signup_trial_owner();

CREATE TRIGGER user_role_assignments_signup_trial_owner_guard
    BEFORE DELETE OR UPDATE ON user_role_assignments
    FOR EACH ROW EXECUTE FUNCTION guard_legacy_signup_trial_owner();

-- A repeat-created team is not a legacy no-grant team: it has an explicit
-- denial marker and must remain blocked until it receives paid billing.
CREATE OR REPLACE FUNCTION team_sandbox_billing_eligible(p_team_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT CASE
        WHEN account.trial_ended_at IS NULL THEN
            (account.stripe_subscription_id IS NOT NULL
                AND lower(coalesce(account.stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due'))
            OR (denial.team_id IS NULL AND pending.team_id IS NULL AND (
                (grant_balance.historical_count = 0 AND account.stripe_subscription_id IS NULL)
                OR (grant_balance.remaining_usd > 0 AND COALESCE(cache.eligible, true))
            ))
        ELSE lower(coalesce(account.stripe_subscription_status, '')) IN ('active', 'trialing', 'past_due')
    END
    FROM (SELECT trial_ended_at, stripe_subscription_id, stripe_subscription_status
          FROM team_billing_account WHERE team_id = p_team_id) account
    FULL JOIN (SELECT COALESCE(SUM(remaining_usd) FILTER (WHERE expires_at IS NULL OR expires_at > now()), 0)::numeric AS remaining_usd,
                      COUNT(*)::int AS historical_count
               FROM team_credit_grant
               WHERE team_id = p_team_id
                 AND reason = 'signup trial credit') grant_balance ON true
    LEFT JOIN team_trial_eligibility_cache cache ON cache.team_id = p_team_id
    LEFT JOIN team_signup_trial_denial denial ON denial.team_id = p_team_id
    LEFT JOIN team_signup_trial_provenance pending
        ON pending.team_id = p_team_id AND pending.completed_at IS NULL;
$$;

-- Keep the control-plane query contract stable for callers that do not route
-- teams by region; console provisioning uses the region-aware overload above.
CREATE OR REPLACE FUNCTION create_team_with_signup_trial(p_name text, p_user_id uuid)
RETURNS team
LANGUAGE sql
SECURITY INVOKER
AS $$ SELECT create_team_with_signup_trial(p_name, p_user_id, 'use'); $$;

REVOKE EXECUTE ON FUNCTION grant_signup_trial_credit() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION claim_team_signup_trial(uuid, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION create_team_with_signup_trial(text, uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION create_team_with_signup_trial(text, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION bind_legacy_signup_trial_creator() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION complete_legacy_signup_trial() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION guard_legacy_signup_trial_owner() FROM PUBLIC;

DO $$
DECLARE
    restricted_role text;
    function_signature text;
BEGIN
    FOREACH function_signature IN ARRAY ARRAY[
        'grant_signup_trial_credit()',
        'claim_team_signup_trial(uuid, uuid)',
        'create_team_with_signup_trial(text, uuid, text)',
        'create_team_with_signup_trial(text, uuid)',
        'bind_legacy_signup_trial_creator()',
        'complete_legacy_signup_trial()',
        'guard_legacy_signup_trial_owner()'
    ] LOOP
        FOREACH restricted_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = restricted_role) THEN
                EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM %I', function_signature, restricted_role);
            END IF;
        END LOOP;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', function_signature);
        END IF;
    END LOOP;
END;
$$;

-- Adopt unfinished legacy signup chains. The observable initial-owner chain
-- is the only actor evidence available before this migration; historical
-- ownerless teams with membership, role, audit, or sandbox history stay closed.
INSERT INTO team_signup_trial_provenance(
    team_id, creator_user_id, creator_bound_at, legacy_grant_id
)
SELECT t.id, owner.profile_id, owner.joined_at, g.id
FROM team t
JOIN team_credit_grant g ON g.team_id = t.id
LEFT JOIN team_member owner ON owner.team_id = t.id
WHERE g.reason = 'signup trial credit' AND g.created_by IS NULL
  AND g.amount_usd = 5 AND g.created_at = t.created_at
  AND NOT EXISTS (SELECT 1 FROM team_credit_grant other WHERE other.team_id = t.id AND other.id <> g.id)
  AND (owner.profile_id IS NULL OR LOWER(owner.role) IN ('owner', 'team_owner'))
  AND NOT EXISTS (SELECT 1 FROM team_member other WHERE other.team_id = t.id AND other.profile_id <> owner.profile_id)
  AND NOT EXISTS (
      SELECT 1 FROM team_memberships m WHERE m.team_id = t.id
        AND (m.user_id IS DISTINCT FROM owner.profile_id OR m.status <> 'active')
  )
  AND NOT EXISTS (SELECT 1 FROM user_role_assignments a WHERE a.team_id = t.id)
  AND NOT EXISTS (SELECT 1 FROM audit_logs a WHERE a.team_id = t.id)
  AND NOT EXISTS (SELECT 1 FROM sandbox s WHERE s.team_id = t.id)
ON CONFLICT (team_id) DO NOTHING;
-- Install legacy signup claims only after the final owner assignment commits.

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
WITH legacy_signup_grant_teams AS (
    SELECT g.team_id
    FROM team_credit_grant g
    WHERE g.reason = 'signup trial credit'
      AND NOT EXISTS (
          SELECT 1 FROM team_signup_trial_provenance pending
          WHERE pending.team_id = g.team_id AND pending.completed_at IS NULL
      )
    GROUP BY g.team_id
    HAVING COUNT(g.created_by) = 0
), legacy_signup_owner_candidates AS (
    SELECT
        grant_team.team_id,
        tm.profile_id AS user_id,
        COUNT(*) OVER (PARTITION BY grant_team.team_id) AS owner_count
    FROM legacy_signup_grant_teams grant_team
    JOIN team_member tm ON tm.team_id = grant_team.team_id
    WHERE LOWER(COALESCE(tm.role, '')) IN ('owner', 'team_owner')
), legacy_signup_unique_owners AS (
    SELECT team_id, user_id
    FROM legacy_signup_owner_candidates
    WHERE owner_count = 1
), earliest_team_members AS (
    SELECT team_id, user_id, created_at,
           row_number() OVER (
               PARTITION BY team_id
               ORDER BY created_at, id
           ) AS member_rank
    FROM team_memberships
    WHERE status = 'active'
      AND NOT EXISTS (
          SELECT 1
          FROM team_credit_grant g
          WHERE g.team_id = team_memberships.team_id
            AND g.reason = 'signup trial credit'
      )
      AND NOT EXISTS (
          SELECT 1
          FROM legacy_signup_unique_owners owner
          WHERE owner.team_id = team_memberships.team_id
      )
), provenance_creators AS (
    SELECT owner.user_id, owner.team_id, t.created_at AS team_created_at
    FROM legacy_signup_unique_owners owner
    JOIN team t ON t.id = owner.team_id
    UNION ALL
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

WITH ledger_actors AS (
    SELECT team_id, (array_agg(DISTINCT created_by) FILTER (WHERE created_by IS NOT NULL))[1] AS user_id
    FROM team_credit_grant
    WHERE reason = 'stripe promotional credit'
    GROUP BY team_id
    HAVING COUNT(DISTINCT created_by) = 1
), supported_actors AS (
    SELECT actor.* FROM ledger_actors actor
    WHERE EXISTS (
        SELECT 1 FROM team_member m WHERE m.team_id = actor.team_id AND m.profile_id = actor.user_id
        UNION ALL
        SELECT 1 FROM team_memberships m WHERE m.team_id = actor.team_id AND m.user_id = actor.user_id AND m.status = 'active'
    )
)
UPDATE team_billing_account tba
SET stripe_activation_credit_granted_at = COALESCE(
        tba.stripe_activation_credit_granted_at,
        g.created_at
    ),
    stripe_activation_user_id = COALESCE(tba.stripe_activation_user_id, actor.user_id),
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
LEFT JOIN supported_actors actor USING (team_id)
WHERE g.team_id = tba.team_id
  AND (tba.stripe_activation_credit_grant_id IS NULL
       OR tba.stripe_activation_credit_granted_at IS NULL
       OR (tba.stripe_activation_user_id IS NULL AND actor.user_id IS NOT NULL));

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

-- Current ownership or membership alone cannot identify a historical payer.
-- Unattributed team markers remain consumed and become unresolved canonical
-- history in the next migration; no replacement grant is issued.
CREATE OR REPLACE FUNCTION activate_team_billing(
    p_team_id uuid,
    p_user_id uuid,
    p_stripe_grant_id text
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
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

    UPDATE team_credit_grant
    SET remaining_usd = 0, updated_at = now()
    WHERE team_id = p_team_id AND reason = 'signup trial credit';

    PERFORM finalize_stripe_promotion(p_team_id, p_user_id, p_stripe_grant_id);
END;
$$;

-- Settle the external grant independently of subscription status. An ambiguous
-- request may succeed even when a newer event has already canceled billing.
CREATE OR REPLACE FUNCTION finalize_stripe_promotion(p_team_id uuid, p_user_id uuid, p_stripe_grant_id text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    user_marked boolean;
    affected_rows integer;
    had_signup_trial boolean;
BEGIN
    PERFORM lock_stripe_promotion(p_team_id, p_user_id);
    PERFORM 1 FROM team_billing_account WHERE team_id = p_team_id FOR UPDATE;
    SELECT EXISTS (
        SELECT 1 FROM team_credit_grant
        WHERE team_id = p_team_id AND reason = 'signup trial credit'
    ) INTO had_signup_trial;

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
           stripe_redemption_attempted_at = NULL,
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

-- Anchor claims cannot overtake an open Checkout session or a completed
-- session whose subscription is still being reconciled.
CREATE OR REPLACE FUNCTION claim_team_commercial_billing_anchor(
    p_team_id uuid,
    p_anchor timestamptz
)
RETURNS timestamptz
LANGUAGE plpgsql
AS $$
DECLARE
    v_anchor timestamptz;
    v_existing_anchor timestamptz;
BEGIN
    IF p_anchor IS NULL THEN
        RAISE EXCEPTION 'commercial billing anchor cannot be null';
    END IF;
    p_anchor := date_trunc('second', p_anchor);

    SELECT commercial_billing_anchor
    INTO v_existing_anchor
    FROM team_billing_account
    WHERE team_id = p_team_id
    FOR UPDATE;

    IF EXISTS (SELECT 1 FROM team_billing_account WHERE team_id = p_team_id
               AND (checkout_initializing_at IS NOT NULL OR checkout_completed_at IS NOT NULL)) THEN
        RAISE EXCEPTION 'checkout is initializing for this team';
    END IF;

    INSERT INTO team_billing_account (team_id, commercial_billing_anchor)
    VALUES (p_team_id, p_anchor)
    ON CONFLICT (team_id) DO UPDATE
    SET commercial_billing_anchor = COALESCE(
            team_billing_account.commercial_billing_anchor,
            EXCLUDED.commercial_billing_anchor
        ),
        updated_at = now()
    WHERE team_billing_account.checkout_completed_at IS NULL
      AND team_billing_account.checkout_initializing_at IS NULL
    RETURNING commercial_billing_anchor INTO v_anchor;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'checkout is initializing for this team';
    END IF;

    IF v_anchor IS DISTINCT FROM p_anchor THEN
        RAISE EXCEPTION
            'commercial billing anchor already established for team % at %',
            p_team_id,
            v_anchor;
    END IF;

    RETURN v_anchor;
END;
$$;

COMMIT;
