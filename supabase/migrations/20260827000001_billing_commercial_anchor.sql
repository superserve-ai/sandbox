-- Persist the Superserve commercial billing anchor independently of
-- Stripe subscription activation. This anchor may predate Checkout for
-- sales-assisted conversions and must survive later subscription webhooks.

ALTER TABLE team_billing_account
    ADD COLUMN commercial_billing_anchor timestamptz;

ALTER TABLE team_billing_account
    ADD COLUMN checkout_initializing_at timestamptz,
    ADD COLUMN checkout_anchor_snapshot timestamptz,
    ADD COLUMN checkout_session_id text;

COMMENT ON COLUMN team_billing_account.commercial_billing_anchor IS
    'Authoritative Superserve commercial billing start. May predate Stripe subscription creation and must not be overwritten by Checkout time.';

CREATE INDEX idx_team_billing_account_commercial_anchor
    ON team_billing_account(commercial_billing_anchor)
    WHERE commercial_billing_anchor IS NOT NULL;

-- Claim the commercial anchor exactly once. Repeating the same claim is
-- idempotent; attempting to move an established anchor fails rather than
-- silently changing the commercial cutover after usage may already be billable.
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

    IF EXISTS (SELECT 1 FROM team_billing_account WHERE team_id = p_team_id AND checkout_initializing_at > now() - interval '32 minutes') THEN
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
    WHERE team_billing_account.checkout_initializing_at IS NULL
       OR team_billing_account.checkout_initializing_at < now() - interval '32 minutes'
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

COMMENT ON FUNCTION claim_team_commercial_billing_anchor(uuid, timestamptz) IS
    'Atomically establishes a team commercial billing anchor once. Same-value retries are idempotent; conflicting attempts fail.';

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
    -- A dead Checkout process can leave its reservation behind. Reclaim
    -- expired reservations in the same transaction so the cleanup and anchor
    -- assignment predicates observe the same state as the lease check.
    UPDATE team_billing_account
    SET checkout_initializing_at = NULL,
        checkout_anchor_snapshot = NULL,
        updated_at = now()
    WHERE checkout_initializing_at < now() - interval '32 minutes';
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
          AND a.checkout_initializing_at > now() - interval '32 minutes'
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

COMMENT ON FUNCTION establish_billing_cutover(timestamptz, uuid[]) IS
    'Establishes the production billing cutover for all existing non-preserved teams without overwriting an existing anchor.';

CREATE EXTENSION IF NOT EXISTS btree_gist;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM team_billing_period a
        JOIN team_billing_period b
          ON b.team_id = a.team_id
         AND (b.period_start, b.period_end) > (a.period_start, a.period_end)
         AND b.finalized_at IS NULL
         AND b.status IN ('open', 'validating', 'blocked', 'approved', 'exporting')
        WHERE a.finalized_at IS NULL
          AND a.status IN ('open', 'validating', 'blocked', 'approved', 'exporting')
          AND tstzrange(a.period_start, a.period_end, '[)') &&
              tstzrange(b.period_start, b.period_end, '[)')
    ) THEN
        RAISE EXCEPTION 'cannot install billing period overlap constraint until legacy overlaps are cleared';
    END IF;
END;
$$;
ALTER TABLE team_billing_period
    ADD CONSTRAINT team_billing_period_authoritative_no_overlap
    EXCLUDE USING gist (
        team_id WITH =,
        tstzrange(period_start, period_end, '[)') WITH &&
    ) WHERE (
        finalized_at IS NULL
        AND status IN ('open', 'validating', 'blocked', 'approved', 'exporting')
    );
