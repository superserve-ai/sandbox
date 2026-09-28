-- Event-scoped obsolescence survives later checkouts and removal of team billing
-- authority during migration. It does not acknowledge webhook processing.
ALTER TABLE stripe_checkout_association_alert ADD COLUMN retired_at timestamptz;
