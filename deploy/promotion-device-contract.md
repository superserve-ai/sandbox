# Signup device evidence and regional promotion authority

This is an additive server contract. Regional device enforcement ships off. The
existing canonical identity rollout and Stripe reservation requirements in
[promotion identity authority](promotion-identity-authority.md) still apply.
This change does not switch the live grant callers; the Console producer and
subsequent grant integration must use the operations below before activation.

## Original evidence source

The shared Auth PostgreSQL project owns `signup_device_attempt` and
`signup_device_account_evidence`. Apply
`supabase/shared-auth-migrations/20260925000000_signup_device_evidence.sql` **once
to that project**, separately from each regional migration chain. This store is
server only, independent of East or West promotion databases. Verified attempts
and account bindings are retained indefinitely, including after account deletion;
unverified attempts may be purged only after their verification window closes.
Database backups and migration rollback protection must retain the tables.

Console's server, using the shared project's service credential, calls:

1. `create_signup_device_attempt()` before Fingerprint capture. It returns an
   unpredictable attempt UUID and challenge UUID. Only the challenge is sent to
   the browser as Fingerprint event metadata.
2. Console looks up the provider event on its server, verifies that the event
   belongs to this challenge, and calls
   `verify_signup_device_attempt(attempt, challenge, event_id, fingerprint,
   event_at)`. The database additionally checks challenge equality, a 30 minute
   attempt window, a five minute event freshness window and unique event ID.
   An event ID or browser supplied metadata alone is never acceptable input.
   Identical verification replays; a changed event or reused event fails.
3. After the Auth signup call returns the new Auth user's ID, Console calls
   `bind_signup_device_account(attempt, user_id)`. The caller must bind the ID
   from that trusted server result, never an email lookup or browser parameter.
   The function checks `auth.users` creation time against the attempt and
   serializes same account attempts. The first verified attempt bound to the
   account wins. A missing observation leaves the account unbound so a later
   valid attempt can win. Binding may occur before email confirmation.
4. Console retrieves durable evidence via
   `get_signup_device_account_evidence(user_id)` using the authenticated
   server side Auth principal. It must check that the requested ID is the
   current authenticated principal. This works after cookie loss, delayed
   confirmation, and later West team creation from another browser. The source
   returns one original attempt ID, event ID, exact case sensitive Fingerprint,
   original event time and binding time. Initial event freshness is checked
   only at verification. Retrieval has no event age limit.

The shared Auth service credential is kept exclusively by trusted Console
server code. These RPCs and tables grant no access to `anon` or `authenticated`.
A missing shared source, failed provider lookup, failed actor check, or ambiguous
binding withholds promotional credit; it does not block signup, team creation or
normal paid access. Console must not infer evidence from cookies, visitor IDs,
editable Auth user metadata or telemetry. Provider attestation field details
belong to the Console integration; it must compare the provider's event metadata
with the issued challenge and use the provider's server result.

## Regional publication and claims

Apply `20260925000001_regional_promotion_device_authority.sql` in **each**
regional database. Console first publishes the existing canonical Auth identity
observation, then obtains the shared original device evidence and calls
`register_promotion_signup_device(user_id, source_attempt_id, source_event_id,
fingerprint)` in the selected region. All inputs come from the server's durable
shared source and authenticated principal. This is also required before an
explicit West team creation months later. No East promotion result or owner is
sent to West; there is no East backend lookup from West. Publication is safe to
retry: `owner` means this account owns the regional Fingerprint,
`owner_conflict` means another account committed first, and conflicting account
or event evidence raises an error. Both owners and losers retain their original
account evidence locally. Registration grants no money and consumes no bonus.
The first regional insert commits independently of any later grant attempt, so
an abandoned signup, failed award or account deletion cannot transfer ownership.

`promotion_device_decision(user_id, promotion)` returns `eligible`,
`evidence_missing`, `owner_conflict` or `device_already_redeemed` for promotion
`signup` or `stripe`. SQL errors mean authority unavailable or invalid
configuration and must withhold credit. The caller must not substitute its own
Fingerprint, and must always consult this durable lookup even when its input
omits evidence. Tenant responses may use these reason codes but must never
include a Fingerprint, another user ID, event ID or raw identity.

`claim_team_signup_trial_with_device(team_id, user_id)` calls the existing local
claim transaction and records a device grant only when the existing claim
actually awards money. Its no-grant outcome leaves the device entitlement
unconsumed. The caller must invoke it inside initial regional team creation
before award. `reserve_stripe_promotion_with_device(team_id, user_id, event_id,
subscription_id, checkout_generation, has_checkout_generation)` checks device
eligibility before the existing durable local reservation. An existing pending
reservation replays through the original reservation function without applying
a newly changed policy. The later grant integration must record actual Stripe
issuance in `promotion_device_grant` in the same regional finalization transaction
by calling `record_stripe_promotion_device_grant(team_id, user_id)` and retain
the existing actor, evidence and checkout-generation pins. It must
not contact Stripe before a durable reservation or release an uncertain attempt.

The `promotion_device_policy` row starts with D=off and E=off. The canonical C
gate remains the existing `promotion_identity_enforcement` authority. A
configuration with C=off and either D or E on is invalid. Once C is on,
`set_promotion_device_policy(D)` defaults E to the same value, while the
two-argument form permits all four D/E combinations. D=off bypasses device
denial only; registration and actual-grant recording continue. Missing evidence
creates no owner. Policy changes never delete ownership, grants or pending
reservations. Existing balances, claims and reservations are untouched, with
no historical device reconstruction or cross-region financial reconciliation.

Deploy the shared source, then both regional schemas, then the Console producer,
then grant path integration. Verify initial East publication and later West
publication independently. Keep enforcement off until canonical readiness,
producer coverage, and both regional deployments have been verified.
