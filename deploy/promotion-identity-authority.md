# Promotion identity authority

Global Supabase Auth supplies identity evidence; regional PostgreSQL owns promotion
claims. Trusted Console/server code reads the authenticated Auth User, then writes
its raw email, verification state and source revision alongside the regional
profile. There is no database-to-database Auth bridge, remote credential or
regional `profile.email` fallback. Canonicalization never changes login or stored
emails. Claim uniqueness is regional, not coordinated across independently active cells.

## Additive deployment and activation

The expansion migrations are:

- `20260925195213_promotion_redemption_limits.sql`: user/team entitlement and legacy compatibility.
- `20260925195235_canonical_promotion_identity.sql`: local evidence, canonical claims, history and inactive enforcement gate.
- `20260925195248_canonical_stripe_promotion_fences.sql`: durable Stripe identity and evidence pins.

Canonical enforcement starts **off**. Existing Console UUID-based claims continue
through the shared authority, without requiring a simultaneous Console rollout.
Every new grant is recorded for the eventual canonical cutover: an observation
captured before that grant can reconcile it; insufficient evidence leaves a
pending historical obligation. Aliases can still receive separate UUID-based
grants while enforcement is off. Existing grants are never replaced or clawed back.

Deploy the trusted Console producer next, to every cell and claim-bearing path:
first-login, explicit/lazy team creation, existing profiles and existing-team
billing activation. Profile existence is not evidence freshness. Fetch trusted
Auth state immediately before a claim-bearing operation; refresh email and
verification changes. Do not add Auth calls to ordinary sandbox operations.
A callback-only or new-account-only producer is insufficient.

Before activation, reconcile pending historical obligations, settle pending
Stripe reservations/checkouts, verify all-cell writer coverage, and prevent
rollback to Console versions that omit evidence. An administrator then invokes:

```sql
SELECT enable_canonical_promotion_identity(
  '{"reference":"approved rollout record","all_writers_ready":true,"rollback_ready":true}'
);
```

This function returns void, takes an exclusive transaction-scoped gate lock and
refuses activation while unresolved history or pending billing state remains.
Claim paths hold the matching shared gate lock. The operator must supply truthful
deployment attestations; the database does not discover deployed Console versions.
Activation is irreversible through the application interface. Do not clear durable
fences or historical obligations merely to pass the gate.

The later team-creation API/Console switch and legacy-trigger removal are separate
steps; see [signup trial rollout](signup-trial-rollout.md). This expansion contains
no runnable trigger-removal migration.

## Transaction-compatible caller contract

The server-only writer is:

```sql
upsert_profile_with_promotion_identity(
  p_user_id uuid, p_email text, p_email_verified boolean,
  p_auth_updated_at timestamptz, p_observed_at timestamptz
) RETURNS TABLE(outcome text, evidence_version uuid)
```

Bind the UUID to the verified authenticated user. Email, verification and Auth
revision must come from the full trusted Auth record, never browser input,
user-editable metadata, regional profile or an unverified assertion. The server
records observation time when it retrieves that record. Auth `updated_at` supplies
the source revision; verification comes from the authoritative email confirmation
field. The authenticated provisioning API may transport these values only through
its verified Console assertion.

The writer atomically upserts the raw profile email and immutable evidence,
preserving other profile fields. It returns `applied` for a new version or
`replayed` for a compatible older observation of the same source revision.
An older source revision or conflicting payload for the same revision is rejected.
Observation age is limited to five minutes, with thirty seconds of future clock
tolerance. A separate current pointer advances on valid refresh. Publishing
evidence consumes no entitlement.

The creator then uses, in the **same database transaction** as membership and
role setup:

```sql
claim_team_signup_trial(p_team_id uuid, p_user_id uuid)
  RETURNS TABLE(outcome text, reason text)
```

Stable outcomes are `granted`, `already_claimed` and `promotion_ineligible`.
A no-grant outcome permits team creation. Same-team replay returns its stored
decision; changing the initial actor is invalid. Joining an existing team consumes
nothing. The existing convenience interface is:

```sql
create_team_with_signup_trial(p_name text, p_user_id uuid, p_home_region text)
  RETURNS team
```

It inserts the team and performs the shared claim, but does **not** create any
memberships or owner roles. The API must insert both membership representations,
the owner role and its durable recovery result in the same transaction before
committing. Read `team_signup_promotion_outcome` for the decision. Neither function
commits. Calling the evidence writer, team/claim, owner setup and recovery write
in one transaction ensures failure rolls everything back. Legacy owner-completion
triggers call the same claim authority.

When enforcement is on, Gmail/Googlemail identities lowercase, normalize to
gmail.com, strip the plus suffix and remove local-part dots. Other valid, verified
providers retain authenticated-user UUID semantics. Known missing, malformed or
unverified email means `promotion_ineligible`, never a UUID fallback. Absent/stale
evidence raises unavailable authority rather than issuing credit or recording
permanent ineligibility for an outage.

| SQLSTATE | Caller meaning |
| --- | --- |
| `22023` | Invalid input, source revision conflict, actor mismatch or readiness attestation; correct inputs before retry. |
| `55000` | Authority unavailable, invalid captured evidence or activation prerequisite incomplete; roll back and repair/refresh. |
| `55P03`, `40P01`, `40001` | Lock/transaction conflict; retry the complete authenticated transaction with bounded backoff. |
| Other SQL errors | Roll back; never convert infrastructure failure into a grant. |

Only trusted service-role/owner callers may invoke application mutators; tenant
`anon`/`authenticated` roles cannot publish evidence or claim directly.
Evidence/current/gate tables have no service-role direct mutation grants.
Reconciliation and activation are administrator-only. The service role is a
trusted backend boundary, not an end-user credential.

## Billing capture and durable reservations

Checkout captures `stripe_checkout_identity_evidence_version` atomically with its
initiating actor and generation before contacting Stripe. Resume retains that pin;
another billing writer cannot change Stripe parameters or the activation actor.
Definitive generation abandonment clears its pin with its actor. A delayed webhook
resolves the captured immutable version without reapplying the freshness deadline.
Only a legacy/external activation with no generation tag and no conflicting
Checkout capture may fall back to fresh evidence. Explicitly empty or malformed
generation tags are not equivalent to absent metadata.

Actor UUID alone is not a Checkout association. Subscription-event reservation
must prove the matching Checkout subscription or generation before using its
snapshot. If the same actor has a conflicting replacement snapshot, enabled
enforcement keeps the event retryable instead of borrowing that mailbox or
substituting current evidence. Recover the original subscription's trusted
association/evidence through audited reconciliation; do not clear the replacement
Checkout fence to force a grant. During the inactive rollout, such a grant keeps
an unresolved historical obligation rather than attributing the replacement key.

Use the [recovery-only Checkout operation](checkout-recovery.md) when identity
refresh fails. It retrieves only the original recorded session and revalidates
the actor/generation/evidence tuple under locks; it never creates a replacement.
Closing a non-active subscription's Checkout lease retains its subscription
association so later activation can still use the original actor and evidence.

The reservation additionally pins `stripe_activation_identity_evidence_version`
and identity. Ambiguous Stripe results retain the original durable fence; retries
never substitute a later email, event or actor. Independent $95 team uniqueness,
event/attempt ownership and deletion protections remain enforced. Captured evidence
travels before billing pins during team migration; importing a historical version
never marks it as a fresh current Auth observation.

Ambiguous credit-grant retries are bounded by the durable first-attempt time.
At 23 hours, the webhook returns an error requiring explicit settlement and
keeps its user, team, identity and event fences instead of replaying a Stripe
create after the provider may have discarded the idempotency result. This check
also runs immediately before the outgoing request. An old reservation that has
never attempted a grant can still make its first attempt. Operators must reconcile
the original provider result; age is never evidence that no grant occurred, and
clearing the attempt timestamp or changing the idempotency key is not recovery.

## Historical reconciliation

Migration snapshots retain consumed user/team facts and ledger-only grants.
Current Auth or regional email cannot prove the mailbox used for an old grant;
ambiguous history stays pending rather than being attributed to a current owner,
operator or present-day mailbox. An administrator uses audited evidence with:

```sql
reconcile_promotion_identity_history(
  p_history_key text, p_identity_keys text[], p_evidence_reference text,
  p_grant_outcome text DEFAULT 'granted'
) RETURNS void
```

For a consumed grant, enumerate all supported historical canonical keys; this
preserves consumption without issuing credit or altering existing balances.
`released` is only for proof that a pending Stripe grant did not occur, never a
refund of an issued grant. A later login cannot prove an old mailbox. Pending
history blocks activation; unresolved history imported afterward quarantines new
grants for that promotion rather than failing open. Profile/team deletion and
email changes cannot erase consumed entitlements.

Use disposable PostgreSQL and synthetic accounts to verify concurrent aliases,
mixed legacy/API claims, rollback, joining, missing/stale authority, delayed
webhooks, historical ambiguity, privileges and the activation lock. Production
activation and reconciliation require separately approved operator actions.
