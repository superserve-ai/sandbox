# Signup trial rollout

The promotion migration is an **expand** deployment. It must remain compatible
with the deployed Console's direct database provisioning while team creation
moves behind the control-plane API. The Stripe activation promotion is
independent of this caller migration.

## Expand: shared promotion authority

Deploy the entitlement tables, historical backfill, and compatibility triggers
before switching callers. Do not drop `team_signup_trial_credit` in this phase.
Its new implementation records pending signup provenance instead of issuing an
unconditional grant.

The legacy Console writes a team, its initial legacy owner, active membership,
and finally a `team_owner` assignment in separate transactions. The first owner
insert binds the initiating actor. The final matching owner assignment claims
that actor's trial and grants $5, or records a denial, in the same transaction.
Adding members or replacing owners after completion never opens a new claim.
An unfinished team is not eligible for free compute.

The explicit `create_team_with_signup_trial` operation uses the same claim
authority. Its caller must authenticate the actor and include team creation,
membership, owner assignment, and claim in one database transaction. These
mutating functions are not tenant-facing RPCs.

The additive identity schema initially keeps canonical enforcement off, preserving
the UUID-based claim policy while recording every grant for reconciliation.
Deploy the trusted Console profile/evidence writer next, including existing users
and billing entry in every cell. It atomically stores raw Auth evidence locally;
there is no live Auth database bridge or trust in regional profile email.
After historical reconciliation, pending-billing settlement and rollback readiness,
an administrator separately enables canonical enforcement. See
[promotion identity authority](promotion-identity-authority.md) for exact interfaces
and the activation gate. Once enabled, known missing/unverified email permits a
team without a grant, but unavailable/stale authority aborts provisioning without
falling back to a user-ID-only claim.

Before legacy completion, a failed write consumes no claim. A lost response
after the final owner transaction commits is a successfully provisioned team,
not grounds to refund its entitlement. While that completed legacy team's
signup grant exists, scoped last-owner protections reject compensating cleanup
that would strand the team without an owner. Ordinary team deletion does not
refund a claim. Administrative removal requires removing dependent grants
first, while preserving the consumed user claim.

The migration locks legacy creation tables across the backfill and trigger
transition. It adopts only tightly shaped unfinished legacy chains with one
anonymous creation-time $5 grant and no role, audit, or sandbox history. It
preserves that grant's balance instead of issuing another. Ambiguous historical
teams are not reopened using current owners or an age-based heuristic. A fully
scrubbed historical orphan is indistinguishable from an unfinished creation;
operators should inspect such rows before rollout if cleanup history is known.

Trusted team imports must discard newly created pending provenance before
copying the existing owner chain, then restore the original credit ledger.
Importing ownership must never mint a new signup grant.
Merge consumed signup claims and the team's denial marker into the destination
before exposing copied ownership, preserving existing destination claims. A
source claim associated with a different or deleted team must still remain
consumed even when its team association cannot be copied. This transfers known
state during migration; it does not provide coordination between independently
active cells.
Include departed creators identified by completed legacy provenance. For denied
teams, retain that completed creator link so later moves can still locate the
consumed claim; pending provenance is never imported as a new claim.
Canonical consumed keys and bindings, completed outcomes, and historical evidence
travel before ownership or billing-account pins. Pending Stripe reservations
must be settled before migration. Conflicting historical evidence between cells
blocks the move until reconciled; a reconciled destination record cannot erase
an unresolved source obligation. Neither migration nor deletion refunds credit.
Copy, detach and purge require a destination administrator credential with
promotion-history privileges. The ordinary application service role cannot
rewrite historical evidence; the migration tool rejects it before destination
mutations. Keep that restriction rather than granting history writes to the API.
An unexpanded source must run its promotion backfill before moving a team into
an expanded destination; otherwise the tool cannot prove past consumption.
After validating the destination, the migration tool retires the source's
legacy cleanup guard atomically with detaching ownership. The source's consumed
claim and original ledger remain intact.

Promotion-bearing moves also require a source administrator credential. Before
copy publishes destination ownership, the tool locks the source promotion actors,
canonical identities and team, rejects pending grants, and commits a source-only
`stripe_promotion_migration_fence`. Promotion snapshots and ownership copy then
run while holding those scoped source locks. Detach and purge repeat the checks.
The fence is not copied to the destination and survives source team deletion.
It denies new source $95 reservations without consuming an entitlement or changing
the Stripe customer, subscription, paid-billing state, or historical ledger.
Existing reservations must be settled first; migration never discards them.

A failed or interrupted copy retains the committed source fence. Retrying the
move is safe; simply canceling the tool does not restore source promotion
admission. To roll back the move, an administrator must first stop or fence the
destination team and settle every pending destination grant, reconcile consumed
promotion state back to the source, and only then remove that team's source
fence under the same promotion locks. Never reopen both cells. Webhook events
processed while fenced may already have acknowledged their normal subscription
update without a promotion; removing the fence does not replay those events or
promise a replacement grant. This is a per-team migration admission guard, not
global entitlement coordination across independently active cells.

## Switch: authenticated API and Console integration

The companion change owns the team-creation HTTP API and Console integration;
the promotion migration does not introduce either. The API must derive the
actor from verified user authentication, preserve signup/CAPTCHA proof checks,
use the correct regional database, and commit the complete provisioning chain
atomically. A shared service key plus an arbitrary caller-supplied user ID is
not sufficient authentication.

Switch first-login auto-provisioning and explicit team creation to that API in
every deployed cell. During the transition, old and new callers share the same
database claim. Rollback to the old Console writer is safe only while the
compatibility triggers remain installed.

## Contract: a separate later migration

Do not ship a runnable trigger-removal migration alongside the expand change:
automatic database deployment would apply both phases together. Prepare it in
a separate change only after all of the following are evidenced:

- The authenticated API is deployed and verified in every cell.
- Both Console creation paths use it, including retries and failure handling.
- Controlled tests show one $5 grant across concurrent old/new attempts,
  join-before-create eligibility, and rollback without a consumed claim.
- No deployed caller or supported rollback can restore the incompatible direct
  database path. Retire that fallback before removing compatibility.
- Pending legacy chains are completed or explicitly reconciled; none are
  silently abandoned when their completion trigger is removed.

The contract migration must make explicit creation independent of the legacy
team trigger before dropping it, remove obsolete compatibility functions and
guards deliberately, and retain durable claims, denials, and historical audit
state. Re-run provisioning, concurrency, migration, billing, and rollback
tests. Database rollback must not restore the unconditional per-team grant.
