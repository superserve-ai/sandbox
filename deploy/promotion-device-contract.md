# Signup device evidence and regional promotion authority

This is an additive server contract. Regional device enforcement ships off. The
existing canonical identity rollout and Stripe reservation requirements in
[promotion identity authority](promotion-identity-authority.md) still apply.
The grant integration routes the existing signup and Stripe writers through
the regional device authority. Keep the policy off until the selected region's
Console producer and all grant paths are ready.

## Original evidence source

The shared Auth PostgreSQL project owns `signup_device_attempt` and
`signup_device_account_evidence`. Apply the scripts in
`supabase/shared-auth-migrations/` in timestamp order **once to that project**,
separately from each regional migration chain. The immutability script revokes
Supabase's direct application-role table grants and guards accepted facts.
This store is server only, independent of East or West promotion databases.
Verified attempts and account bindings are retained indefinitely, including after
account deletion;
unverified attempts may be purged only after their verification window closes.
Database backups and migration rollback protection must retain the tables.

Console's server calls the following scoped control-plane routes, which execute
the corresponding shared Auth RPCs:

The control plane exposes these operations to Console through dedicated
credentials. Configure `PROMOTION_AUTH_DATABASE_URL` with access to the shared
Auth project, `PROMOTION_CAPTURE_TOKEN` for attempt creation and provider
attestation, and a distinct `PROMOTION_ACCOUNT_TOKEN` for binding, retrieval,
and selected-region registration. Missing or identical tokens deny requests;
an unavailable shared Auth database returns `authority_unavailable` and must
withhold credit. The regional database remains `DATABASE_URL`. Keep these
credentials server side; the VMD internal token and tenant API keys grant no
access. Every account operation also requires a signed
`X-Promotion-Account-Assertion`; `X-Actor-User-Id` does not establish identity.
Configure `PROMOTION_ACCOUNT_PUBLIC_KEY` with the standard base64 encoding of
its 32-byte Ed25519 public key. Missing or invalid keys reject account operations.
The private key belongs only to Console's trusted Auth adapter, separately from
the capture/account transport credentials; it is never deployed to the control
plane or provided to a browser. The adapter must derive identity from the Auth
signup result or a verified server-side session, never request fields. It must
not offer arbitrary subject signing to holders of a promotion transport token.
Console configures `PROMOTION_ACCOUNT_PRIVATE_KEY` as an Ed25519 PKCS#8 PEM
private key, with actual newlines. Its corresponding raw 32-byte public key,
standard-base64 encoded, supplies `PROMOTION_ACCOUNT_PUBLIC_KEY` in every
selected backend cell. Neither variable uses a `NEXT_PUBLIC_` prefix. Missing,
malformed or non-Ed25519 private keys withhold account requests before transport.

The adapter signs an EdDSA JWT with `iss: promotion-auth-adapter`,
`aud: promotion-account`, `sub: <Auth user UUID>`, `iat`, `exp`, and
`operation: bind|evidence|register`. Both times are required, expiry must be
later than issue time and at most five minutes after it, and future-issued or
expired assertions reject. For `bind`, also sign `attempt_id` from the
server-owned signup flow; for the other operations omit it. The control plane
verifies the signature, issuer, audience, time bounds, operation and exact
subject/body match, plus the attempt/body match for binding, before database
access. `X-Actor-User-Id` is required and must equal that verified subject and
the body's `user_id`; this is a consistency check, never login verification.
The account bearer credential remains required, so an assertion alone
never exposes evidence to tenants. The same assertion may retry its idempotent
operation during its lifetime; the adapter issues a new assertion for later
requests. This does not expire previously accepted device evidence.

A binding assertion can be issued from the trusted signup response before email
confirmation, without requiring a user session. Later retrieval and regional
entry use fresh assertions derived from the current verified session. An
assertion for one account or operation cannot authorize another.

### Console login verification and consumer handoff

For `/evidence` and `/register`, Console must use its existing request-scoped
Auth client and call `auth.getUser()` with the current login credential. An
Auth error, missing user, missing credential or invalid credential must stop
the operation before signing or calling the promotion backend. Derive the JWT
subject, actor header and body user ID only from the returned `user.id`. If a
caller supplies a target user ID, reject a mismatch with that verified ID.
Matching request fields, decoded JWT claims without verification, `getSession()`
alone and user-editable metadata do not establish the principal. Reuse the
existing login flow and Auth verification; this requires no additional database
connection or regional identity authority.

Keep the assertion signer server-only. It must not be exposed as a browser
action accepting an arbitrary subject, operation or attempt. Browser headers
and assertions must never be forwarded as promotion credentials. Console creates
the outgoing bearer credential, signed assertion, actor header and body itself.
Raw evidence responses remain inside the server and must not be returned to
the browser.

`/bind` has a separate provenance rule: retain the server-owned attempt and
bind it only to the actual account created by the trusted email signup result
or verified Google signup callback. Email signup can lack a session before
confirmation; do not require a login for this initial bind or defer persistence
until confirmation. A normal login is not authority to attach an arbitrary
attempt to an existing account. Later evidence reuse requires verified login
and uses the persisted binding without another capture or freshness check.

Console's server-only `promotion-device-evidence` adapter verifies the existing
login before retrieval and registration and signs each account request. Its
optional target user ID is only a consistency constraint; the verified Auth
result supplies the subject, actor header and body. The separate binding caller
retains trusted signup provenance before confirmation. Backend assertion tests
alone do not prove this consumer behavior. Deploy the matching consumer and
public key together, and keep device enforcement off until the consumer's tests
establish:

| Case | Required result |
| --- | --- |
| Missing, invalid or expired login; Auth verification error | No assertion, evidence request or regional registration |
| Verified user A with browser actor/body IDs for B, including matching forged IDs | Reject before signing or backend access |
| Valid login for A with no browser identity fields | Derive all outgoing identity fields from verified A |
| Browser-supplied promotion bearer token or assertion | Never use it for an outgoing promotion call |
| Trusted email signup before confirmation, without a session | Bind the server-owned attempt to the actual new account |
| Google signup callback | Bind only the attempt associated with that verified signup |
| Existing login months later in another browser, including West entry | Reuse A's original evidence and register in the selected region |

For signer interoperability, the Console producer test can write fresh request
fixtures to `PROMOTION_ASSERTION_FIXTURE_OUT`. Run
`TestPromotionAccountConsoleInterop` with `PROMOTION_ASSERTION_FIXTURE_IN` pointing
to that file within five minutes. It passes the actual Console assertions through
the backend middleware and handler identity checks for all three operations,
including matching forged actor/body IDs. The fixture contains a generated test
public key and assertions, never a private key or real account evidence. This
test skips without the fixture; an ordinary backend suite pass is not evidence
that the cross-runtime check ran. Record both producer and verifier execution.

The staging, production East, and production West Terraform roots each create
four cell-specific Secret Manager secrets. `promotion_evidence_enabled` defaults
to `false` in each root: a normal full apply creates the empty resources without
attaching them to Cloud Run or requiring secret versions. Apply the shared Auth
migrations first, then set a password on the `promotion_evidence_proxy` database
role. Its URL secret must
connect as that role; the role has only `USAGE` on `public` and `EXECUTE` on the
four signup-evidence RPCs, with no direct evidence-table privileges. Create
the empty secret resources with a normal full Terraform apply, then publish an
enabled version of each through the operator secret workflow. Only after all
four versions are available, persist `promotion_evidence_enabled = true` in that
cell's Terraform configuration and apply again to bind their latest versions
and grant the control-plane runtime access. This integration switch does not
enable device enforcement. Terraform never stores those values. Keep the capture
and account tokens different from each other and from `INTERNAL_API_TOKEN`; a
missing or reused token rejects producer requests. A missing shared Auth
connection or failed RPC returns `authority_unavailable` and withholds credit.

Before enabling device enforcement in either production region, verify that
each cell's serving revision has all four secret-backed environment variables,
that both scoped credentials work only on their own routes, account assertions
reject unsigned or mismatched actors, and that original evidence can be
retrieved and published to the selected region. Check both
regions independently, including delayed West entry. Keep the device policy
off until these checks and the inherited canonical activation prerequisites
have passed.

| Operation | Route | JSON input | Result |
| --- | --- | --- | --- |
| Create attempt | `POST /internal/promotion/signup/attempts` | Empty body | `attempt_id`, `challenge` |
| Verify | `POST /internal/promotion/signup/attempts/verify` | `attempt_id`, `challenge`, `event_id`, `fingerprint`, `event_at` | `verified` or `replayed` |
| Bind | `POST /internal/promotion/account/bind` | `user_id`, `attempt_id` | `bound`, `replayed`, or `first_evidence_retained` |
| Retrieve | `POST /internal/promotion/account/evidence` | `user_id` | Original bound evidence; `evidence_missing` if absent |
| Register locally | `POST /internal/promotion/account/register` | `user_id` | `owner` or `owner_conflict` |

The registration route reads the original binding from shared Auth itself and
passes that exact evidence to the selected region's SQL function. A regional
registration request cannot provide a new event or Fingerprint. Requests are
limited to 4 KiB and database work to three seconds; SQL errors are not
interpreted as eligibility. Invoke the register route on the selected regional
control plane before the grant decision, including delayed West entry.

The control-plane routes above invoke the following shared Auth operations:

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
   from that trusted server result, never an email lookup or browser parameter,
   and sign the matching account/attempt assertion for the bind route.
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

The shared Auth database credential is kept by the control plane. These RPCs
and tables grant no access to `anon` or `authenticated`.
A missing shared source, failed provider lookup, failed actor check, or ambiguous
binding withholds promotional credit; it does not block signup, team creation or
normal paid access. Console must not infer evidence from cookies, visitor IDs,
editable Auth user metadata or telemetry. Provider attestation field details
belong to the Console integration; it must compare the provider's event metadata
with the issued challenge and use the provider's server result.

## Regional publication and claims

Apply `20260927003551_regional_promotion_device_authority.sql` in **each**
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
`evidence_missing`, `owner_conflict`, `device_already_redeemed` or
`device_reservation_pending` for promotion
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
a newly changed policy. `device_reservation_pending` withholds a new reservation
while another account's grant on the same device remains unresolved. The reservation
pins the original Fingerprint in the regional entitlement row; release
allows a later retry. Finalization records actual Stripe issuance in
`promotion_device_grant` in the same regional transaction by calling
`record_stripe_promotion_device_grant(team_id, user_id)` and retains
the existing actor, evidence and checkout-generation pins. It must
not contact Stripe before a durable reservation or release an uncertain attempt.

The existing `claim_team_signup_trial` entry point now routes through the device
claim. Explicit team creation and legacy completion triggers use the same
decision. A promotion authority error completes an initial claim with
`promotion_ineligible` and `authority_unavailable` without awarding credit or
aborting team creation. Existing Stripe reservation signatures also route
through the device reservation before external credit. A promotion authority
error skips the credit while paid activation continues. Finalization records
the device grant with the settled Stripe grant in one regional transaction.
Recoverable or uncertain external attempts retain their reservation.
An ambiguous database transport failure during reservation is retried because
its commit state cannot be inferred from the lost response.

`POST /internal/promotion/account/signup-eligibility` accepts `user_id` under
the account credential and matching `X-Actor-User-Id` header. Call it in East
after trusted account binding and regional registration, before the original
signup notification. It returns `ownership` (`owner`, `another_owner`, or
`evidence_missing`), a policy-aware `device_decision`, and `eligibility` with
a safe `reason`. `eligibility=unknown` covers pending team checks and unresolved
canonical evidence, including pre-confirmation identity. This snapshot creates
no grant, claim, or reservation. The $5 claim rechecks authority atomically.
The response contains no Fingerprint or other account identifier.

The `promotion_device_policy` row starts with D=off and E=off. The canonical C
gate remains the existing `promotion_identity_enforcement` authority. A
configuration with C=off and either D or E on is invalid. Once C is on,
`set_promotion_device_policy(D)` defaults E to the same value, while the
two-argument form permits all four D/E combinations. D=off bypasses device
denial only; registration and actual-grant recording continue. Missing evidence
creates no owner. Policy changes never delete ownership, grants or pending
reservations. Existing balances, claims and reservations are untouched, with
no historical device reconstruction or cross-region financial reconciliation.

Deploy the shared source and each regional schema before its Console producer
and grant path integration. Verify initial East publication and later West
publication independently. Keep enforcement off in a region until its canonical
readiness, producer coverage, and every local grant writer have been verified.
