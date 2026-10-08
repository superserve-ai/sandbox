# Hosted QM machine identity contract

This document is the sandbox-side handoff for the hosted QM machine-identity
boundary. It describes interfaces and rollout obligations; it is not evidence
that hosted issuance is enabled.

## Verified caller contract

The API authentication layer resolves a credential to a `CallerContext` with
stable `principal_id`, `credential_id`, `lineage_id`, `team_id`,
`hosted_tenant_id`, explicit operation permissions, `audience`, `expires_at`,
and `revocation_generation`. The caller policy is an explicit default-deny
allowlist of the known QM operation inventory; unknown/future operations are
rejected before capability derivation. Proxy and peer routes forward this
verified context or a server-issued `MachineCapability`; they never trust
public actor, team, creator, or ownership headers.

Machine capabilities additionally bind one `sandbox_id`. A child capability
must keep the parent principal, team, credential lineage, audience, and
revocation generation, use a subset of the parent operations, and expire no
later than the parent. Legacy sandbox-only tokens are not a machine fallback.

The sandbox-side wire form is `mcap.v1.<base64url-payload>.<base64url-HMAC>`.
The payload contains principal, credential and lineage references, team,
sandbox, explicit operations, audience, expiry, and revocation generation.
Verifiers reject unknown versions/fields, invalid signatures, expired values,
and generations that are no longer current. Peer forwarding carries this
verified capability, never an actor or team header.

The proxy resolver/VMD attestation for a machine-owned sandbox must include
`machine_owned`, the durable `machine_owner_principal_id`, and `team_id`.
Machine capabilities are rejected when any binding is absent or mismatched;
the proxy never infers ownership from a human `owner_id`. A VMD response also
attests `ownership_state` as `machine`, `ordinary`, or `unknown`. For an existing
ownerless record with no machine attestation, or an old VMD response that omits
the ownership field and carries an ordinary creator UUID, the proxy verifies
its live team and owner association through the restricted database role after
verifying the request token. This supports proxy-first upgrades without treating
the creator as ownership proof. Only confirmed absence establishes ordinary ownership. These
reads have a 500ms deadline, share a bounded five-second cache, and never run
per frame or during VM startup. Missing configuration or lookup failure denies
access; explicit or contradictory machine attestations cannot be downgraded.
Configure `PROXY_DATABASE_URL` on serving proxies before rollout, including
proxies with peer routing disabled. Authorized team API keys receive a typed `mcap.v1` child with
`caller_kind=api_key`, the verified `parent_credential_id`, team, operation
subset, and `sandbox-proxy` audience. Expiry is capped at the earlier of fifteen
minutes and the parent key expiry. An API key creator is not a verified human
session: these claims omit actor identity and machine-owner lineage. The
`human` kind is reserved for independently verified human sessions; the API-key
producer does not issue it. Ownership lookup failures never produce legacy
capabilities. Ordinary sandboxes retain legacy compatibility after confirmed
absence of a machine-owner association.

Attribution consumers can read `VerifiedMachineCallerFromContext` after API
credential verification, including route denials, without treating it as an
authorization grant. Proxy `VerifiedCallerFromContext` carries authenticated
identity through resource and operation denials; failed authentication has no
verified caller. API-key claims identify their parent key, never its creator as
the current user. Peer destinations independently verify the capability.

Resume returns the immutable ownership association in the existing claim
statement and reuses that result for VM publication and token production.
Ownership verification adds no separate round trip to the resume path.

## Durable lifecycle handoff

The authorized control-plane/provisioning actor owns these fenced operations:

| Operation | Required outcome |
| --- | --- |
| Ensure principal | One immutable principal for exactly one hosted tenant/team; retries return the same principal. |
| Issue | Create a fresh credential lineage only while the principal is active. |
| Rotate | Preserve principal and sandbox ownership; revoke the replaced credential according to the bounded rotation policy. |
| Revoke | Invalidate one credential, its descendants, and associated sessions. |
| Disable | Invalidate every credential and block new issuance. |
| Restore | Reuse the same principal during the authorized same-tenant seven-day recovery window and issue fresh credentials; old generations remain invalid. |

Credential issue, rotate, and restore requests carry an operation ID and
expected generation; rotation also binds the replacement target. The server
supplies the permission/audience policy and hashes the supplied credential.
The authority stores the input digest and resulting credential ID atomically.
A matching response-loss retry returns the recorded credential with its current
state and original expiry, including revoked state after disable. Conflicting
reuse, stale generation on a new operation, or an invalid replacement is denied
without mutation. Ensure uses the immutable tenant/team tuple; credential
revoke is monotonic and idempotent. Disable also requires an operation ID and expected generation;
its durable result prevents a delayed retry from disabling a restored
generation. Rotation validates and locks the active current-generation
replacement before revoking exactly that row.

Runtime machine credentials cannot invoke these operations or change tenant,
team, owner, scope, or template associations. Secret payloads and credential
material remain in the owning delivery workflow; logs contain only safe IDs and
denial context.

Serving instances keep bounded in-memory session registrations. A stream
registers once at handshake and unregisters on every exit path; each request
or continuation checks the local generation/expiry snapshot without a
per-frame database call. Durable revoke/disable invalidation closes matching
registrations immediately, while bounded freshness refresh fails closed when
the authority store is unavailable. Deployment must measure the multi-instance
result against the 30-second maximum. Local response transports and remote
edge bridges close on cancellation, including when a client stops reading.

Machine API bodies are limited to 1 MiB and read under a five-second socket
deadline before credential verification. Authority lookups have a separate
bounded deadline; neither limit shortens VM startup. Runtime machine request
capture is excluded from error reporting to protect credential material.

## Operator administration transport

Provisioning and credential-delivery owners invoke the sandbox API over TLS
using `Authorization: Bearer <operator credential>` backed by
`OPERATOR_API_TOKEN`. The infrastructure `INTERNAL_API_TOKEN`, tenant API keys,
and runtime machine credentials cannot administer identity. Requests carrying
`X-QM-Machine-Credential` are rejected even when an operator token is also
present. The operator token must never be delivered to a hosted runtime.

All routes below are under `/internal/machine-identity`:

| Method and path | Request and result |
| --- | --- |
| `POST /principals` | JSON `team_id`, `hosted_tenant_id`, `approved_template_id`; returns the immutable principal and current generation. |
| `GET /principals/{principal_id}` | Returns `principal_id`, `team_id`, `hosted_tenant_id`, `status`, and `generation` for lifecycle fencing. |
| `POST /principals/{principal_id}/credentials/issue` | Fenced credential request; returns credential metadata. |
| `POST /principals/{principal_id}/credentials/rotate` | Fenced credential request plus `replacement_credential_id`; replaces only that credential. |
| `POST /principals/{principal_id}/credentials/restore` | Fenced credential request; restores the same principal within its recovery window. |
| `POST /principals/{principal_id}/disable` | JSON `operation_id` and `expected_generation`; disables the principal and its credentials once for that fence; returns 204. |
| `POST /credentials/{credential_id}/revoke` | Revokes that credential; returns 204. |

A fenced credential request contains `operation_id` (a nonzero UUID),
`expected_generation` (the positive generation just read), and
`credential_material` (canonical unpadded base64url of 32 cryptographically
random bytes). The external delivery owner generates the material once,
stores it securely before invocation, and reuses the exact material and
operation ID after a lost response. The runtime presents that encoded string
as its machine credential. Secrets belong only in the TLS-protected request
body, never in URLs or logs. Responses contain only `credential_id`,
`principal_id`, `lineage_id`, `state`, `expires_at`, and
`revocation_generation`; they never return credential material. The server
supplies operation permissions, audiences, expiry, and lineage policy.

JSON bodies are limited to 4 KiB and reject unknown fields or trailing values.
Invalid request fields return 400; missing/wrong operator authentication returns
401; a mixed runtime/admin identity returns 403; state/fence conflicts return
409; unavailable or unconfigured authority returns 503. Readiness gates apply
to principal creation, issuance, rotation and restore. Revocation, disablement,
and principal reads remain available when issuance is disabled. Operator
callers must handle an uncertain result by reconciling or retrying the same
operation rather than creating a second credential.

Invocation scheduling, protected delivery to the dedicated runtime, activation
of the replacement credential, shutdown/quarantine, and client rollout belong
to their respective control-plane owners. A successful local API test does not
establish that those integrations are deployed. After PR creation and before
production issuance, rollout, or completion, record staging evidence for:

- multi-instance revocation and active-stream closure within 30 seconds of the
  durable commit, including lost notifications and unavailable authority;
- operator invocation, response-loss retries, rotation, creator offboarding,
  disablement and same-tenant restore with fresh credentials;
- recreated sandbox ownership, legacy/downgrade refusal, approved-template
  enforcement, compatible clients, and safe attribution on both API and proxy;
- production revocation monitoring: the sandbox lifecycle owner must provide
  a durable post-commit revocation signal; the attribution/collector owner must
  preserve safe credential references and correlate existing session start and
  completion events. Validate loss/restart behavior and the 30-second alert in
  staging before issuance. Request logs alone are not a durable audit ledger,
  and this PR does not claim the monitor is deployed.

## Ownership and rollout seam

Sandbox creation atomically records `{sandbox_id, owner_principal_id, team_id}`
from the verified caller. List pagination, known-ID reads, metadata, lifecycle,
token issuance, command/file routes, reconnects, and peer forwarding require
both team and owner equality. Missing or unverifiable ownership fails closed.
Approved QM template identity is resolved server-side. Machine creation rejects
arbitrary template aliases, snapshots/clones, and stored-team-secret bindings
before privileged lookup. Ordinary human/admin authorization remains separate.

Deploy compatible schema, API, proxy, client, and verifier revisions before
enabling issuance. Existing pre-fix hosted sandboxes are recreated under the
machine principal; ownership is never backfilled onto historical rows. Rollout
must prove multi-instance revocation and active-stream disconnect within 30
seconds of durable commit, authority-refresh failure behavior, creator
offboarding, rotation, same-tenant restore, safe logs, and downgrade refusal.
Credential revocation does not replace the lifecycle owner's workload
quarantine/stop procedure.

The serving authority uses a five-second absolute freshness budget. Active
streams refresh independently of frame activity and cancel at the deadline on
failed, hung, invalidated, or late authority fills; admission and registration
share the same deadline. Refresh work is coalesced and bounded, and session
fences are compacted with an epoch so an older in-flight verification cannot
re-enter after invalidation.

## Compatibility and activation gate

The supported serving revision is `machine-identity-v1`: the schema migration
`20261008000001_hosted_machine_identity.sql`, the API `CallerContext` resolver
and route gate, the `mcap.v1` verifier, and the proxy session registry must be
deployed as one compatible set. A serving instance is **ready** only when its
health/readiness check reports all four surfaces present, the authority lookup
is available, and the proxy is configured with the machine revocation resolver.
Before enabling issuance or admitting a rollback target, probe `/health` on
**every serving proxy** with `Host: proxy-machine-readiness.invalid`. Require
HTTP 200, `machine_identity_ready: true`, and
`machine_identity_revision: machine-identity-v1`. This probe includes the
ordinary resolver/routing checks and bounded machine-authority/ownership
schema reads using the restricted database role. Missing database
configuration, missing compatible schema/permissions, or an unavailable
lookup remains incompatible. Ordinary `/health` success alone is not machine
readiness evidence. The existing VMD probe must attest the matching ownership
protocol. VMD also withholds machine records from proxies that do not declare
that protocol, preventing an older verifier from accepting legacy tokens for
a machine sandbox.

The deployment must also provide `QM_MACHINE_AUTH_CONFIGURED_ENVIRONMENT`; the
activation record's `environment` must exactly match that independently supplied
value. Unsupported revisions or arbitrary non-empty environment values remain
ineligible.
Issuance additionally requires an explicit activation record containing the
contract revision, environment, schema readiness, ownership-producer
readiness, verifier readiness, and operator/staging eligibility. Missing or
incompatible values keep issue, rotate, restore, and principal/template
creation disabled; revoke and disable remain available. Authentication
startup alone never enables issuance, and eligibility is invalidated whenever
the supported revision or verifier policy changes.

Rollback is permitted only to another revision that rejects legacy machine
capabilities and creator-derived hosted issuance. A downgrade that lacks the
route gate, owner relation, generation checks, or active-stream cancellation
must fail its readiness check and cannot receive newly issued credentials.
The provisioning, secret-delivery, lifecycle-containment, QM client, and
attribution owners must each provide their issue/rotate/revoke/disable/restore,
delivery, shutdown, client-version, and verified-caller readiness evidence
before activation. Staging measurements for active-stream revocation,
authority-refresh failure, restore/rotation, sandbox recreation, and safe
attribution remain required pre-production gates; this local checkpoint does
not claim those measurements passed.
