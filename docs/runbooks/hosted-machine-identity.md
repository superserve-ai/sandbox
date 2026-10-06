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
the proxy never infers ownership from a human `owner_id`.

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
result against the 30-second maximum.

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

## Compatibility and activation gate

The supported serving revision is `machine-identity-v1`: the schema migration
`20261006000200_hosted_machine_identity.sql`, the API `CallerContext` resolver
and route gate, the `mcap.v1` verifier, and the proxy session registry must be
deployed as one compatible set. A serving instance is **ready** only when its
health/readiness check reports all four surfaces present, the authority lookup
is available, and the proxy is configured with the machine revocation resolver.
Issuance and activation remain disabled until every serving instance in the
deployment reports that revision and the recreate-without-backfill plan has
completed.

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
