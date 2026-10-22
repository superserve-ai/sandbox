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
per frame or during VM startup. A lookup failure denies access; explicit or
contradictory machine attestations cannot be downgraded. A proxy with no
ownership database treats these records as ordinary: it cannot pass machine
readiness, so no machine-owned sandbox is served through it. Configure
`PROXY_DATABASE_URL` on every serving proxy, including proxies with peer routing
disabled, before enabling issuance. Authorized team API keys receive a typed `mcap.v1` child with
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
| `POST /principals` | JSON `team_id`, `hosted_tenant_id`, `approved_template_id`; returns the same fields as the read below. |
| `GET /principals/{principal_id}` | Returns exactly `principal_id`, `team_id`, `hosted_tenant_id`, `status`, `generation`, and `approved_template_id` for lifecycle fencing. |
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
`20261016150934_hosted_machine_identity.sql`, the API `CallerContext` resolver
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

## Production East configuration

The `infra/envs/production/us-east4` root accepts the nullable
`qm_machine_identity_activation` object. Its default is `null`, which emits no
`QM_MACHINE_AUTH_*` fields and keeps issuance disabled. Deploying this source
with the default does not activate machine credentials.

The object requires `contract_revision = "machine-identity-v1"`,
`environment = "production"`, and explicit `ownership_ready`, `verifier_ready`,
and `operator_ready` booleans. Each boolean requires the corresponding deployed
ownership, verifier, and operator/staging evidence described above. False
predicates remain false and keep issuance disabled. The configured environment
is derived independently from the root's environment; a non-null record is
rejected outside the production project and East region. The API additionally
checks authority schema readiness at startup; there is no schema-ready input
that bypasses that check.

Before supplying an activation record, bind compatible API/schema/VMD receipts,
probe every serving proxy, and collect the operator lifecycle, revocation and
recovery evidence above. An operator-token secret reference or an ordinary
health check alone is insufficient. Team creation, private template readiness
and normal billing eligibility are separate prerequisites.

Review the production plan through the existing deployment process. Activation
changes the regional API revision and enables issuance for all authorized
operators in that region, not just one tenant. The intended change is the six
API environment fields; unexpected changes require reconciliation. Source
changes may still run the normal shared deployment workflow even with null
input. After an approved release, verify serving traffic, all six fields and
fresh proxy readiness before the bounded operator invocation. Removing the
record disables new issuance; it does not revoke credentials or stop workloads.
Use the existing revoke/disable and containment procedures for those actions.

### Supervised initial commissioning

A release may explicitly approve a one-time internal commissioning exception
to the full prior deployed/staging validation requirements above. This is a
separate decision from deferring automated revocation monitoring. It permits
initial activation from verified component and operator capabilities so that
retained functional proofs can follow activation; it does not record those
unperformed proofs as passed or relax the executable authorization checks.

Before activation, bind the actually serving reviewed API, schema, VMD, proxy
and client contract; verify every serving proxy's machine readiness; and bind
the released protected operator credential version, material custody, fixture,
supervisor, cleanup executor and host reclamation observer. Review the full
infrastructure plan and its shared deployment effects. The API's startup schema
check, ownership restrictions and five-second fail-closed enforcement remain
required. A hypothetical plan's true values describe proposed effects only;
they are not readiness evidence or permission to merge or apply.

The commissioning approval must explicitly allow these capability attestations
before the retained live proofs are available. After activation, perform the
bounded principal/credential operations, positive-controlled isolation,
revocation-caused stream closure and denied reuse, then workload termination
and host reclamation. Only passing those retained checks permits the separately
released runtime agent proof. Failed or inconclusive proof stops the affected
operation and invokes only its authorized containment. Do not claim broader
lifecycle acceptance or automated monitoring from this supervised test.

Activation applies to all authorized operators in the region. It has no
executable test-team allowlist or automatic expiry. Bind the test's cessation
and the separately approved activation disposition explicitly; completion of
the test does not remove the flags, revoke credentials or stop workloads.
General customer rollout still requires the original readiness obligations or
its own explicit disposition.

#### Explicit commissioning input

The example `infra/envs/production/us-east4/qm-machine-commissioning.tfvars`
is not auto-loaded. Ordinary PR plans and Terraform CD omit it and retain the
default-null record. Do not rename it to `terraform.tfvars` or `*.auto.tfvars`,
or inject it through shared workflow environment variables. Its true values
are hypothetical until the commissioning approval and receipts above exist.

For a separately authorized plan-only inspection, use the reviewed source
revision, existing production credentials/backend and the same reviewed root
inputs as the East deployment job, then explicitly select the file:

```sh
cd infra/envs/production/us-east4
terraform init -input=false
terraform plan -input=false -lock-timeout=5m \
  -var-file=qm-machine-commissioning.tfvars -out=commissioning.tfplan
terraform show commissioning.tfplan
```

Keep the saved plan protected; it can contain sensitive state. This inspection
does not apply, pin traffic or prove readiness. Review all root effects, not
only the six machine fields. Default CI plans do not verify this explicit
enabled input against production state.

Applying requires a separate released operation. The release coordinator must
bind the source, input, target and current readiness receipts, coordinate the
East deployment window, and preserve the existing East migration receipt,
serving-revision pin, host-logging, host-migration, control-plane identity and
proxy-frontend plan guards from `terraform-cd.yml`. After the approved traffic
pin, create a fresh plan with the explicit `-var-file` above, run those guards,
and obtain approval of that exact saved plan before `terraform apply
-input=false commissioning.tfplan`. Verify the new revision's identity and image
before promotion. Then promote it and verify that revision serves 100% of
traffic, followed by the existing health and regional smoke checks. Checking
the public endpoint while traffic remains pinned only tests the old revision.
Do not dispatch ordinary Terraform CD as an activation substitute.

The manually supplied record is not persisted as a default source input.
A later ordinary CD apply removes its fields and disables new issuance; it
does not revoke credentials or stop workloads. The commissioning release must
bind that subsequent-deployment behavior and its explicit removal/containment
plan. Coordinate only the affected East runs during the bounded test, not a
global CI/CD hold, and verify activation before issuance. Unexpected disablement
stops test progression while preserving cleanup; do not silently re-enable or
reissue. Continuing activation across ordinary deployments requires a separately
reviewed configuration release, but is not a prerequisite for this bounded test.

## Restoring the source after the coordinated-rollout revert

PR #683 reverted PR #660 before its migration or deployments ran. The restored
migration is `20261016150934_hosted_machine_identity.sql`, ordered after the
newer billing migrations with unchanged SQL. Before applying it, verify that
no earlier hosted-machine migration was applied in the target environment;
stop for reconciliation if its schema or migration history is already present.

Install the schema before deploying the API or a database-backed proxy: ordinary
routing and ownership queries also use the new ownership table. For an initial
rollout with no existing machine credentials or workloads, VMD, proxy and API
upgrades may otherwise overlap while issuance remains disabled. VMD tolerates
the absent machine schema, and the new proxy supports legacy VMD ownership
records. Issuance disabled does not revoke existing credentials; verify the
initial-rollout assumption before relying on mixed-version compatibility.
Before enabling machine use, deploy compatible components everywhere and
validate readiness, ordinary-client compatibility, tenant isolation and
revocation. A dedicated backing team does not relax principal ownership checks inside
that team. Team provisioning and billing policy remain separate integrations.
