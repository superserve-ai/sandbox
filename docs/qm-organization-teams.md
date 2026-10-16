# Organization backing teams

The QM provisioner creates an internal Superserve team for each QM organization.
This path creates no profile, user, membership, owner role, or signup promotion.
Existing customer team creation is unchanged.

The central authority serves `POST` and `GET` at
`/internal/qm/organizations/{qm_org_id}/team`. POST accepts only
`{"idempotency_key":"qm-org:v1:<canonical organization UUID>"}`; GET requires
that same key as its only query parameter. Both authenticate with the dedicated
`X-QM-Team-Service-Token` header. Customer API keys and human sessions are not
accepted. The service credential must not be reused from host or operator APIs.

A successful response contains `qm_org_id`, `idempotency_key`, `ss_team_id`,
`namespace`, and `authority_id`. Only an authenticated 404 with
`error=organization_team_absent` and matching organization, key, namespace and
authority means absence. A timeout, malformed response, conflict, or deleted
team is not absence. Retrying POST with the identical key is safe even when an
earlier transaction is still committing. The unique binding has no expiry.

Team and binding creation share one database transaction and an organization
advisory lock. Team names do not authorize adoption. Deleting the team permanently
tombstones its binding, including if someone later reinserts the same team UUID.
Deleting or replacing a QM deployment must never call a team deletion endpoint.
The cell-migration tool refuses teams with organization bindings, including
tombstones, because their permanent authority cannot be moved independently.

## Billing and runtime authority

The immutable organization binding is also the protected managed-billing policy.
It is inserted before the team in the same transaction, so human signup and
checkout initialization never run for that team. Database guards reject signup
credits and individual Stripe customer/subscription enrollment, including writes
from older API versions. Sandbox billing eligibility recognizes the managed payer;
normal abuse controls and machine authorization still apply.

Compute/storage intervals and hourly usage stay attributed to the Superserve team.
Provisioning explicitly enables metrics and hourly rollups. No billing-disabled
flag or synthetic subscription is used. QM's customer charging remains a separate
service concern.

Machine principals are created under the verified backing team and retain their
tenant, template and sandbox ownership restrictions. Only the scoped machine
credential reaches a tenant runtime. Team creation and machine administration
credentials remain in the control plane. Two-organization integration coverage uses
real credential resolution, scoped sandbox creation, cross-team denial and the
production usage-rollup query with a synthetic VM transport.

## Provisioning signals and billing cost

Authenticated, validated provisioning calls emit `qm_team_provisioning_attempt`
and `qm_team_provisioning_outcome`. Both contain namespace, method and the stable
SHA-256 `qm_org_ref` correlation value. Outcomes are `bound`, `absent`, `deleted`,
`conflict` or `unavailable`, with duration and the team ID only when bound. Tokens,
request bodies, raw errors and organization IDs are not logged by these events.
Alert on organization correlations with attempts but no `bound` outcome over
15 minutes. These events run on provisioning calls, not sandbox create/resume.

The managed-billing predicate performs a unique `team_id` lookup and verifies the
immutable authority. Its PL/pgSQL query plan is reused across calls. The existing
eligibility read remains synchronous on a cache miss so the verdict comes from
the same database snapshot; there is no new network round trip or separately
maintained policy cache. Existing singleflight, 30-second eligible/3-second
ineligible TTLs, bounded cache size and `billing_eligibility_ms` measurement remain.

`BenchmarkQMManagedBilling` compares the prior eligibility body with the managed
branch and executes the production active-team sweep. Local PostgreSQL 16 results
with warm database pages, no application cache, and local container round trips:

| Bindings | Ordinary eligibility, baseline / managed branch | Sweep, baseline / managed branch |
| --- | --- | --- |
| 1 | 0.330 / 0.358 ms | 3.59 / 5.44 ms |
| 1,000 | 0.370 / 0.371 ms | 7.07 / 11.68 ms |
| 100,000 | 0.370 / 0.390 ms | 7.93 / 10.94 ms |

The sweep fixture has 500 ordinary teams, up to 500 managed teams and four active
sandboxes per team. It deduplicates before eligibility evaluation. The unique
lookup touched five shared buffers at 100,000 bindings; it did not scan the binding
fleet. Reusing the predicate plan reduced that fixture's sweep from 35.63 to
10.94 ms. The background sweep still scales with distinct active teams; its output
limit does not cap candidates inspected. These measurements do not model cold
database pages, network latency or a 100,000-active-team sweep.

Reproduce with a disposable migrated database:
`go test -tags integration ./internal/integration -run '^$' -bench '^BenchmarkQMManagedBilling$' -benchtime=1s -count=1 -v`.
The benchmark rolls back its fixtures and emits `EXPLAIN (ANALYZE, BUFFERS)` plans.

## Deployment

Configure `QM_TEAM_SERVICE_TOKEN`, `QM_TEAM_NAMESPACE`, `QM_TEAM_AUTHORITY_ID`
(a canonical UUID identifying the authoritative database deployment), and
`QM_TEAM_REGION` (`use` or `usw`). The API's database connection must point at
the single central authority for that namespace. The deployment owner must
explicitly install the matching row in `qm_team_service_authority` after applying
the migration. This identity is immutable and the API role can only read it.
No configuration or authority row is generated by an HTTP request; missing or
mismatched database identity disables lookup and creation.

Do not clone that authority identity into an independently writable regional
database. Disaster recovery must fence the old writer before restoring the same
database identity and permanent bindings. There is no regional fallback.

The worker pins the origin, namespace and authority UUID before its first call.
Changing them requires reconciliation, rather than creating teams against a new
authority. Rotating the dedicated service credential preserves this binding.

This endpoint provisions infrastructure identity only. Runtime machine-principal
issuance, deployment readiness and commercial entitlements retain their separate
validation gates. No production authority or credential is enabled by this change.
