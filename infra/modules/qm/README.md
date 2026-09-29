# Hosted QM foundation

This is a dormant infrastructure foundation. It does not deploy applications,
activate tenant provisioning, migrate an existing installation, or prove live
isolation. Deployment workflow integration is a subsequent change. Existing
Terraform CD still sees `infra/**` changes and performs its normal existing-root
and API rollout; none of its four fixed regional roots imports these modules.
Proxy/VMD deployment ownership is unchanged.

## Roots, state, and ownership

| Root | State | Writer and scope |
| --- | --- | --- |
| `infra/bootstrap/qm` with `environment=development` | Dedicated administrator-controlled GCS bucket, prefix `qm/development/bootstrap` | Explicitly authorized development bootstrap identity: project, billing, APIs, platform identities, protected IAM, federation, secret containers, registry pulls, routine state bucket |
| `infra/bootstrap/qm` with `environment=production` | Separate administrator-controlled GCS bucket, prefix `qm/production/bootstrap` | Separate production bootstrap identity; same ownership, production only |
| `infra/envs/qm/development` | `rayai-qm-dev-terraform/network` | `qm-infra@rayai-qm-dev.iam.gserviceaccount.com`: regional tenant networks, subnets, NAT, firewall policy |
| `infra/envs/qm/production` | `rayai-qm-prod-terraform/network` | `qm-infra@rayai-qm-prod.iam.gserviceaccount.com`: regional tenant networks, subnets, NAT, firewall policy |

GCS locking is mandatory: never use `-lock=false`. One apply per root/state at a
time. Bootstrap state must not share a bucket, IAM inheritance, or access group
with routine state. Both use uniform bucket access, public-access prevention,
versioning, and Google-managed encryption at rest. Restrict state readers as
carefully as writers: future database-owner state can contain credentials.
Never publish state or unsanitized plan JSON as public artifacts. Root outputs
contain references only. Routine network Terraform never reads bootstrap state;
the release operator transfers its reviewed, non-secret `contract` output.

Bootstrap also enables the QM project's Cloud Storage `DATA_READ` and
`DATA_WRITE` audit logs. This project-level configuration covers reads and
writes of the routine state bucket without granting `qm-infra` project IAM
authority. The administrator must verify during rollout that the effective
Cloud Audit Logs routing and retention policy preserves those records; the
routine network root must not manage or weaken this setting.

| Environment | Paired project | QM project | Regions / tenant CIDRs |
| --- | --- | --- | --- |
| development | `rayai-dev` | `rayai-qm-dev` | `us-central1`: `10.80.0.0/20` |
| production | `rayai-prod` | `rayai-qm-prod` | `us-central1`: `10.81.0.0/20`; `us-west2`: `10.81.16.0/20`; `us-east4`: `10.81.32.0/20` |

The QM project number is allocated by Google and appears in the bootstrap
output. The paired Superserve project number is supplied from the reviewed
rollout preparation manifest and is published alongside its project ID; this
keeps planning backend-independent and avoids an implicit live lookup. Verify
project-ID/number pairing, matching deployment regions, quota, and CIDR
conflicts before applying. Region additions require review of both root maps,
protected services, cell infrastructure, and the address budget. There is one
project per environment and one central control database, whose owner chooses
its home/availability topology. A regional map does not create extra control
state or active/active coordination.

## Permission inventory

All platform grants/custom-role definitions below belong to bootstrap Terraform.
Routine identities have no project `setIamPolicy`, role mutation, API enablement,
federation mutation, tag mutation, service-account key creation, or bootstrap
impersonation grant. IAM administration is deliberately retained in the protected
root; the network identity does not need even a grantable-role allowlist.
Exact custom-role permissions are enumerated in `../qm-bootstrap/iam.tf`.
Network CRUD is project-scoped: infrastructure approval can change network
isolation and is a trusted security administration boundary. Subnet use is
granted directly on each tenant subnet after it exists, without relying on
unsupported subnetwork-name IAM Conditions.

| Identity | Permissions | Resource scope | Use / owner |
| --- | --- | --- | --- |
| Environment bootstrap identity in an existing protected administration project | Temporary Project Creator / Billing Account User; initial project Owner supplied by creation; temporary paired-project Service Usage Consumer and registry IAM administration; state object administration | Selected folder, billing account, newly created QM project, paired project quota usage and one image repository, its own bootstrap bucket | Authorized bootstrap only; manual preparation and cleanup below |
| `qm-infra` | `qm_network`: network/subnet/firewall/router CRUD and operation reads; `storage.objectAdmin` | QM environment project network resources; its routine state bucket only | Routine Terraform network root |
| `qm-api-deployer` | `qm_deploy_service`: service get/update; operation/project reads and service usage; `iam.serviceAccountUser`; image reader | Named `qm-api` service in supported regions; `qm-api` identity only; one image repository | Routine API deployment; service binding exists only after platform shells exist |
| `qm-provisioner-deployer` | Same deployment permissions | Named `qm-provisioner` service; provisioner identity only; one image repository | Privileged provisioner deployment, separate protected GitHub environment |
| `qm-api` | `secretAccessor` | Exact `qm-platform-api-control-db` and `qm-platform-api-auth` containers | Public management API runtime; no provisioning administration |
| `qm-provisioner` | `qm_tenant_create`, bounded tenant lifecycle roles; exact subnet use; image reader; exact secret readers | This QM project; unprotected tenant accounts/services; `qm-tenant-*` secrets; `<project>-tenant-*` buckets; enumerated cell admin secrets and `qm-platform-provisioner-control-db` | Privileged tenant lifecycle; create/mutation grants disabled initially |
| Google Cloud Run service agent | Google service-agent authority; cross-project image reader | QM project and one paired-project repository | Google-managed platform operations; no provisioner impersonation grant |
| Tenant service account | No project role; own bucket object access and own secret-version access granted by provisioner | Exact tenant bucket/secrets; database SQL role limited to its tenant database | Tenant runtime; API-created resources and bindings, never foundation state |

Deploying code as a runtime identity confers its effective power. In particular,
provisioner deployment can administer tenant resources and read assigned cell
admin credentials. Its GitHub environment must require privileged approval.
An API deployment identity cannot deploy provisioner code or act as provisioner.
Build/push authority stays with the existing build job and is not granted here.
The registry repository administrator must authorize bootstrap to add the
additive reader bindings; no project-wide repository or paired-project DB access
is granted. No routine identity may access another environment's state or roles.

### Protected platform objects

Cloud Run and service-account authorization use the bootstrap-owned
`qm-protected=platform` resource tag. Provisioner lifecycle permissions require
that tag to be absent. Account permissions additionally require
`qm-account-scope=tenant-project`, attached only to the QM project by bootstrap.
Locally owned accounts inherit this tag; Google-owned service agents and accounts
in other projects do not. An absent protection tag alone cannot grant account
access. Every locally owned platform service/account and default account is
protected before activation. This module does not attempt to tag Google-owned
service agents through a QM-project service-account path.
See Google's [tag inheritance documentation](https://cloud.google.com/iam/docs/tags-access-control)
and [service-agent ownership documentation](https://cloud.google.com/compute/docs/access/service-accounts). The provisioner
cannot attach/remove tags, change service-account policies, create keys, mint
service-account tokens, or mutate project/custom-role/federation policy. It may
attach only an unprotected tenant identity to a tenant service. All unprotected
accounts/services in this project must therefore remain tenant resources with
no platform authority. Prefixes are naming contracts for these two resource
types, not an unsupported claim of name-based IAM enforcement.

Service-account tags are currently a Google preview feature. This is a material
rollout dependency: verify their conditional authorization for get/update/delete
and `actAs` using actual identities before enabling provisioning. Confirm a newly
created tenant account inherits the project scope tag and is usable, while
protected platform/default accounts, the Cloud Run, Compute Engine and Google
APIs service agents, and an account in the paired project are denied. Check each
target's effective tags and `testIamPermissions`; exercise forbidden mutations
only against disposable fixtures. Confirm attaching a service agent to a
disposable tenant Cloud Run service is denied. Repeat for newly enabled APIs'
service agents before restoring provisioning. See Google's
[service-account tag documentation](https://cloud.google.com/iam/docs/service-accounts-tags)
and [tag-based access controls](https://cloud.google.com/iam/docs/tags-access-control).
Do not substitute unconditional account administration if verification fails.

Protect new locally owned platform accounts/services and audit Google service
agent impersonation before granting new authority. To add APIs, regions, or platform objects after launch:
revoke provisioner create/mutation grants, stop the worker and drain in-flight
operations, verify revocation has propagated, create/protect the objects, audit
IAM, then restore provisioning. Renaming/removing protection while the worker
is live is unsafe. The explicit activation inputs are bootstrap operations, not
routine CD switches. Default service accounts are deprivileged without deletion.
Inherited organization/folder roles and existing service-account policies must
still be audited; separate account names alone provide no isolation.

## Network and capacity contract

Each region gets its own dedicated tenant VPC, IPv4-only `/20` Direct VPC subnet,
and subnet-specific Cloud NAT. Services must use **ALL_TRAFFIC** egress. An
omitted tag does not bypass private egress denial. No peering, VPN, route, private
DNS attachment, or general access to a Superserve VPC is added.

| Priority | Egress policy |
| --- | --- |
| 100 | Deny all traffic to published central-control DB CIDRs, including an accidentally duplicated cell address |
| 200 | For each persisted cell ID, allow its `qm-db-<db_cell_id>-client` tag to exactly its private `/32`, TCP 5432 |
| 300 | Deny private, shared-address, link-local and other reserved ranges for every tenant interface |
| 1000 | Allow public destinations, including public Google API endpoints, through NAT |

Ingress through tenant VPC interfaces is denied. Cloud Run's HTTP ingress/edge
policy is separate and belongs to the runtime/edge owners. Google-managed
metadata/DNS behavior is not controlled by these VPC firewall rules; the attached
tenant identity must have only its own grants. IPv6 is not enabled. Published
control CIDRs are required before adding any cell allow. Cell endpoints must be
unique and RFC1918 IPv4. The database owner supplies private connectivity to this
VPC and disables public SQL endpoints. No control DB private connection is added
to tenant VPCs. Never import unrelated private destinations through public address
space or add generic private allow rules.

The provisioner resolves `tenant_id -> persisted db_cell_id -> regional contract`
and applies exactly that cell tag and that region's subnet. A retry reuses the
allocation, never chooses placement. Tenant-supplied tags, subnet overrides, or
SQL destinations must be rejected. A tag for another cell is not a tenant API
input. Per-cell rules scale with cells, not tenants. Database roles separately
prevent two tenants in the same cell from accessing each other's databases.

A `/20` contains 4092 usable IPv4 addresses. Budget two addresses per instance,
two overlapping revisions, and at least 508 addresses of additional headroom:
`2 * sum(ceil(2 * instances_per_revision / 16) * 16) <= 3584`.
The nominal ceiling is 896 steady instances **only when block rounding permits**;
small services and retained addresses lower it. Budget across the entire subnet,
including drained revisions whose addresses have not yet been released. Block
rounding and revision overlap must be enforced by the placement/capacity owner;
this module does not implement admission. Confirm release delays and consumption
in staging using Google's [Direct VPC guidance](https://cloud.google.com/run/docs/configuring/vpc-direct-vpc).

## Consumer contract and readiness

`bootstrap.contract` publishes version 1, paired project IDs/numbers, regions,
identity emails, protected tag IDs, workflow-specific WIF providers, GitHub
environment names, state location, registry readers and image format, platform
secret IDs, and regional service names. `network.contract[region]` publishes
VPC/subnet IDs,
ALL_TRAFFIC egress, capacity budget, cell tags/endpoints/ports/firewall IDs, and
control denial CIDRs. No secret value is an output.

The provider map keys are `terraform` and `deploy_qm_api`; use the key matching
the workflow rather than reusing one provider for both release classes. The
legacy `workload_identity_provider` field remains an infrastructure-provider
alias for compatibility and must not be used by application deployment.

Platform services are contract-only here: regional Cloud Run services `qm-api`
and `qm-provisioner`, separate identities, immutable `@sha256:` images from the
published repository. The background provisioner is an authenticated/private
worker service with no public management ingress; queue/worker semantics remain
with its application owner. No Cloud Run job is declared or granted authority.
Platform service Terraform owns configuration; subsequent image deployment must
have one owner (for example Terraform ignores image changes owned by the release
job). Provisioner and API deployments require their own protected environments.

The WIF providers require the numeric GitHub repository/owner IDs and `main`.
The `terraform` provider accepts only `terraform-cd.yml`; the `deploy_qm_api`
provider accepts only `deploy-qm-api.yml`. Each identity also requires its
exact output GitHub environment subject, and the IAM binding uses the matching
workflow-specific pool. Packet 2 consumes these exact workflow/identity/environment
bindings for infrastructure and code-only releases; it cannot silently widen a
provider condition. Routine jobs never authenticate as bootstrap.
Pending/unconfigured deployment must report disabled/pending, not successful.
Required gates are: bootstrap applied and audited, regional
networks and DB/edge dependencies ready, platform secret versions populated,
immutable images available, registry pull grants verified, platform service
shells created, then protective tags applied and verified. Only then may
`provisioning_enabled=true` be separately approved/applied.

The central database owner creates the single coordination DB, its platform
network connectivity and restricted API/worker SQL roles. The cell infrastructure
owner creates regional cells/private service connections and supplies endpoint
maps. Those owners must consume this project's identity/network outputs without
duplicating ownership. The allocator owns placement. Shared wildcard edge,
URL-mask serverless NEGs, DNS, and certificates remain static infrastructure-owned
resources. The provisioner has no LB/NEG/DNS or network-policy mutation permission.

For Superserve auth/team/entitlement, use an authenticated management-only HTTPS
interface with a credential limited to that interface and explicit user/team
context. Existing `internal/authz` evaluates against Superserve's DB; the current
internal API credential authorizes broader operations and must not be copied to
QM. The narrow interface is an application-owner dependency, not an implemented
endpoint in this foundation. Its issuer supplies `qm-platform-api-auth` only
after the scoped interface exists. No Superserve DB role or generic private
network access is granted. Management calls incur one extra network round trip;
record p50/p95 by region during rollout. Healthy tenant DB/bucket/secret use has
no Superserve round trip. Sandbox execution uses the existing sandbox API with a
tenant-scoped machine credential. This foundation adds no startup/resume work.

### Secret values and rotation

Bootstrap owns platform containers and exact accessor grants. The database
infrastructure owner owns platform SQL users and their generated passwords; its
protected Terraform state must be encrypted/access restricted as above. It
supplies the appropriate API, worker, and cell-admin secret versions through an
authorized credential-writing step. Do not create competing container resources.
Only the worker reads enumerated cell-admin credentials; it does not receive
control-DB superuser credentials. Database-level provisioning uses those assigned
cell credentials, not project-wide Cloud SQL administration.

The auth issuer supplies an externally issued, narrowly scoped credential through
an authenticated operator/CI secret input. Grant its authorized rotator
`roles/secretmanager.secretVersionAdder` on that exact container, never project
Secret Manager Admin. Use `gcloud secrets versions add NAME --project=PROJECT
--data-file=PROTECTED_FILE` or a secret-to-secret transfer with tracing disabled;
never put values in arguments, tfvars, outputs, plans, or logs. Record issuer,
owner, version number and expiry without the value. Rotate by issuing a new
credential/password with overlap, uploading a new version, updating the pinned
version in the consumer, verifying it, then revoking/disabling the old version.
For DB credentials coordinate SQL and secret updates to avoid a mismatched
password window. After response loss, inspect version metadata and consumer
health rather than repeatedly rotating. Never destroy an old version before all
consumers have moved. Tenant secret values/containers/grants belong to the
provisioner and use `qm-tenant-*`; foundation Terraform does not adopt them.

## Backend-independent development checks

The existing `scripts/terraform-validate.sh` now includes the dormant bootstrap
and both environment roots, plus mocked IAM/network contract tests. The existing
Terraform Checks and Plans code-validation jobs already invoke that wrapper;
no workflow/trigger or live-plan matrix change is needed. Provider locks reuse
repository-pinned versions. Required procedure: `terraform fmt -check -recursive
infra/`, then `scripts/terraform-validate.sh`. No cloud credentials, live project,
backend, or environment plan is required for the new roots. Mock tests protect
cell/control-denial precedence and absence of privilege escalation/activation;
they do not prove Google IAM semantics. Live checks below remain required.

See [rollout instructions](ROLLOUT.md) for administrator commands, recovery,
impact classification, and actual-identity verification.
