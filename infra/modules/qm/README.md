# qm

Shared, tenant-independent infrastructure for hosted QM. One instance per
environment, in the same GCP project as the rest of the platform. The
consumer is `cmd/qm-api`: the Cloud Run service serves `/v1/qm`, and the
same binary runs as the provisioner job (`qm-api provision`) for one tenant
per execution.

## Shared vs per-tenant

Terraform (this module) owns:

- the Cloud SQL Postgres 16 instance `qm-tenants-<suffix>` (private IP on the
  environment VPC, automated backups, point-in-time recovery, deletion
  protection) and its admin role
- the admin password in Secret Manager (`qm-sql-admin-<suffix>`, readable
  only by the provisioner) and the empty `qm-api-database-url-<suffix>` secret
  both workloads read `DATABASE_URL` from
- the wildcard edge: DNS authorization, managed certificate for `<domain>` and
  `*.<domain>`, certificate map, global HTTPS load balancer with the
  `qm-redirect` service as its default route, and the `:80` to `:443` redirect
- the provisioner, qm-api and redirect service accounts and their grants
- the qm-api Cloud Run service, the provisioner Cloud Run job, and the
  `qm-redirect` Cloud Run service
- the `qm-<suffix>` Artifact Registry repository tenant images are pulled
  from, and the fleet-default tenant image (`tenant_image`, exported as
  `QM_TENANT_IMAGE`)
- the empty `qm-resend-<suffix>` secret every tenant's sign-in broker sends
  magic links with, and the tenant runtime configuration the provisioner
  renders into each tenant's service: `tenant_email_from`, `sandbox_api_url`,
  `sandbox_template` and the optional `sandbox_key_region` (exported as
  `QM_RESEND_SECRET`, `QM_EMAIL_FROM`, `QM_SANDBOX_API_URL`,
  `QM_SANDBOX_TEMPLATE` and `QM_SANDBOX_KEY_REGION`)
- Cloud DNS records for the authorization, apex and wildcard, only when
  `dns_managed_zone` is set

`cmd/qm-api` refuses to start when any of those four is unset, so an
environment cannot accept tenants it would build without a working sign-in.
That is also why the deploy workflow sets none of them: this module does not
ignore environment drift on the service or the job, so a second owner would
flap, and `QM_API_SERVICE` is only set for an environment whose module has
already been applied.

## Tenant sign-in

Hosted QM has one Resend account and one verified sending domain for the
whole fleet, so the API key is a single shared secret rather than a
per-tenant one: the provisioner grants each tenant's service account read on
it and the tenant's own container mounts it. The provisioner is deliberately
excluded from its broad `secretmanager.admin` grant over `qm-*` for this one
secret and holds a two-permission role on it instead — it only ever reads and
writes the secret's IAM policy, and one run wrongly deleting it would take
sign-in away from every tenant at once.

`tenant_email_from` must be at that account's verified domain. It is a
property of the Resend account rather than of an environment, which is why it
is not derived from `var.domain` and why staging and production share it.

Only the secret is created here; the key itself is added out of band, as with
`qm-api-database-url-<suffix>`. Nothing this module deploys mounts it, so an
environment stands up complete and empty — the first *tenant* provisioned
without a version fails at its Cloud Run deploy. That is the loud failure we
want: the reference tenant shipped with no email transport, answered its
health check, and 503'd the moment anybody tried to sign in.

The module deliberately offers no way to point at a secret somewhere else.
Every provisioned tenant mounts this one by name, so a second supported
location would mean an apply that moves the name can delete a secret the
fleet is still reading, or strand the tenant grants the provisioner has to
revoke on the one it left behind. Rotating the Resend key is adding a version
here; tenants mount `:latest` and pick it up on their next revision.

`sandbox_api_url` is the one of the four that genuinely differs per
environment. The sandbox key the provisioner issues a tenant is bound to the
cell that issued it, and a key presented to another cell is refused, so
staging tenants must point at the staging API. It has no default for that
reason: a wrong one points a whole environment's tenants at the wrong cell
and nothing fails until a tenant tries to run something.

The tenant registry (tenants, runs, secret refs) is a set of tables in the
control-plane Postgres, reached as the `qm_api` role; it is not on the Cloud
SQL instance here, which holds only tenant databases.

The provisioner job creates, at runtime and outside Terraform state, for each
tenant `<slug>` (names from `internal/qm/provisioner/steps`):

- a Cloud Run service `qm-<slug>` running the tenant image as its own
  `qm-<slug>` service account
- a database `qm_<slug>` and role on the shared instance, through the SQL
  Admin API
- a bucket `<project>-qm-<slug>` in `tenant_bucket_location`, with the
  lifecycle policy from `tenant_bucket_lifecycle_policy_json`, bucket IAM for
  the tenant account, and an HMAC key for that account (QM reaches its bucket
  through an S3 client, which authenticates with an access key)
- `qm-<slug>-<name>` secrets (qm-api itself writes the model key a tenant
  hands it before the run starts)
- a serverless NEG, backend service, and host rule on the shared URL map so
  `https://<slug>.<domain>` reaches the tenant service. Terraform ignores
  `host_rule` and `path_matcher` on the URL map for this reason.

There is deliberately no shared tenant runtime service account.

Because tenant names share the `qm-` / `qm_` prefixes with the platform's own
resources, slug validation on the Go side must reserve at least `api`,
`redirect`, `provisioner`, `sql`, and `tenants` (and anything else this
module names `qm-<word>`), or a tenant could collide with `qm-api-*`,
`qm-sql-admin-*`, or `qm-tenants-<suffix>`.

It must also bound slug length. Terraform never fills `{slug}`, so the module
computes the budget from its own prefixes and exports it as the
`tenant_slug_max_length` output and `QM_TENANT_SLUG_MAX_LENGTH`: the smallest
of the bucket (`<project>-qm-<slug>`, 63), service account (`qm-<slug>`, 30),
Cloud Run service (`qm-<slug>`, 49) and database (`qm_<slug>`, 63) limits. The
service account is normally the binding one; a long project ID makes it the
bucket. Enforce that value rather than recomputing it, or a long slug fails
partway through a provision with some resources already created.

## One environment per project

The per-tenant names the provisioner derives — `qm-<slug>` service account and
Cloud Run service, `<project>-qm-<slug>` bucket, `qm-<slug>-<name>` secrets —
carry no `resource_suffix`, and service accounts, buckets and secrets are all
project-global. Two instances of this module in one project would therefore
collide on any slug they both provision, and the prefix-conditioned IAM grants
would let each environment's qm-api read the other's tenant secrets. Platform
secrets (`qm-sql-admin-*`, `qm-api-database-url-*`) are excluded from those
grants for exactly that reason, but tenant secrets cannot be without a suffix
in the name.

So: one enabled QM environment per GCP project. Staging is in `rayai-dev` and
production in `rayai-prod`, which satisfies that today. Putting a second one
in either project means adding `resource_suffix` to the tenant naming in
`internal/qm/provisioner/steps` and `internal/qm/secrets` first, then to the
prefixes in `main.tf` and the IAM conditions in `iam.tf` together — the Go
side and this module have to agree on those names.

## Deletion safety

Every tenant's database is on the one `qm-tenants-<suffix>` instance, so it
carries three independent guards: `deletion_protection` (Terraform refuses the
delete call), `settings.deletion_protection_enabled` (the API refuses it from
the console and `gcloud` too), and `prevent_destroy` (the plan fails before an
apply starts, which is also what catches a *replacement* — a changed
`resource_suffix`, `region`, or `private_network` plans destroy-then-create and
the other two flags do not make that obvious). Removing the instance is
deliberately three changes: drop `prevent_destroy`, set both
`deletion_protection` flags to false and apply, then remove the resource.

The qm-api Cloud Run service carries Cloud Run deletion protection as well, so
set `api_deletion_protection = false` and apply before removing the module or
setting `enable_qm` back to false; otherwise the destroy fails on the service.

Backups are on by default: daily automated backups at `sql_backup_start_time`
with `sql_backup_retained_count` (14) retained, plus point-in-time recovery
with `sql_transaction_log_retention_days` (7) of write-ahead log.

Note that `prevent_destroy` also applies to turning the module off again:
once `enable_qm` has been applied as true, flipping it back to false fails at
plan time. That is intentional for an instance holding tenant data, and the
teardown above is the way through it.

## Connection sizing

`max_connections` on the instance is

```
tenant_capacity x sql_connections_per_tenant x sql_connection_headroom
= 25 x 17 x 1.3 = 552.5, rounded up to the 560 default
```

17 is one QM container's steady-state pool plus workers; 1.3 leaves room for
the provisioner, migrations, and operator sessions. A `check` block warns
when `sql_max_connections` falls below the formula for the configured
`tenant_capacity`. Raise `sql_tier` with the flag: the default
`db-custom-2-7680` is sized for the default, not for a much larger fleet.

## Service-account quota

Every tenant adds a `qm-<slug>` service account. A project's default quota
is 100 service accounts, and the platform's own accounts count against it.
Before `tenant_capacity` approaches that, request an increase for the IAM API
"Service accounts" quota on the project (IAM & Admin > Quotas, service
`iam.googleapis.com`). Terraform cannot raise it.

## IAM scoping

- Secret Manager: `roles/secretmanager.admin` (provisioner) and
  `roles/secretmanager.secretAccessor` + `secretVersionAdder` (qm-api) are
  project-level bindings with a `resource.name` condition limited to `qm-*`
  secrets; qm-api's conditions additionally exclude `qm-sql-admin-*` and
  `qm-api-database-url-*`. Both conditions also exclude the shared Resend
  secret, and that one by exact name rather than by prefix: its name is a
  caller's to choose, so a prefix would miss an overridden one — and a
  `qm-resend-` prefix would swallow the secrets of a tenant whose slug is
  `resend`. The provisioner reaches it through a three-permission custom
  role (`secrets.get`, `getIamPolicy`, `setIamPolicy`) bound on the secret
  itself: enough to grant and revoke tenant access, not enough to read the
  key or delete it.
- Buckets: a custom role with bucket-level permissions plus object
  list/delete for teardown (no object read), conditioned on the
  `<project>-qm-` name prefix.
- Storage HMAC keys: a second custom role, unconditional, for the
  interoperability credential each tenant's S3 client authenticates with.
  These belong to the project and the service account rather than to a
  bucket, so there is no resource name to condition on.
- Create permissions (`storage.buckets.create`, `secretmanager.secrets.create`)
  are evaluated against the project, so they cannot be conditioned on the
  eventual name; they sit in separate unconditional custom roles (one for
  the provisioner, one with secret creation only for qm-api).
- Cloud SQL: a project-level custom role with database and user create,
  update, delete, list and instance get. Cloud SQL has no instance-level
  IAM, so it cannot be narrowed to the QM instance.
- `run.admin`, `cloudsql.client`, `compute.loadBalancerAdmin`,
  `iam.serviceAccountAdmin`, and `iam.serviceAccountUser` are project-level.
  `serviceAccountUser` is the broadest; the follow-up if it needs to shrink is
  for the provisioner to grant itself `actAs` per tenant account after
  creating it.
- `roles/compute.networkUser` is granted on the Direct VPC egress subnet only,
  so the provisioner can deploy tenant services onto it.
- qm-api gets `roles/run.jobsExecutorWithOverrides` (the trigger passes the
  team, tenant and mode as container args) and `roles/run.viewer` on the
  provisioner job only.

## Apply order

1. **Images.** `deploy-qm-api.yml` pushes the qm-api image (service and job
   share it) to the existing `superserve` repository; set `api_image` to a
   tag that exists there, and `redirect_image` likewise. Cloud Run rejects a
   revision whose image cannot be pulled, so placeholders fail the apply.
   Tenant images go in the `qm-<suffix>` repository this module creates; on a
   brand-new environment apply it first with `-target` on
   `google_artifact_registry_repository.tenant_images`, push, then continue.
2. **Private Service Access.** If the VPC already has a servicenetworking
   connection, set `create_private_service_connection = false` and add a
   reserved range for QM to that connection out of band; otherwise the module
   creates both.
3. **Certificate DNS authorization.** Apply. Publish the CNAME from the
   `dns_authorization` output (done automatically when `dns_managed_zone` is
   set) before expecting the certificate to become `ACTIVE`; the load balancer
   serves nothing until it does. Then point `<domain>` and `*.<domain>` at the
   `address` output.
4. **Resend key.** Add a version to `qm-resend-<suffix>` with the platform's
   Resend API key. Nothing starts without it, but the first tenant
   provisioned before it exists fails at its Cloud Run deploy.
5. **`qm_api` role and `DATABASE_URL`.** The role and its grants come from
   the control-plane schema migrations; its password is set out of band.
   Add a version to `qm-api-database-url-<suffix>` with the control-plane
   connection string for that role. Both the qm-api service and the
   provisioner job mount this secret, and neither will start until the
   version exists, so on a first apply create the secrets first
   (`-target=module.qm[0].google_secret_manager_secret.api_database_url`),
   add the version, then apply the rest.
6. **Service-account quota** as above, before onboarding tenants at scale.

Later qm-api image rollouts are owned by deploy tooling (`deploy-qm-api.yml`
updates the service and the job to the same SHA), so Terraform ignores image
drift on those two, matching the `api` module. That workflow lands with the
qm-api change, not with this module; until it does there is nothing to enable
`enable_qm` for, which is why the flag ships off. The redirect service has no
deploy-tooling path, so Terraform owns its image: change `redirect_image` and
apply to roll it.
