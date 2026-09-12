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
- Cloud DNS records for the authorization, apex and wildcard, only when
  `dns_managed_zone` is set

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
  lifecycle policy from `tenant_bucket_lifecycle_policy_json` and bucket IAM
  for the tenant account
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
  secrets; qm-api's conditions additionally exclude `qm-sql-admin-*`.
- Buckets: a custom role with bucket-level permissions plus object
  list/delete for teardown (no object read), conditioned on the
  `<project>-qm-` name prefix.
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
4. **`qm_api` role and `DATABASE_URL`.** The role and its grants come from
   the control-plane schema migrations; its password is set out of band.
   Add a version to `qm-api-database-url-<suffix>` with the control-plane
   connection string for that role. Both the qm-api service and the
   provisioner job mount this secret, and neither will start until the
   version exists, so on a first apply create the secrets first
   (`-target=module.qm[0].google_secret_manager_secret.api_database_url`),
   add the version, then apply the rest.
5. **Service-account quota** as above, before onboarding tenants at scale.

Later image rollouts are owned by deploy tooling (`deploy-qm-api.yml` updates
the service and the job to the same SHA): Terraform ignores image drift on
all three workloads, matching the `api` module.
