# Identities. Two, deliberately: the provisioner holds the broad create-and-
# grant permissions and serves no traffic; qm-api holds only what it needs to
# read its own config, store the secrets a tenant hands it, and start
# provisioner executions. There is no shared tenant runtime identity: every
# tenant service runs as its own qm-<slug> account, created by the
# provisioner, so a tenant container can reach only its own bucket and
# secrets.
#
# Service-account quota: each tenant adds one account, and a project's default
# quota is 100 service accounts. Before tenant_capacity gets within reach of
# that (platform accounts count too), request an increase for the IAM API's
# "Service accounts" quota on the project; the README has the step. Nothing
# here can raise it.
resource "google_service_account" "provisioner" {
  project      = var.project_id
  account_id   = "qm-provisioner-${var.service_account_suffix}"
  display_name = "QM tenant provisioner (${var.environment})"
  description  = "Runs the provisioner job: creates per-tenant Cloud Run services, databases, buckets, secrets, qm-<slug> service accounts, and load balancer host rules."
}

resource "google_service_account" "api" {
  project      = var.project_id
  account_id   = "qm-api-${var.service_account_suffix}"
  display_name = "QM API (${var.environment})"
  description  = "Runtime identity of the qm-api Cloud Run service."
}

resource "google_service_account" "redirect" {
  project      = var.project_id
  account_id   = "qm-redirect-${var.service_account_suffix}"
  display_name = "QM redirect (${var.environment})"
  description  = "Runtime identity of the qm-redirect Cloud Run service. Holds no grants."
}

locals {
  provisioner_member = "serviceAccount:${google_service_account.provisioner.email}"
  api_member         = "serviceAccount:${google_service_account.api.email}"

  # Custom role IDs allow only [a-zA-Z0-9_.].
  custom_role_suffix = replace(var.resource_suffix, "-", "_")

  # IAM condition prefixes. Secret Manager and Cloud Storage both expose
  # resource.name to conditions, so grants on existing resources can be held
  # to the tenant prefixes. Project-level create permissions are checked
  # against the project itself, where a name prefix cannot match, so those
  # live in an unconditional custom role that carries nothing else.
  secret_name_prefix           = "projects/${local.project_number}/secrets/${local.qm_secret_prefix}"
  sql_admin_secret_name_prefix = "projects/${local.project_number}/secrets/${local.sql_admin_secret_id}"
  tenant_bucket_name_prefix    = "projects/_/buckets/${local.tenant_bucket_prefix}"
}

# Project-level roles the provisioner needs and that cannot be narrowed by
# resource name in a way that still lets it create things:
#   run.admin              create/update/delete tenant services and jobs
#   cloudsql.client        connect to the shared instance (private IP)
#   compute.loadBalancerAdmin
#                          append host rules, backend services and serverless
#                          NEGs to the tenant URL map
#   iam.serviceAccountAdmin
#                          create qm-<slug> accounts and set their IAM
#   iam.serviceAccountUser project-wide actAs, required to deploy a tenant
#                          service as its qm-<slug> account. Not
#                          conditioned: a qm- name-prefix condition would
#                          have to match the resource name IAM evaluates for
#                          service accounts, which is not guaranteed to be
#                          the email form. The narrower shape, where the
#                          provisioner grants itself actAs on each account
#                          right after creating it (serviceAccountAdmin
#                          allows that), is a runtime change for the Go side
#                          and the follow-up if this grant needs to shrink.
resource "google_project_iam_member" "provisioner" {
  for_each = toset([
    "roles/run.admin",
    "roles/cloudsql.client",
    "roles/compute.loadBalancerAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountUser",
  ])

  project = var.project_id
  role    = each.value
  member  = local.provisioner_member
}

# Tenant databases and roles are created through the SQL Admin API
# (internal/qm/provisioner/steps DatabaseAdmin), which needs database and
# user permissions the client role does not carry. Cloud SQL has no
# instance-level IAM and no resource-name conditions, so this is project
# level; the custom role keeps it to databases and users, without instance
# create/delete or settings changes.
resource "google_project_iam_custom_role" "tenant_database_admin" {
  project     = var.project_id
  role_id     = "qmTenantDatabaseAdmin_${local.custom_role_suffix}"
  title       = "QM tenant database admin (${var.environment})"
  description = "Create and drop per-tenant databases and users on the shared Cloud SQL instance."
  permissions = [
    "cloudsql.instances.get",
    "cloudsql.databases.create",
    "cloudsql.databases.delete",
    "cloudsql.databases.get",
    "cloudsql.databases.list",
    "cloudsql.users.create",
    "cloudsql.users.delete",
    "cloudsql.users.list",
    "cloudsql.users.update",
  ]
}

resource "google_project_iam_member" "provisioner_tenant_database_admin" {
  project = var.project_id
  role    = google_project_iam_custom_role.tenant_database_admin.id
  member  = local.provisioner_member
}

# Tenant services use Direct VPC egress on the same subnet as qm-api so they
# can reach the private-only instance, and deploying a service onto a subnet
# checks compute.subnetworks.use on the deployer. Scoped to that one subnet.
resource "google_compute_subnetwork_iam_member" "provisioner_network_user" {
  project    = var.project_id
  region     = var.region
  subnetwork = var.vpc_subnetwork
  role       = "roles/compute.networkUser"
  member     = local.provisioner_member
}

# Full Secret Manager control, but only over qm-* secrets: tenant secrets
# (create versions, grant the tenant account accessor, delete on teardown)
# and the shared qm-sql-admin secret.
resource "google_project_iam_member" "provisioner_secret_admin" {
  project = var.project_id
  role    = "roles/secretmanager.admin"
  member  = local.provisioner_member

  condition {
    title       = "qm secrets only"
    description = "Limits Secret Manager admin to secrets named qm-*."
    expression  = "resource.name.startsWith(\"${local.secret_name_prefix}\")"
  }
}

# Bucket lifecycle for tenant buckets only: create, configure (lifecycle,
# labels), set per-bucket IAM for the tenant account, delete on teardown.
# Delete must empty the bucket first (BucketAdmin.Delete), hence the object
# list/delete pair; no object read, so the provisioner never sees tenant data.
resource "google_project_iam_custom_role" "tenant_bucket_admin" {
  project     = var.project_id
  role_id     = "qmTenantBucketAdmin_${local.custom_role_suffix}"
  title       = "QM tenant bucket admin (${var.environment})"
  description = "Bucket-level control over <project>-qm-* tenant buckets, plus object delete for teardown, without object read."
  permissions = [
    "storage.buckets.get",
    "storage.buckets.update",
    "storage.buckets.delete",
    "storage.buckets.getIamPolicy",
    "storage.buckets.setIamPolicy",
    "storage.objects.list",
    "storage.objects.delete",
  ]
}

resource "google_project_iam_member" "provisioner_tenant_bucket_admin" {
  project = var.project_id
  role    = google_project_iam_custom_role.tenant_bucket_admin.id
  member  = local.provisioner_member

  condition {
    title       = "qm tenant buckets only"
    description = "Limits bucket administration to buckets named <project>-qm-*."
    expression  = "resource.name.startsWith(\"${local.tenant_bucket_name_prefix}\")"
  }
}

# Create permissions are evaluated against the project, so they cannot be
# conditioned on the eventual resource name. Kept in their own role so the
# unconditional grant carries nothing else.
resource "google_project_iam_custom_role" "provisioner_create" {
  project     = var.project_id
  role_id     = "qmProvisionerCreate_${local.custom_role_suffix}"
  title       = "QM provisioner create (${var.environment})"
  description = "Project-level create permissions for tenant buckets and secrets."
  permissions = [
    "storage.buckets.create",
    "secretmanager.secrets.create",
  ]
}

resource "google_project_iam_member" "provisioner_create" {
  project = var.project_id
  role    = google_project_iam_custom_role.provisioner_create.id
  member  = local.provisioner_member
}

resource "google_secret_manager_secret_iam_member" "provisioner_sql_admin" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.sql_admin.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = local.provisioner_member
}

# The conditional secretmanager.admin grant above already covers this; the
# explicit binding is what the job depends on so a first apply orders the
# grant before Cloud Run validates the mounted secret.
resource "google_secret_manager_secret_iam_member" "provisioner_database_url" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.api_database_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = local.provisioner_member
}

resource "google_artifact_registry_repository_iam_member" "provisioner_reader" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.tenant_images.name
  role       = "roles/artifactregistry.reader"
  member     = local.provisioner_member
}

# qm-api: read the shared instance, read and write qm-* secrets except the
# admin credentials (it stores the model key a tenant hands it before the
# provisioner runs: secrets.GCP.Put creates the secret and adds a version),
# and start (and watch) provisioner executions.
resource "google_project_iam_member" "api_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = local.api_member
}

resource "google_project_iam_member" "api_secrets" {
  for_each = toset([
    "roles/secretmanager.secretAccessor",
    "roles/secretmanager.secretVersionAdder",
  ])

  project = var.project_id
  role    = each.value
  member  = local.api_member

  condition {
    title       = "qm secrets except sql admin"
    description = "qm-* secrets only; the instance admin password stays with the provisioner."
    expression  = "resource.name.startsWith(\"${local.secret_name_prefix}\") && !resource.name.startsWith(\"${local.sql_admin_secret_name_prefix}\")"
  }
}

# Same project-level create caveat as the provisioner's role above; this one
# carries only secret creation.
resource "google_project_iam_custom_role" "api_secret_create" {
  project     = var.project_id
  role_id     = "qmApiSecretCreate_${local.custom_role_suffix}"
  title       = "QM API secret create (${var.environment})"
  description = "Project-level secret creation for tenant-supplied secrets."
  permissions = ["secretmanager.secrets.create"]
}

resource "google_project_iam_member" "api_secret_create" {
  project = var.project_id
  role    = google_project_iam_custom_role.api_secret_create.id
  member  = local.api_member
}

# Explicit secret-level grant for DATABASE_URL in addition to the conditional
# project grant above: Cloud Run checks the runtime account can read every
# mounted secret at deploy time, and this is the binding the service depends
# on so a first apply orders correctly.
resource "google_secret_manager_secret_iam_member" "api_database_url" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.api_database_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = local.api_member
}

resource "google_cloud_run_v2_job_iam_member" "api_runs_provisioner" {
  for_each = toset([
    # run.jobs.run plus run.jobs.runWithOverrides: qm-api passes the tenant
    # slug and action as per-execution overrides, which roles/run.invoker
    # alone does not permit.
    "roles/run.jobsExecutorWithOverrides",
    # run.executions.get / list to follow an execution to completion
    "roles/run.viewer",
  ])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.provisioner.name
  role     = each.value
  member   = local.api_member
}
