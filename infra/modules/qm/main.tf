# Shared, tenant-independent infrastructure for hosted QM. One instance of this
# module per environment owns everything a tenant stack depends on but does
# not own: the Cloud SQL instance tenant databases live on, the wildcard edge
# (certificate, certificate map, HTTPS load balancer), the provisioner and
# qm-api identities, and the image repository tenant containers are pulled
# from. Per-tenant resources (Cloud Run service, database + role, bucket,
# qm-<slug> service account, URL-map host rule + serverless NEG) are created
# at runtime by the provisioner job (cmd/qm-api provision) through the GCP
# APIs and never appear in Terraform state. The tenant registry itself is a
# set of tables in the control-plane Postgres, read as the qm_api role; the
# Cloud SQL instance here holds only tenant databases.
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source = "hashicorp/google"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  name           = "qm-${var.resource_suffix}"
  project_number = data.google_project.this.number

  sql_instance_name = "qm-tenants-${var.resource_suffix}"

  # Per-tenant naming, mirroring internal/qm/provisioner/steps (ServiceName,
  # BucketName, ServiceAccountID) and internal/qm/secrets (TenantSecretName).
  # The IAM conditions in iam.tf are scoped to these prefixes, so a naming
  # change on the Go side has to land here too.
  tenant_service_account_prefix = "qm-"
  tenant_bucket_prefix          = "${var.project_id}-qm-"
  tenant_bucket_name_pattern    = "${local.tenant_bucket_prefix}{slug}"
  tenant_bucket_location        = coalesce(var.tenant_bucket_location, var.region)
  qm_secret_prefix              = "qm-"

  sql_admin_secret_id        = "qm-sql-admin-${var.resource_suffix}"
  api_database_url_secret_id = "qm-api-database-url-${var.resource_suffix}"

  tenant_image_repository_id = local.name
  tenant_image_repository    = "${var.region}-docker.pkg.dev/${var.project_id}/${local.tenant_image_repository_id}"

  # Lifecycle rules in the JSON API shape (`{"rule": [...]}`) so the
  # provisioner can hand them to buckets.patch or `gcloud storage buckets
  # update --lifecycle-file` unchanged. Null condition fields are dropped so
  # the API does not see them as explicit zero values.
  lifecycle_condition_keys = {
    age                        = "age"
    days_since_noncurrent_time = "daysSinceNoncurrentTime"
    num_newer_versions         = "numNewerVersions"
    matches_prefix             = "matchesPrefix"
    matches_storage_class      = "matchesStorageClass"
  }
  tenant_bucket_lifecycle_policy = {
    rule = [
      for rule in var.tenant_bucket_lifecycle_rules : {
        action = merge(
          { type = rule.action.type },
          rule.action.storage_class == null ? {} : { storageClass = rule.action.storage_class },
        )
        condition = {
          for key, value in rule.condition : local.lifecycle_condition_keys[key] => value
          if value != null
        }
      }
    ]
  }

  required_apis = [
    "artifactregistry.googleapis.com",
    "certificatemanager.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
  ]
}

resource "google_project_service" "required" {
  for_each = toset(local.required_apis)

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# Private Service Access for the Cloud SQL private IP. The peering is per VPC
# and per service, so an environment whose VPC already carries a
# servicenetworking connection must reuse it (create_private_service_connection
# = false) rather than let this module fight over the reserved-range list.
resource "google_compute_global_address" "private_service_range" {
  count = var.create_private_service_connection ? 1 : 0

  project       = var.project_id
  name          = "${local.name}-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.private_service_range_prefix_length
  address       = var.private_service_range_address
  network       = var.network_self_link
  labels        = var.labels
}

resource "google_service_networking_connection" "private_service_access" {
  count = var.create_private_service_connection ? 1 : 0

  network                 = var.network_self_link
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_range[0].name]
  # The peering outlives this module: other Google services on the VPC may
  # attach to it later, and deleting it while a Cloud SQL instance still
  # holds an address in the range fails anyway.
  deletion_policy = "ABANDON"

  depends_on = [google_project_service.required]
}

check "sql_max_connections_covers_tenant_capacity" {
  assert {
    condition     = var.sql_max_connections >= ceil(var.tenant_capacity * var.sql_connections_per_tenant * var.sql_connection_headroom)
    error_message = "sql_max_connections (${var.sql_max_connections}) is below tenant_capacity x sql_connections_per_tenant x sql_connection_headroom (${ceil(var.tenant_capacity * var.sql_connections_per_tenant * var.sql_connection_headroom)}). Raise the flag or lower tenant_capacity."
  }
}

# One Postgres instance shared by every tenant: each tenant gets its own
# database and role on it (created by the provisioner as sql_admin_user), not
# its own instance. Private IP only, reached over Direct VPC egress.
resource "google_sql_database_instance" "tenants" {
  project             = var.project_id
  name                = local.sql_instance_name
  region              = var.region
  database_version    = var.sql_database_version
  deletion_protection = true

  settings {
    tier              = var.sql_tier
    edition           = "ENTERPRISE"
    availability_type = var.sql_availability_type
    disk_type         = "PD_SSD"
    disk_size         = var.sql_disk_size_gb
    disk_autoresize   = true

    # API-side guard in addition to Terraform's deletion_protection above:
    # blocks deletion from the console and gcloud too.
    deletion_protection_enabled = true

    backup_configuration {
      enabled                        = true
      start_time                     = var.sql_backup_start_time
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = var.sql_transaction_log_retention_days

      backup_retention_settings {
        retained_backups = var.sql_backup_retained_count
        retention_unit   = "COUNT"
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.network_self_link
      # TLS required, client certificates not: clients connect with
      # sslmode=require over the private IP.
      ssl_mode = "ENCRYPTED_ONLY"
    }

    # tenant_capacity x sql_connections_per_tenant x sql_connection_headroom;
    # see the variable descriptions and README for the sizing formula.
    database_flags {
      name  = "max_connections"
      value = tostring(var.sql_max_connections)
    }

    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
    }

    user_labels = var.labels
  }

  depends_on = [
    google_project_service.required,
    google_service_networking_connection.private_service_access,
  ]
}

resource "random_password" "sql_admin" {
  length  = 32
  special = false
}

resource "google_sql_user" "admin" {
  project  = var.project_id
  name     = var.sql_admin_user
  instance = google_sql_database_instance.tenants.name
  password = random_password.sql_admin.result
}

# Instance admin credentials, readable only by the provisioner (see iam.tf):
# tenant databases and roles are created through the SQL Admin API, but
# anything that has to run SQL against a tenant database from the job
# (extensions, ownership fixes) connects as this role over the private IP.
resource "google_secret_manager_secret" "sql_admin" {
  project   = var.project_id
  secret_id = local.sql_admin_secret_id

  replication {
    auto {}
  }

  labels = var.labels

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_version" "sql_admin" {
  secret      = google_secret_manager_secret.sql_admin.id
  secret_data = random_password.sql_admin.result
}

# DATABASE_URL for qm-api and the provisioner: the control-plane Postgres as
# the qm_api role (the tenant registry lives there, not on the instance
# above). Only the secret is managed here; the version is added out of band
# once the role exists (see README apply order), and neither workload will
# start a revision until it does.
resource "google_secret_manager_secret" "api_database_url" {
  project   = var.project_id
  secret_id = local.api_database_url_secret_id

  replication {
    auto {}
  }

  labels = var.labels

  depends_on = [google_project_service.required]
}

# Tenant container images. The provisioner deploys every tenant service from
# this repository; the platform's own images stay in the existing superserve
# repository.
resource "google_artifact_registry_repository" "tenant_images" {
  project       = var.project_id
  location      = var.region
  repository_id = local.tenant_image_repository_id
  format        = "DOCKER"
  description   = "Hosted QM tenant images (${var.environment})."
  labels        = var.labels

  depends_on = [google_project_service.required]
}
