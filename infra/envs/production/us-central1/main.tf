terraform {
  required_version = ">= 1.5.0"

  backend "gcs" {
    bucket = "superserve-terraform-state-prod"
    prefix = "production/us-central1"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = local.project_id
  region  = local.region
  # impersonate_service_account = "terraform@rayai-dev.iam.gserviceaccount.com"
}

locals {
  project_id                 = var.project_id
  environment                = var.environment
  region                     = var.region
  zone                       = var.zone
  resource_suffix            = coalesce(var.resource_suffix, var.environment)
  service_account_suffix     = coalesce(var.service_account_suffix, local.resource_suffix)
  api_sa_key                 = "superserve_api"
  api_runner_sa_key          = "superserve_api_runtime"
  host_runner_sa_key         = "superserve_sandbox_runtime"
  api_service_account_email  = "superserve-api-runtime@${local.project_id}.iam.gserviceaccount.com"
  host_service_account_email = "superserve-sandbox-runtime@${local.project_id}.iam.gserviceaccount.com"

  common_labels = {
    environment = local.environment
    managed_by  = "terraform"
    region      = local.region
  }
}

module "network" {
  source = "../../../modules/network"

  project_id  = local.project_id
  environment = local.environment
  region      = local.region

  create_network = var.create_network
  network_name   = var.network_name

  # The us-central1 primary control plane and VMD host are decommissioned. This
  # root retains the shared subnet and bootstrap IAM/state resources only; the
  # active production workloads are managed by their regional roots.
  subnet_name            = "superserve-prod-subnet"
  subnet_cidr            = var.subnet_cidr
  manage_public_ssh_deny = false
  enable_iap_ssh         = false
  create_vpc_connector   = false
  firewall_rules         = {}

  labels = local.common_labels
}

module "iam" {
  source = "../../../modules/iam"

  project_id  = local.project_id
  environment = local.environment
  service_accounts = {
    (local.api_sa_key) = {
      account_id   = "superserve-api-runner"
      display_name = "Superserve API (legacy runtime)"
      description  = "Retained during migration to the dedicated production runner account."
    }
    (local.api_runner_sa_key) = {
      account_id   = "superserve-api-runtime"
      display_name = "Superserve production API runtime"
      description  = "Runtime identity for the production API service."
    }
    (local.host_runner_sa_key) = {
      account_id   = "superserve-sandbox-runtime"
      display_name = "Superserve production sandbox runtime"
      description  = "Runtime identity for the production sandbox host."
    }
    superserve_runner = {
      account_id   = "superserve-runner"
      display_name = "Superserve production runtime (legacy)"
      description  = "Retained during migration to separate API and sandbox runtime identities."
    }
    superserve_deployer = {
      account_id   = "superserve-deployer"
      display_name = "Superserve production infrastructure deployer"
      description  = "Terraform and deployment identity; not used by running workloads."
    }
  }
  project_bindings = {
    production_runtime_metric_writer = {
      role = "roles/monitoring.metricWriter"
      members = [
        # Keep the legacy runtime identity in the primary slot while the
        # production cutover is still retaining its metrics access.
        "serviceAccount:superserve-api-runner@${local.project_id}.iam.gserviceaccount.com",
        "serviceAccount:${local.api_service_account_email}",
        "serviceAccount:${local.host_service_account_email}",
      ]
    }
    production_runtime_log_writer = {
      role = "roles/logging.logWriter"
      members = [
        "serviceAccount:${local.api_service_account_email}",
        "serviceAccount:${local.host_service_account_email}",
        "serviceAccount:superserve-api-runner@${local.project_id}.iam.gserviceaccount.com",
      ]
    }
    production_deployer_compute_instance_admin = {
      role    = "roles/compute.instanceAdmin.v1"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_compute_network_admin = {
      role    = "roles/compute.networkAdmin"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_compute_security_admin = {
      role    = "roles/compute.securityAdmin"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_compute_load_balancer_admin = {
      role    = "roles/compute.loadBalancerAdmin"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_compute_os_admin_login = {
      role    = "roles/compute.osAdminLogin"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_iap_tunnel_accessor = {
      role    = "roles/iap.tunnelResourceAccessor"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_run_admin = {
      role    = "roles/run.admin"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    # Account creation and project/secret IAM policy changes are bootstrap-only
    # operations. Keeping those permissions off the routine deployer prevents
    # it from escalating itself or changing unrelated identities and secrets.
    production_deployer_service_account_viewer = {
      role    = "roles/iam.serviceAccountViewer"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_secret_viewer = {
      role    = "roles/secretmanager.viewer"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_artifact_registry_writer = {
      role    = "roles/artifactregistry.writer"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_vpc_access_admin = {
      role    = "roles/vpcaccess.admin"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_monitoring_editor = {
      role    = "roles/monitoring.editor"
      members = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
  }
  service_bindings = {
    production_deployer_can_run_as_runtime = {
      service_account = "projects/${local.project_id}/serviceAccounts/${local.api_service_account_email}"
      role            = "roles/iam.serviceAccountUser"
      members         = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
    production_deployer_can_run_as_sandbox_runtime = {
      service_account = "projects/${local.project_id}/serviceAccounts/${local.host_service_account_email}"
      role            = "roles/iam.serviceAccountUser"
      members         = ["serviceAccount:superserve-deployer@${local.project_id}.iam.gserviceaccount.com"]
    }
  }
  workload_identity = {
    github_sandbox = {
      service_account = "projects/${local.project_id}/serviceAccounts/superserve-deployer@${local.project_id}.iam.gserviceaccount.com"
      principal       = "principalSet://iam.googleapis.com/projects/887554770957/locations/global/workloadIdentityPools/github-pool/attribute.repository/superserve-ai/sandbox"
    }
  }
  labels = local.common_labels
}
# Keep the legacy production metric grant in state while renaming the binding
# key so the rollout does not delete the shared member during the cutover.
moved {
  from = module.iam.google_project_iam_member.project_bindings["production_host_metric_writer"]
  to   = module.iam.google_project_iam_member.project_bindings["production_runtime_metric_writer"]
}

# These four instances existed before the runtime identity split. Move their
# state to the legacy resource so Terraform retains the live IAM members instead
# of deleting them after creating duplicate grants under the new address.
moved {
  from = google_secret_manager_secret_iam_member.api_runtime_secrets["posthog-project-key"]
  to   = google_secret_manager_secret_iam_member.legacy_api_runtime_secrets["posthog-project-key"]
}

moved {
  from = google_secret_manager_secret_iam_member.api_runtime_secrets["slack-quota-alert-webhook"]
  to   = google_secret_manager_secret_iam_member.legacy_api_runtime_secrets["slack-quota-alert-webhook"]
}

moved {
  from = google_secret_manager_secret_iam_member.api_runtime_secrets["sentry-dsn"]
  to   = google_secret_manager_secret_iam_member.legacy_api_runtime_secrets["sentry-dsn"]
}

moved {
  from = google_secret_manager_secret_iam_member.api_runtime_secrets["system-team-id-production"]
  to   = google_secret_manager_secret_iam_member.legacy_api_runtime_secrets["system-team-id-production"]
}

resource "google_secret_manager_secret_iam_member" "new_api_runtime_secrets" {
  for_each = toset([
    coalesce(var.database_url_secret_name, "database-url-${local.resource_suffix}"),
    coalesce(var.internal_api_token_secret_name, "internal-api-token-${local.resource_suffix}"),
    coalesce(var.sandbox_access_token_seed_secret_name, "sandbox-access-token-seed-${local.resource_suffix}"),
    coalesce(var.secrets_signing_key_secret_name, "secretsproxy-signing-key-${local.resource_suffix}"),
    "posthog-project-key",
    "slack-quota-alert-webhook",
    coalesce(var.sentry_dsn_secret_name, "sentry-dsn"),
    coalesce(var.system_team_id_secret_name, "system-team-id-${local.resource_suffix}"),
  ])

  project   = local.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.api_service_account_email}"
}

# The old API runtime stays authorized until the regional rollout finishes so
# old revisions can still read their secret environment variables during cutover.
resource "google_secret_manager_secret_iam_member" "legacy_api_runtime_secrets" {
  for_each = toset([
    coalesce(var.database_url_secret_name, "database-url-${local.resource_suffix}"),
    coalesce(var.internal_api_token_secret_name, "internal-api-token-${local.resource_suffix}"),
    coalesce(var.sandbox_access_token_seed_secret_name, "sandbox-access-token-seed-${local.resource_suffix}"),
    coalesce(var.secrets_signing_key_secret_name, "secretsproxy-signing-key-${local.resource_suffix}"),
    "posthog-project-key",
    "slack-quota-alert-webhook",
    coalesce(var.sentry_dsn_secret_name, "sentry-dsn"),
    coalesce(var.system_team_id_secret_name, "system-team-id-${local.resource_suffix}"),
  ])

  project   = local.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:superserve-api-runner@${local.project_id}.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "deployer_terraform_state" {
  bucket = "superserve-terraform-state-prod"
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${module.iam.service_account_emails["superserve_deployer"]}"
}

resource "google_storage_bucket_iam_member" "deployer_terraform_state_reader" {
  bucket = "superserve-terraform-state-prod"
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${module.iam.service_account_emails["superserve_deployer"]}"
}

module "observability" {
  source = "../../../modules/observability"

  project_id  = local.project_id
  environment = local.environment
  labels      = local.common_labels
  dashboards = {
    sandbox_operations = {
      display_name = "Sandbox Telemetry / Production Operations"
      definition = templatefile("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-operations.json.tftpl", {
        environment  = local.environment
        display_name = "Sandbox Telemetry / Production Operations"
      })
    }

    sandbox_collector = {
      display_name = "Sandbox Telemetry / Collector"
      definition   = file("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-collector.json")
    }

    sandbox_fleet = {
      display_name = "Sandbox Telemetry / Production Fleet"
      definition = templatefile("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-fleet.json.tftpl", {
        environment  = local.environment
        display_name = "Sandbox Telemetry / Production Fleet"
      })
    }

    sandbox_hosts = {
      display_name = "Sandbox Telemetry / Production Hosts"
      definition = templatefile("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-hosts.json.tftpl", {
        environment  = local.environment
        display_name = "Sandbox Telemetry / Production Hosts"
      })
    }

    sandbox_database = {
      display_name = "Sandbox Telemetry / Production Database"
      definition = templatefile("${path.module}/../../../dashboards/cloud-monitoring/sandbox-telemetry-database.json.tftpl", {
        environment  = local.environment
        display_name = "Sandbox Telemetry / Production Database"
      })
    }
  }
}
