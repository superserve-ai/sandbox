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

resource "google_project_service" "cloud_ids" {
  project            = local.project_id
  service            = "ids.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "compute" {
  project            = local.project_id
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "logging" {
  project            = local.project_id
  service            = "logging.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "monitoring" {
  project            = local.project_id
  service            = "monitoring.googleapis.com"
  disable_on_destroy = false
}

locals {
  project_id                = var.project_id
  environment               = var.environment
  region                    = var.region
  zone                      = var.zone
  resource_suffix           = coalesce(var.resource_suffix, var.environment)
  service_account_suffix    = coalesce(var.service_account_suffix, local.resource_suffix)
  api_sa_key                = "superserve_api"
  api_service_account_email = "superserve-api-runner@${local.project_id}.iam.gserviceaccount.com"

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

  # The us-central1 primary control plane and vmd host are decommissioned. This
  # root now keeps only its subnet in the shared superserve-production-vpc; the
  # host's firewall rules, IAP-SSH allow, public-SSH deny, and the Cloud Run VPC
  # connector (used only by the removed control plane) are all removed. The
  # us-east4 cell owns its own equivalents in the same VPC.
  subnet_name = "superserve-prod-subnet"
  subnet_cidr = var.subnet_cidr

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
      display_name = "Superserve API Cloud Run Service Account"
    }
  }
  project_bindings = {
    production_host_metric_writer = {
      role = "roles/monitoring.metricWriter"
      members = [
        "serviceAccount:${local.api_service_account_email}"
      ]
    }
  }
  labels = local.common_labels
}
resource "google_secret_manager_secret_iam_member" "api_runtime_secrets" {
  for_each = toset([
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

# The api-runner SA's encrypt/decrypt grant on the credentials-kek KMS key is
# managed out-of-band: the CD Terraform SA lacks KMS setIamPolicy on the key,
# and the SA is shared across cells, so this follows the same out-of-band
# pattern as the shared runtime secrets.


# Production monitoring dashboards. These are fleet-wide (whole-fleet
# operations/hosts/database/collector views spanning every region), not
# us-central1-specific — they are rooted in this state only because us-central1
# was historically the primary region. The host and control plane here are being
# decommissioned, but the dashboards must survive, so this module stays. The
# per-host CPU alert that used to live here was removed with the host it watched.
module "observability" {
  source = "../../../modules/observability"

  project_id               = local.project_id
  environment              = local.environment
  notification_channel_ids = var.notification_channel_ids
  labels                   = local.common_labels
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
