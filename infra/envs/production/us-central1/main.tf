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

  subnet_name            = "superserve-prod-subnet"
  subnet_cidr            = var.subnet_cidr
  manage_public_ssh_deny = true
  enable_iap_ssh         = true
  iap_ssh_target_tags    = ["superserve-vmd"]

  create_vpc_connector        = true
  create_vpc_connector_subnet = false
  vpc_connector_name          = "superserve-prod-conn"
  vpc_connector_mode          = "ip_cidr_range"
  vpc_connector_ip_cidr_range = var.connector_subnet_cidr
  vpc_connector_machine_type  = "e2-micro"
  vpc_connector_min_instances = 2
  vpc_connector_max_instances = 10

  firewall_rules = {
    allow_internal = {
      name          = "superserve-prod-allow-internal"
      direction     = "INGRESS"
      source_ranges = [var.subnet_cidr]
      target_tags   = ["superserve-vmd"]
      allow = [
        {
          protocol = "tcp"
          ports    = ["5007", "5008", "50051"]
        }
      ]
      description = "Allow private host-to-host sandbox control traffic only."
    }
    allow_otel_ingress = {
      name          = "superserve-prod-allow-cr-to-host-otel"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["superserve-vmd"]
      allow = [
        {
          protocol = "tcp"
          ports    = ["4317", "4318"]
        }
      ]
      description = "Allow Cloud Run connector traffic to host-local OTLP endpoints."
    }
    allow_vmd_grpc = {
      name          = "superserve-prod-allow-cr-to-host-vmd"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["superserve-vmd"]
      allow = [{
        protocol = "tcp"
        ports    = ["50051"]
      }]
      description = "Allow Cloud Run connector traffic to the host VMD gRPC endpoint."
    }
  }

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

module "api" {
  source = "../../../modules/api"

  project_id            = local.project_id
  environment           = local.environment
  region                = local.region
  service_name          = "superserve-api"
  service_account_email = module.iam.service_account_emails[local.api_sa_key]
  image                 = "${local.region}-docker.pkg.dev/${local.project_id}/superserve/controlplane:replace-me"

  env = {
    API_PORT                    = "8080"
    SUPABASE_URL                = var.supabase_url
    SECRETS_SIGNING_KEY_ID      = "v1"
    VMD_GRPC_ADDRESS            = format("%s:50051", module.sandbox_host.internal_ip)
    ALLOW_EPHEMERAL_SEED        = "0"
    DB_MAX_CONNS                = "12"
    EDGE_PROXY_DOMAIN           = "sandbox.superserve.ai"
    KMS_KEY_RESOURCE            = "projects/rayai-prod/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek"
    OTEL_ENVIRONMENT            = local.environment
    OTEL_EXPORTER_OTLP_ENDPOINT = "http://${module.sandbox_host.internal_ip}:4318"
    OTEL_EXPORT_INTERVAL        = "15s"
    OTEL_METRICS_ENABLED        = "true"
    OTEL_SERVICE_NAME           = "sandbox-controlplane"
  }

  secrets = {
    DATABASE_URL = {
      secret = coalesce(var.database_url_secret_name, "database-url-${local.resource_suffix}")
    }
    INTERNAL_API_TOKEN = {
      secret = coalesce(var.internal_api_token_secret_name, "internal-api-token-${local.resource_suffix}")
    }
    SANDBOX_ACCESS_TOKEN_SEED = {
      secret = coalesce(var.sandbox_access_token_seed_secret_name, "sandbox-access-token-seed-${local.resource_suffix}")
    }
    SECRETS_SIGNING_KEY = {
      secret = coalesce(var.secrets_signing_key_secret_name, "secretsproxy-signing-key-${local.resource_suffix}")
    }
    SENTRY_DSN = {
      secret = coalesce(var.sentry_dsn_secret_name, "sentry-dsn")
    }
    SYSTEM_TEAM_ID = {
      secret = coalesce(var.system_team_id_secret_name, "system-team-id-${local.resource_suffix}")
    }
    SLACK_QUOTA_ALERT_WEBHOOK = {
      secret = "slack-quota-alert-webhook"
    }
    POSTHOG_KEY = {
      secret = "posthog-project-key"
    }
  }
  cpu_limit         = "2"
  memory_limit      = "1Gi"
  min_instances     = 6
  max_instances     = 10
  startup_cpu_boost = true
  cpu_idle          = true

  vpc_connector = module.network.vpc_connector_id
  vpc_egress    = "PRIVATE_RANGES_ONLY"
  labels        = local.common_labels

  depends_on = [
    google_secret_manager_secret_iam_member.api_runtime_secrets,
  ]
}

module "sandbox_host" {
  source = "../../../modules/sandbox-host"

  project_id    = local.project_id
  environment   = local.environment
  region        = local.region
  zone          = local.zone
  instance_name = "superserve-vmd-prod"
  machine_type  = var.machine_type
  subnet        = module.network.subnetwork_self_link
  internal_ip   = "10.0.0.3"
  tags          = ["superserve-vmd"]
  labels = merge(local.common_labels, {
    component               = "vmd"
    sandbox_role            = "vmd"
    "goog-ops-agent-policy" = "v2-template-1-7-0"
  })

  service_account_email = module.iam.service_account_emails[local.api_sa_key]
  boot_disk_image       = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts"
  can_ip_forward        = false
  on_host_maintenance   = "TERMINATE"
  metadata              = {}
}

module "observability" {
  source = "../../../modules/observability"

  project_id               = local.project_id
  environment              = local.environment
  notification_channel_ids = var.notification_channel_ids
  compute_instance_cpu_alerts = {
    sandbox_host = {
      display_name  = "Infrastructure / ${module.sandbox_host.instance_name} / CPU saturation"
      instance_name = module.sandbox_host.instance_name
      instance_id   = module.sandbox_host.instance_id
    }
  }
  labels = local.common_labels
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
