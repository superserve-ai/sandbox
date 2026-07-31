terraform {
  required_version = ">= 1.5.0"

  backend "gcs" {
    bucket = "superserve-terraform-state-prod"
    prefix = "production/us-west2"
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
  project_id             = var.project_id
  environment            = var.environment
  region                 = var.region
  zone                   = var.zone
  resource_suffix        = coalesce(var.resource_suffix, var.environment)
  service_account_suffix = coalesce(var.service_account_suffix, local.resource_suffix)
  api_sa_key             = "superserve_api"

  common_labels = {
    environment = local.environment
    managed_by  = "terraform"
    region      = local.region
  }

  sandbox_host_labels = merge(local.common_labels, {
    owner              = "platform"
    project            = "sandbox"
    dataclassification = "confidential"
    application        = "sandbox-host"
  })

  api_service_account_email = "superserve-api-runner@${local.project_id}.iam.gserviceaccount.com"
}
module "network" {
  source = "../../../modules/network"

  project_id  = local.project_id
  environment = local.environment
  region      = local.region

  create_network = var.create_network
  network_name   = var.network_name

  subnet_name            = "superserve-usw2-subnet"
  subnet_cidr            = var.subnet_cidr
  manage_public_ssh_deny = true
  enable_iap_ssh         = true
  iap_ssh_target_tags    = ["vmd-usw2"]

  create_vpc_connector        = false
  create_vpc_connector_subnet = true
  vpc_connector_name          = "superserve-usw2-connector"
  vpc_connector_subnet        = "superserve-usw2-cr-subnet"
  vpc_connector_subnet_ip     = var.connector_subnet_cidr

  firewall_rules = {
    allow_vmd_grpc = {
      name          = "superserve-usw2-allow-cr-vmd"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["vmd-usw2"]
      allow = [{
        protocol = "tcp"
        ports    = ["50051"]
      }]
      description = "Allow API-to-VMD gRPC traffic"
    }
  }

  labels = local.common_labels
}

data "google_service_account" "api_runner" {
  project    = local.project_id
  account_id = "superserve-api-runner"
}


data "google_service_account" "github_actions" {
  project    = local.project_id
  account_id = "superserve-github-actions"
}

# The api-runner SA's encrypt/decrypt grant on the credentials-kek KMS key is
# managed out-of-band and owned centrally: the CD Terraform SA lacks KMS
# setIamPolicy on the key, and the SA is shared across cells, so this follows
# the same out-of-band pattern as the shared runtime secrets.

# The runtime grant for the shared system-team-id-production secret is owned
# solely by production/us-central1 (its api_runtime_secrets set), matching how
# the other shared runtime secrets (posthog/slack/sentry) are granted to the
# shared api-runner SA — so this root doesn't double-manage the same binding
# from a separate state.

# deploy-proxy.yml fetches this secret directly via `gcloud secrets versions
# access` at deploy time for the usw cell step, instead of through a Cloud
# Run secret binding — so the CI service account needs read access here too,
# not just the Cloud Run runtime SA.
resource "google_secret_manager_secret_iam_member" "github_actions_sandbox_access_token_seed" {
  project   = local.project_id
  secret_id = coalesce(var.sandbox_access_token_seed_secret_name, "sandbox-access-token-seed-${local.resource_suffix}")
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${data.google_service_account.github_actions.email}"
}

module "api" {
  source = "../../../modules/api"

  project_id            = local.project_id
  environment           = local.environment
  region                = local.region
  service_name          = "superserve-api-${local.resource_suffix}"
  service_account_email = data.google_service_account.api_runner.email
  image                 = "us-central1-docker.pkg.dev/${local.project_id}/superserve/controlplane:replace-me"

  cpu_limit         = "2"
  memory_limit      = "1Gi"
  min_instances     = 2
  max_instances     = 100
  startup_cpu_boost = true
  cpu_idle          = true

  env = {
    API_PORT               = "8080"
    EDGE_PROXY_DOMAIN      = "usw-sandbox.superserve.ai"
    SANDBOX_ID_REGION      = "usw"
    SUPABASE_URL           = var.supabase_url
    SECRETS_SIGNING_KEY_ID = "v1"
    ALLOW_EPHEMERAL_SEED   = "0"
    DB_MAX_CONNS           = "12"
    VMD_GRPC_ADDRESS       = format("%s:50051", module.sandbox_host.internal_ip)
    KMS_KEY_RESOURCE       = "projects/rayai-prod/locations/us-central1/keyRings/superserve/cryptoKeys/credentials-kek"
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

  vpc_connector  = null
  vpc_egress     = "PRIVATE_RANGES_ONLY"
  vpc_network    = var.network_name
  vpc_subnetwork = module.network.vpc_connector_subnetwork_name
  vpc_tags       = ["cr-usw2"]

  labels = local.common_labels
}

module "sandbox_host" {
  source = "../../../modules/sandbox-host"

  project_id    = local.project_id
  environment   = local.environment
  region        = local.region
  zone          = local.zone
  instance_name = "superserve-vmd-${local.resource_suffix}"
  machine_type  = var.machine_type
  subnet        = module.network.subnetwork_self_link
  internal_ip   = "10.1.0.2"
  tags          = ["vmd-usw2"]
  labels = merge(local.sandbox_host_labels, {
    component    = "vmd"
    sandbox_role = "vmd"
  })

  service_account_email = data.google_service_account.api_runner.email
  boot_disk_image       = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts"
  boot_disk_size_gb     = 250
  can_ip_forward        = false
  on_host_maintenance   = "TERMINATE"

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "TRUE"
  }
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
}

# Durability tier for the host's local-SSD artifacts (sandbox snapshots,
# template builds). The vmd host runs as the shared api-runner SA, so that SA
# is the writer: create+read on this bucket, never delete — deletes belong to
# the module's dedicated GC identity, which nothing on the host runs as.
module "backup_storage" {
  source = "../../../modules/backup-storage"

  project_id  = local.project_id
  environment = local.environment
  location    = local.region
  bucket_name = "superserve-artifact-backup-${local.resource_suffix}"

  gc_service_account_id = "superserve-backup-gc-${local.resource_suffix}"

  restore_service_account_id = "superserve-backup-ro-${local.resource_suffix}"

  writer_members = [
    "serviceAccount:${data.google_service_account.api_runner.email}",
  ]

  labels = merge(local.common_labels, {
    component = "backup"
  })
}
