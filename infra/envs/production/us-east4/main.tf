terraform {
  required_version = ">= 1.5.0"

  backend "gcs" {
    bucket = "superserve-terraform-state-prod"
    prefix = "production/us-east4"
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
}

locals {
  project_id             = var.project_id
  environment            = var.environment
  region                 = var.region
  zone                   = var.zone
  resource_suffix        = coalesce(var.resource_suffix, var.environment)
  service_account_suffix = coalesce(var.service_account_suffix, local.resource_suffix)

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

  subnet_name            = "superserve-use4-subnet"
  subnet_cidr            = var.subnet_cidr
  manage_public_ssh_deny = true
  enable_iap_ssh         = false
  iap_ssh_target_tags    = ["vmd-use4"]

  # Cloud Run reaches the vmd host over direct VPC egress (no connector),
  # matching the usw2 cell. The dedicated egress subnet carries the Cloud Run
  # sender range; the firewall rules below admit it to vmd gRPC + host OTLP.
  create_vpc_connector        = false
  create_vpc_connector_subnet = true
  vpc_connector_subnet        = "superserve-use4-cr-subnet"
  vpc_connector_subnet_ip     = var.connector_subnet_cidr

  firewall_rules = {
    allow_vmd_grpc = {
      name          = "superserve-use4-allow-cr-vmd"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["vmd-use4"]
      allow = [{
        protocol = "tcp"
        ports    = ["50051"]
      }]
      description = "Allow API-to-VMD gRPC traffic"
    }
    allow_otel_ingress = {
      name          = "superserve-use4-allow-cr-to-host-otel"
      direction     = "INGRESS"
      source_ranges = [var.connector_subnet_cidr]
      target_tags   = ["vmd-use4"]
      allow = [{
        protocol = "tcp"
        ports    = ["4317", "4318"]
      }]
      description = "Allow Cloud Run connector traffic to host-local OTLP endpoints."
    }
  }

  labels = local.common_labels
}

data "google_service_account" "api_runner" {
  project    = local.project_id
  account_id = "superserve-api-runner"
}

# A5: us-east4 control plane for the "use" cell.
#
# This is a host swap, not a new cell: us-east4 shares the use-cell Supabase,
# runtime secrets, api-runner service account, and KMS key with us-central1.
# Only the service name, region, and VMD address are region-local — traffic
# splits between this service and the us-central1 one during cutover, then
# us-central1 drains. Secrets resolve to the shared (suffix-less) use-cell
# names via the *_secret_name overrides in terraform.tfvars.
#
# No per-root secret IAM here: the shared api-runner SA already holds the
# runtime accessor grants (owned by us-central1's api_runtime_secrets) and the
# credentials-kek encrypt/decrypt grant (owned out-of-band). Re-declaring them
# from this state would double-manage the same bindings — the same split we
# settled for usw2 in #232/#233.
module "api" {
  source = "../../../modules/api"

  project_id            = local.project_id
  environment           = local.environment
  region                = local.region
  service_name          = "superserve-api-${local.resource_suffix}"
  service_account_email = data.google_service_account.api_runner.email
  # First create must reference a tag that actually exists, or the initial
  # revision never goes ready and the apply fails. The other regions can carry
  # a ":replace-me" placeholder only because their services already exist and
  # image is in the module's ignore_changes. us-east4's service is new, so pin
  # ":latest" for the create; CD's deploy step later moves it to the commit SHA
  # and ignore_changes keeps terraform from reverting that.
  image = "us-central1-docker.pkg.dev/${local.project_id}/superserve/controlplane:latest"

  cpu_limit         = "2"
  memory_limit      = "1Gi"
  min_instances     = 2
  max_instances     = 100
  startup_cpu_boost = true
  cpu_idle          = true

  env = {
    API_PORT               = "8080"
    EDGE_PROXY_DOMAIN      = "sandbox.superserve.ai"
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
  vpc_tags       = ["cr-use4"]

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
  internal_ip   = var.host_internal_ip
  tags          = ["vmd-use4"]

  # Keep the host out of production discovery until bring-up and pre-cutover
  # validation are complete. CD and the scheduler use workload labels for
  # host discovery, so those labels must be added through the cutover process.
  labels = merge(local.common_labels, {
    sandbox_status = "provisioning"
  })

  service_account_email = data.google_service_account.api_runner.email

  # Matches the live us-central1 prod host (Ubuntu 22.04 LTS), NOT this
  # module's typical 24.04 default — the current prod host actually runs
  # 22.04, and a host-OS kernel mismatch between hosts has been observed to
  # break snapshot restore. Since this host must restore snapshots copied
  # from us-central1, matching its OS/kernel family is the safe choice.
  boot_disk_image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts"

  # C4 (like Z3) has no Persistent Disk support — the boot disk must be a
  # Hyperdisk type, or the instance insert is rejected.
  boot_disk_type = var.boot_disk_type

  can_ip_forward      = false
  on_host_maintenance = "TERMINATE"

  reservation_name = var.reservation_name

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
