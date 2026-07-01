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

  api_service_account_email = "superserve-api-runner@${local.project_id}.iam.gserviceaccount.com"
}

module "network" {
  source = "../../../modules/network"

  project_id  = local.project_id
  environment = local.environment
  region      = local.region

  create_network = var.create_network
  network_name   = var.network_name

  subnet_name = "superserve-prod-subnet"
  subnet_cidr = var.subnet_cidr

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
      target_tags   = []
      allow = [
        {
          protocol = "icmp"
          ports    = []
        },
        {
          protocol = "tcp"
          ports    = ["0-65535"]
        },
        {
          protocol = "udp"
          ports    = ["0-65535"]
        }
      ]
      description = null
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
  labels = local.common_labels
}

module "api" {
  source = "../../../modules/api"

  project_id            = local.project_id
  environment           = local.environment
  region                = local.region
  service_name          = "superserve-api"
  service_account_email = module.iam.service_account_emails[local.api_sa_key]
  image                 = "${local.region}-docker.pkg.dev/${local.project_id}/superserve/controlplane:replace-me"

  env = {
    API_PORT          = "8080"
    EDGE_PROXY_DOMAIN = "usc-sandbox.superserve.ai"
    SUPABASE_URL      = var.supabase_url
    VMD_GRPC_ADDRESS  = "10.0.0.3:50051"
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
  tags          = []
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

  project_id  = local.project_id
  environment = local.environment
  labels      = local.common_labels
}
