terraform {
  required_version = ">= 1.9.0"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "= 8.2.0"
    }
  }
}

locals {
  environments = {
    development = {
      project_id        = "rayai-qm-dev"
      paired_project_id = "rayai-dev"
      regions           = ["us-central1"]
    }
    production = {
      project_id        = "rayai-qm-prod"
      paired_project_id = "rayai-prod"
      regions           = ["us-central1", "us-west2", "us-east4"]
    }
  }
  environment = local.environments[var.environment]
}

provider "google" {
  project                     = local.environment.paired_project_id
  impersonate_service_account = var.bootstrap_service_account
}
provider "google-beta" {
  project                     = local.environment.paired_project_id
  impersonate_service_account = var.bootstrap_service_account
}

module "foundation" {
  source                  = "../../modules/qm-bootstrap"
  project_id              = local.environment.project_id
  paired_project_id       = local.environment.paired_project_id
  regions                 = toset(local.environment.regions)
  folder_id               = var.folder_id
  billing_account         = var.billing_account
  github                  = var.github
  registry                = var.registry
  provisioning_enabled    = var.provisioning_enabled
  platform_services_ready = var.platform_services_ready
  cell_admin_secret_ids   = var.cell_admin_secret_ids
}

output "contract" {
  value = merge(module.foundation.contract, {
    bootstrap_identity = var.bootstrap_service_account
    bootstrap_state = {
      bucket = var.bootstrap_state_bucket
      prefix = "qm/${var.environment}/bootstrap"
    }
    roots = {
      bootstrap = "infra/bootstrap/qm"
      network   = "infra/envs/qm/${var.environment}"
    }
  })
}
