terraform {
  required_version = ">= 1.9.0"
  backend "gcs" {
    bucket = "rayai-qm-dev-terraform"
    prefix = "network"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  project = "rayai-qm-dev"
}

locals {
  regions = {
    us-central1 = "10.80.0.0/20"
  }
}

module "network" {
  for_each         = local.regions
  source           = "../../../modules/qm"
  project_id       = "rayai-qm-dev"
  region           = each.key
  subnet_cidr      = each.value
  db_cells         = lookup(var.db_cells, each.key, {})
  control_db_cidrs = var.control_db_cidrs
}

output "contract" {
  value = { for region, network in module.network : region => network.contract }
}
