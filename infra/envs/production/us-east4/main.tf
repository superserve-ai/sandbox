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

  subnet_name = "superserve-use4-subnet"
  subnet_cidr = var.subnet_cidr

  # Cloud Run networking (connector or direct-VPC-egress subnet) is deferred
  # to the us-east4 Cloud Run rollout — this environment stands up the vmd
  # host only.
  create_vpc_connector        = false
  create_vpc_connector_subnet = false

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

  # Label-last: deliberately NOT setting component=vmd/sandbox_role=vmd here.
  # CD and the scheduler key on these labels, so the host stays out of prod
  # rotation until bring-up (SS-189) and validation (Phase C) are done. Flip
  # to component=vmd / sandbox_role=vmd via `gcloud compute instances
  # add-labels` at cutover — `labels` is in the module's ignore_changes, so a
  # later `terraform apply` won't revert that.
  labels = merge(local.common_labels, {
    sandbox_status = "provisioning"
  })

  service_account_email = data.google_service_account.api_runner.email

  # Matches the live us-central1 prod host (Ubuntu 22.04.5 LTS), NOT this
  # module's typical ubuntu-2404-lts default — verified 2026-07-17 via direct
  # SSH that us-central1 actually runs 22.04.5, and SS-173 showed a host-OS
  # kernel mismatch (west's newer default vs prod's) breaks snapshot restore.
  # Since this host must restore snapshots copied from us-central1 (SS-195),
  # matching its OS/kernel family is the safe choice.
  boot_disk_image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2204-lts"

  can_ip_forward      = false
  on_host_maintenance = "TERMINATE"

  reservation_name = var.reservation_name

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "TRUE"
  }
}
