terraform {
  required_version = ">= 1.5.0"
}

locals {
  create_vpc_connector_subnet = coalesce(
    var.create_vpc_connector_subnet,
    var.create_vpc_connector && var.vpc_connector_mode == "subnet"
  )

  network_self_link = (
    var.create_network
    ? google_compute_network.this[0].self_link
    : data.google_compute_network.existing[0].self_link
  )

  network_name = var.network_name
}

resource "google_compute_network" "this" {
  count = var.create_network ? 1 : 0

  project                 = var.project_id
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

data "google_compute_network" "existing" {
  count = var.create_network ? 0 : 1

  project = var.project_id
  name    = var.network_name
}

resource "google_compute_subnetwork" "primary" {
  project       = var.project_id
  name          = var.subnet_name
  region        = var.region
  ip_cidr_range = var.subnet_cidr
  network       = local.network_self_link
}

resource "google_compute_subnetwork" "connector" {
  count = local.create_vpc_connector_subnet ? 1 : 0

  project       = var.project_id
  name          = var.vpc_connector_subnet
  region        = var.region
  ip_cidr_range = var.vpc_connector_subnet_ip
  network       = local.network_self_link
}

resource "google_vpc_access_connector" "this" {
  count = var.create_vpc_connector ? 1 : 0

  project       = var.project_id
  name          = var.vpc_connector_name
  region        = var.region
  machine_type  = var.vpc_connector_machine_type
  min_instances = var.vpc_connector_min_instances
  max_instances = var.vpc_connector_max_instances
  network       = var.vpc_connector_mode == "ip_cidr_range" ? local.network_name : null

  ip_cidr_range = var.vpc_connector_mode == "ip_cidr_range" ? var.vpc_connector_ip_cidr_range : null

  dynamic "subnet" {
    for_each = var.vpc_connector_mode == "subnet" ? [1] : []

    content {
      name = (
        local.create_vpc_connector_subnet
        ? google_compute_subnetwork.connector[0].name
        : var.vpc_connector_subnet
      )
      project_id = var.project_id
    }
  }

  depends_on = [
    google_compute_subnetwork.connector,
  ]
}

resource "google_compute_firewall" "rules" {
  for_each = var.firewall_rules

  project       = var.project_id
  name          = coalesce(try(each.value.name, null), replace(each.key, "_", "-"))
  network       = local.network_self_link
  direction     = each.value.direction
  priority      = each.value.priority
  source_ranges = each.value.source_ranges
  target_tags   = each.value.target_tags
  description   = each.value.description

  dynamic "allow" {
    for_each = each.value.allow

    content {
      protocol = allow.value.protocol
      ports    = allow.value.ports
    }
  }

  dynamic "deny" {
    for_each = each.value.deny

    content {
      protocol = deny.value.protocol
      ports    = deny.value.ports
    }
  }
}

locals {
  network_contract = {
    project_id                  = var.project_id
    environment                 = var.environment
    region                      = var.region
    network_name                = local.network_name
    subnet_name                 = google_compute_subnetwork.primary.name
    subnet_cidr                 = google_compute_subnetwork.primary.ip_cidr_range
    create_network              = var.create_network
    create_vpc_connector        = var.create_vpc_connector
    create_vpc_connector_subnet = local.create_vpc_connector_subnet
    vpc_connector_name          = try(google_vpc_access_connector.this[0].name, null)
    vpc_connector_subnet        = try(google_compute_subnetwork.connector[0].name, var.vpc_connector_subnet)
    vpc_connector_subnet_ip     = try(google_compute_subnetwork.connector[0].ip_cidr_range, var.vpc_connector_subnet_ip)
    firewall_rules              = { for key, rule in google_compute_firewall.rules : key => rule.name }
    labels                      = var.labels
  }
}
