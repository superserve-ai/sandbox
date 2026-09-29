terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

resource "google_compute_network" "tenant" {
  project                 = var.project_id
  name                    = "qm-tenant-${var.region}"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_subnetwork" "tenant" {
  project                  = var.project_id
  name                     = "qm-tenant-${var.region}"
  region                   = var.region
  network                  = google_compute_network.tenant.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
  stack_type               = "IPV4_ONLY"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_router" "tenant" {
  project = var.project_id
  name    = "qm-tenant-${var.region}"
  region  = var.region
  network = google_compute_network.tenant.id
}

resource "google_compute_router_nat" "tenant" {
  project                            = var.project_id
  name                               = "qm-tenant-${var.region}"
  region                             = var.region
  router                             = google_compute_router.tenant.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = google_compute_subnetwork.tenant.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}

resource "google_compute_firewall" "control" {
  count              = length(var.control_db_cidrs) == 0 ? 0 : 1
  project            = var.project_id
  name               = "qm-${var.region}-deny-control"
  network            = google_compute_network.tenant.id
  direction          = "EGRESS"
  priority           = 100
  destination_ranges = sort(tolist(var.control_db_cidrs))
  deny {
    protocol = "all"
  }
}

resource "google_compute_firewall" "cell" {
  for_each           = var.db_cells
  project            = var.project_id
  name               = "qm-${var.region}-${each.key}-sql"
  network            = google_compute_network.tenant.id
  direction          = "EGRESS"
  priority           = 200
  target_tags        = ["qm-db-${each.key}-client"]
  destination_ranges = ["${each.value.private_ip}/32"]
  lifecycle {
    precondition {
      condition     = length(var.control_db_cidrs) > 0
      error_message = "Publish the central control database deny ranges before allowing any tenant cell."
    }
  }
  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
}

resource "google_compute_firewall" "private" {
  project   = var.project_id
  name      = "qm-${var.region}-deny-private"
  network   = google_compute_network.tenant.id
  direction = "EGRESS"
  priority  = 300
  destination_ranges = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "198.18.0.0/15",
    "224.0.0.0/4", "240.0.0.0/4",
  ]
  deny {
    protocol = "all"
  }
}

resource "google_compute_firewall" "internet" {
  project            = var.project_id
  name               = "qm-${var.region}-allow-public"
  network            = google_compute_network.tenant.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "all"
  }
}

resource "google_compute_firewall" "ingress" {
  project       = var.project_id
  name          = "qm-${var.region}-deny-ingress"
  network       = google_compute_network.tenant.id
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "all"
  }
}
