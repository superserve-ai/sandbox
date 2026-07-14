terraform {
  required_version = ">= 1.5.0"
}

resource "google_compute_instance" "this" {
  project                   = var.project_id
  name                      = var.instance_name
  zone                      = var.zone
  machine_type              = var.machine_type
  can_ip_forward            = var.can_ip_forward
  allow_stopping_for_update = var.allow_stopping_for_update
  tags                      = var.tags
  labels                    = var.labels

  boot_disk {
    auto_delete = true

    initialize_params {
      image = var.boot_disk_image
      size  = var.boot_disk_size_gb
      type  = var.boot_disk_type
    }
  }

  network_interface {
    subnetwork = var.subnet
    network_ip = var.internal_ip
  }

  metadata = var.metadata

  service_account {
    email  = var.service_account_email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  advanced_machine_features {
    enable_nested_virtualization = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = var.on_host_maintenance
    provisioning_model  = "STANDARD"
  }

  dynamic "reservation_affinity" {
    for_each = var.reservation_name == null ? [] : [var.reservation_name]
    content {
      type = "SPECIFIC_RESERVATION"
      specific_reservation {
        key    = "compute.googleapis.com/reservation-name"
        values = [reservation_affinity.value]
      }
    }
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = false
    enable_vtpm                 = true
  }

  lifecycle {
    prevent_destroy = true

    ignore_changes = [
      advanced_machine_features,
      boot_disk,
      labels,
      metadata,
      network_interface[0].access_config,
      scheduling,
      scratch_disk,
    ]
  }
}

locals {
  sandbox_host_contract = {
    project_id            = var.project_id
    environment           = var.environment
    region                = var.region
    zone                  = google_compute_instance.this.zone
    instance_name         = google_compute_instance.this.name
    machine_type          = google_compute_instance.this.machine_type
    subnet                = var.subnet
    internal_ip           = try(google_compute_instance.this.network_interface[0].network_ip, var.internal_ip)
    tags                  = var.tags
    labels                = var.labels
    service_account_email = var.service_account_email
    boot_disk_image       = var.boot_disk_image
    boot_disk_size_gb     = var.boot_disk_size_gb
    boot_disk_type        = var.boot_disk_type
    can_ip_forward        = var.can_ip_forward
    metadata              = var.metadata
    host_platform         = lookup(var.labels, "sandbox_platform", "unspecified")
    reservation_name      = var.reservation_name
  }
}
