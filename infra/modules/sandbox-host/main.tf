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
  desired_status            = var.desired_status
  tags                      = var.tags
  labels                    = local.instance_labels

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

    dynamic "access_config" {
      for_each = var.external_ip ? [1] : []
      content {}
    }
  }

  # Prepend the host patching policy to whatever startup script the
  # environment provides (or install it alone when none is given), so every
  # provisioned host is covered from first boot. `ignore_changes = [metadata]`
  # below means this applies at instance creation only — running hosts pick
  # the same policy up from the vmd deploy step instead.
  metadata = merge(
    var.metadata,
    var.provisioning_run_id != "" ? { host-provisioning-run = var.provisioning_run_id } : {},
    {
      user-data = "#cloud-config\n${yamlencode(merge(local.host_cloud_config, {
        bootcmd = concat([local.host_identity_prerequisite], var.provisioning ? [local.host_provisioning_hold] : [], [for command in local.host_boot_commands : yamldecode(command)])
      }))}"
      startup-script = trimspace(join("\n\n", compact([
        local.host_patching_policy,
        var.provisioning ? local.host_provisioning_hold : "",
        var.provisioning ? "if [ -f /etc/sandbox/provisioning-complete ]; then\n:\n${lookup(var.metadata, "startup-script", ":")}\nfi" : lookup(var.metadata, "startup-script", ""),
      ])))
    },
  )

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
      # Persistent disks attached out-of-band (e.g. the staging
      # superserve-sandbox-data disk) are managed outside this module, like
      # scratch disks: a plan must never detach a live disk it didn't create.
      attached_disk,
      boot_disk,
      metadata,
      network_interface[0].access_config,
      scheduling,
      scratch_disk,
    ]
  }
}

locals {
  host_provisioning_hold = <<-EOT
    set -eu
    mkdir -p /etc/sandbox
    # Creation metadata persists after explicit runtime initialization.
    if [ ! -f /etc/sandbox/provisioning-complete ]; then
      touch /etc/sandbox/provisioning-hold
      for unit in superserve-vmd.service superserve-vmd.socket; do
        mkdir -p "/etc/systemd/system/$unit.d"
        printf '[Unit]\nConditionPathExists=!/etc/sandbox/provisioning-hold\n' > "/etc/systemd/system/$unit.d/05-provisioning-hold.conf"
      done
      systemctl daemon-reload
      systemctl stop superserve-vmd.socket superserve-vmd.service || true
    fi
  EOT

  # Images must already contain the identity-gated units and fencing-aware VMD.
  # Reassert the gate before caller boot commands; bootcmd can race socket activation.
  host_cloud_config = yamldecode(lookup(var.metadata, "user-data", "{}"))

  host_boot_commands = [for command in try(local.host_cloud_config.bootcmd, []) :
    var.provisioning ? yamlencode(concat(
      ["sh", "-c", "if [ -f /etc/sandbox/provisioning-complete ]; then exec \"$@\"; fi", "provisioning-boot"],
      try(tolist(command), ["sh", "-c", tostring(command)])
    )) : yamlencode(command)
  ]

  host_identity_prerequisite = <<-EOT
    set -eu
    # Preserve normal boot activation once installed; VMD validates the identity.
    if [ ! -s /etc/sandbox/host-identity.json ] || [ ! -s /etc/sandbox/host-identity.env ]; then
      for unit in superserve-vmd.socket superserve-vmd.service; do
        if systemctl cat "$unit" >/dev/null 2>&1; then
          systemctl stop "$unit"
        fi
      done
    fi
    mkdir -p /etc/systemd/system/superserve-vmd.service.d /etc/systemd/system/superserve-vmd.socket.d
    cat > /etc/systemd/system/superserve-vmd.socket.d/10-identity-required.conf <<'IDENTITY'
    [Unit]
    ConditionPathExists=/etc/sandbox/host-identity.json
    ConditionPathExists=/etc/sandbox/host-identity.env
    IDENTITY
    cat > /etc/systemd/system/superserve-vmd.service.d/10-identity-required.conf <<'IDENTITY'
    [Service]
    Environment=HOST_IDENTITY_REQUIRED=1
    ExecStartPre=/usr/bin/test -s /etc/sandbox/host-identity.json
    EnvironmentFile=/etc/sandbox/host-identity.env
    IDENTITY
    systemctl daemon-reload
  EOT

  # Host patching policy: no automatic OS upgrades, and library-upgrade
  # tooling must never restart the VM or platform units — a restarted
  # firecracker unit is a destroyed customer VM. Mirrors the deploy assets
  # (deploy/needrestart-superserve.conf, deploy/apt-no-auto-upgrades.conf)
  # that every vmd deploy re-asserts.
  host_patching_policy = <<-EOT
    #!/bin/bash
    mkdir -p /etc/needrestart/conf.d
    cat > /etc/needrestart/conf.d/50-superserve.conf <<'NRCONF'
    $nrconf{override_rc}{qr(^firecracker)} = 0;
    $nrconf{override_rc}{qr(^superserve-)} = 0;
    $nrconf{override_rc}{qr(^proxy\.service$)} = 0;
    $nrconf{override_rc}{qr(^unbound)} = 0;
    NRCONF
    cat > /etc/apt/apt.conf.d/99superserve-no-auto-upgrades <<'APTCONF'
    APT::Periodic::Update-Package-Lists "1";
    APT::Periodic::Unattended-Upgrade "0";
    APTCONF
    systemctl disable --now apt-daily-upgrade.timer 2>/dev/null || true
  EOT

  instance_labels = merge(
    var.labels,
    {
      environment = var.environment
      managed_by  = "terraform"
      region      = var.region
    },
    var.provisioning ? { component = "vmd-provisioning", sandbox_status = "provisioning" } : {},
  )

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
    labels                = local.instance_labels
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
