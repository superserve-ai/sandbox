terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }
}

locals {
  config_path       = "/etc/google-cloud-ops-agent/config.yaml"
  candidate_config_path = "/var/lib/superserve/host-logging/config.yaml.candidate"
  journald_dropin   = "/etc/systemd/journald.conf.d/30-superserve-host-logging.conf"
  journald_candidate_path = "/var/lib/superserve/host-logging/journald.conf.candidate"
  reconciliation_id = "${var.assignment_name}-${var.assignment_revision}"
  host_units = distinct(flatten([
    for host in values(var.enrolled_hosts) : concat(
      ["superserve-vmd.service", "systemd.service", "systemd-journald.service", "systemd-logind.service", "google-osconfig-agent.service", "google-guest-agent.service", "google-cloud-ops-agent.service", "superserve-otel-collector.service", "unbound.service", "secretsproxy.service", "superserve-secretsproxy.service", "superserve-host-logging-heartbeat.service", "proxy-*.service", "proxy-generation@.service"],
      host.proxy_units,
    )
  ]))
  ops_agent_config = templatefile("${path.module}/templates/ops-agent.yaml.tftpl", {
    environment       = var.environment
    region            = var.region
    assignment_name   = var.assignment_name
    assignment_revision = var.assignment_revision
    host_units        = local.host_units
    enrolled_hosts    = var.enrolled_hosts
    ops_agent_package_version = var.ops_agent_package_version
  })
  reconcile_script = templatefile("${path.module}/templates/reconcile.sh.tftpl", {
    config_path             = local.config_path
    candidate_config_path   = local.candidate_config_path
    journald_dropin         = local.journald_dropin
    journald_candidate_path = local.journald_candidate_path
    ops_agent_config        = local.ops_agent_config
    journal_max_use_bytes   = var.journal_max_use_bytes
    journal_keep_free_bytes = var.journal_keep_free_bytes
    agent_memory_limit_mb   = var.agent_memory_limit_mb
    agent_cpu_limit_millicores = var.agent_cpu_limit_millicores
    agent_buffer_bytes      = var.agent_buffer_bytes
    agent_self_log_max_bytes = var.agent_self_log_max_bytes
    syslog_max_bytes        = var.syslog_max_bytes
    storage_scan_timeout_seconds = var.storage_scan_timeout_seconds
    storage_scan_max_entries = var.storage_scan_max_entries
    package_operation_timeout_seconds = var.package_operation_timeout_seconds
    heartbeat_interval_seconds = var.heartbeat_interval_seconds
    ops_agent_package_version = var.ops_agent_package_version
  })
  validate_script = templatefile("${path.module}/templates/validate.sh.tftpl", {
    candidate_config_path     = local.candidate_config_path
    journald_candidate_path   = local.journald_candidate_path
    journal_max_use_bytes     = var.journal_max_use_bytes
    journal_keep_free_bytes   = var.journal_keep_free_bytes
    agent_cpu_limit_millicores = var.agent_cpu_limit_millicores
    agent_memory_limit_mb     = var.agent_memory_limit_mb
    ops_agent_package_version = var.ops_agent_package_version
    agent_buffer_bytes        = var.agent_buffer_bytes
    agent_self_log_max_bytes = var.agent_self_log_max_bytes
    syslog_max_bytes        = var.syslog_max_bytes
    storage_scan_timeout_seconds = var.storage_scan_timeout_seconds
    storage_scan_max_entries = var.storage_scan_max_entries
    package_operation_timeout_seconds = var.package_operation_timeout_seconds
    heartbeat_interval_seconds = var.heartbeat_interval_seconds
  })
}

# The assignment is the single Terraform owner for installation and runtime
# configuration. Existing zonal assignments are adopted with imports in each
# environment root; no second automatic installer is created.
resource "google_os_config_os_policy_assignment" "host_logging" {
  project  = var.project_id
  location = var.zone
  name     = var.assignment_name

  instance_filter {
    all = false

    inclusion_labels {
      labels = var.selector_labels
    }
  }

  os_policies {
    id   = "superserve-host-logging"
    mode = "ENFORCEMENT"

    resource_groups {
      inventory_filters {
        # All managed serving images are Ubuntu 22.04/24.04.  Keeping the
        # filter aligned with the image family is required for the assignment
        # to converge on both existing and replacement hosts.
        os_short_name = "ubuntu"
      }

      # Package installation is intentionally owned by reconcile.sh after the
      # selected artifact and candidate configuration pass diagnosis. An
      # independent apt resource would mutate the active package before that
      # transaction can capture rollback state.
      resources {
        id = "ops-agent-config"
        file {
          desired_state = "PRESENT"
          file {
            # OS Config writes a candidate outside the active path. The
            # reconciliation exec validates it and atomically activates it.
            path        = local.candidate_config_path
            gcs {
              bucket     = google_storage_bucket.host_logging_artifacts.name
              object     = google_storage_bucket_object.ops_agent_config.name
              generation = tostring(google_storage_bucket_object.ops_agent_config.generation)
            }
            permissions = "0644"
          }
        }
      }

      resources {
        id = "journald-retention"
        file {
          desired_state = "PRESENT"
          file {
            # Reconciliation owns activation and previous-state capture. OS
            # Config must never overwrite the live drop-in before validation.
            path        = local.journald_candidate_path
            content     = <<-EOT
              [Journal]
              Storage=persistent
              SystemMaxUse=${var.journal_max_use_bytes}B
              SystemKeepFree=${var.journal_keep_free_bytes}B
              EOT
            permissions = "0644"
          }
        }
      }

      resources {
        id = "validate-script"
        file {
          desired_state = "PRESENT"
          file {
            path = "/var/lib/superserve/host-logging/validate.sh"
            gcs {
              bucket     = google_storage_bucket.host_logging_artifacts.name
              object     = google_storage_bucket_object.validate_script.name
              generation = tostring(google_storage_bucket_object.validate_script.generation)
            }
            permissions = "0755"
          }
        }
      }

      resources {
        id = "reconcile-script"
        file {
          desired_state = "PRESENT"
          file {
            path = "/var/lib/superserve/host-logging/reconcile.sh"
            gcs {
              bucket     = google_storage_bucket.host_logging_artifacts.name
              object     = google_storage_bucket_object.reconcile_script.name
              generation = tostring(google_storage_bucket_object.reconcile_script.generation)
            }
            permissions = "0755"
          }
        }
      }

      resources {
        id = "reconcile-and-validate"
        exec {
          validate {
            interpreter = "SHELL"
            file {
              local_path = "/var/lib/superserve/host-logging/validate.sh"
            }
          }
          enforce {
            interpreter = "SHELL"
            file {
              local_path = "/var/lib/superserve/host-logging/reconcile.sh"
            }
          }
        }
      }
    }
  }

  rollout {
    disruption_budget {
      fixed = 1
    }
    min_wait_duration = "60s"
    mode              = "ZONE"
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = var.journal_max_use_bytes + var.agent_buffer_bytes + var.agent_self_log_max_bytes + var.syslog_max_bytes <= var.journal_keep_free_bytes
      error_message = "Combined journal, conservative Ops Agent buffer reservation, self-log, and syslog budgets must fit within the host free-space reserve; the reservation is accounting evidence, not an asserted Ops Agent cap."
    }
  }

  depends_on = [google_storage_bucket_iam_member.artifact_reader]
}

# The Ops Agent writes through the host's attached runtime identity. Keep this
# grant narrow and derive it from the same descriptors used by the assignment.
resource "google_project_iam_member" "log_writer" {
  for_each = toset([
    for host in values(var.enrolled_hosts) : host.service_account_email
  ])

  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${each.value}"
}

resource "google_storage_bucket" "host_logging_artifacts" {
  project                     = var.project_id
  name                        = "superserve-host-logging-${var.environment}-${replace(var.region, "-", "")}"
  location                    = var.region
  uniform_bucket_level_access = true

  versioning { enabled = true }

  lifecycle { prevent_destroy = true }
}

resource "google_storage_bucket_object" "ops_agent_config" {
  bucket  = google_storage_bucket.host_logging_artifacts.name
  name    = "${var.assignment_name}/${var.assignment_revision}/config.yaml"
  content = local.ops_agent_config
}

resource "google_storage_bucket_object" "reconcile_script" {
  bucket  = google_storage_bucket.host_logging_artifacts.name
  name    = "${var.assignment_name}/${var.assignment_revision}/reconcile.sh"
  content = local.reconcile_script
}

resource "google_storage_bucket_object" "validate_script" {
  bucket  = google_storage_bucket.host_logging_artifacts.name
  name    = "${var.assignment_name}/${var.assignment_revision}/validate.sh"
  content = local.validate_script
}

resource "google_storage_bucket_iam_member" "artifact_reader" {
  for_each = toset([
    for host in values(var.enrolled_hosts) : host.service_account_email
  ])

  bucket = google_storage_bucket.host_logging_artifacts.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${each.value}"
}

output "assignment_name" {
  value = google_os_config_os_policy_assignment.host_logging.name
}

output "configuration_revision" {
  value = var.assignment_revision
}

output "runtime_identities" {
  value = sort(distinct([
    for host in values(var.enrolled_hosts) : host.service_account_email
  ]))
}
