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
  state_dir              = "/var/lib/superserve/host-logging"
  candidate_config_path  = "${local.state_dir}/otel-logs.yaml.candidate"
  candidate_service_path = "${local.state_dir}/otel-logs.service.candidate"
  journald_dropin        = "/etc/systemd/journald.conf.d/30-superserve-host-logging.conf"
  journald_candidate     = "${local.state_dir}/journald.conf.candidate"
  cursor_dir             = "${local.state_dir}/cursor"
  queue_dir              = "${local.state_dir}/export-queue"

  host_units = distinct(flatten([
    for host in values(var.enrolled_hosts) : concat([
      "superserve-vmd.service",
      "systemd-journald.service",
      "systemd-logind.service",
      "google-osconfig-agent.service",
      "google-guest-agent.service",
      "superserve-otel-collector.service",
      "superserve-otel-logs.service",
      "unbound.service",
      "secretsproxy.service",
      "superserve-secretsproxy.service",
      "superserve-host-logging-heartbeat.service",
      "proxy.service",
      "proxy-generation.service",
      "proxy-*.service",
    ], host.proxy_units)
  ]))

  otel_config = templatefile("${path.module}/templates/otel-logs.yaml.tftpl", {
    environment         = var.environment
    region              = var.region
    assignment_name     = var.assignment_name
    assignment_revision = var.assignment_revision
    release_version     = var.otel_release_version
    host_units          = local.host_units
    cursor_dir          = local.cursor_dir
    queue_dir           = local.queue_dir
  })
  otel_service = templatefile("${path.module}/templates/otel-logs.service.tftpl", {
    binary_path     = var.otel_binary_path
    config_path     = "/etc/superserve/host-logging/otel-logs.yaml"
    cursor_dir      = local.cursor_dir
    queue_dir       = local.queue_dir
    queue_max_bytes = var.otel_queue_max_bytes
    memory_limit_mb = var.otel_memory_limit_mb
    cpu_limit       = var.otel_cpu_limit
  })
  reconcile_script = templatefile("${path.module}/templates/reconcile.sh.tftpl", {
    candidate_config_path             = local.candidate_config_path
    candidate_service_path            = local.candidate_service_path
    journald_dropin                   = local.journald_dropin
    journald_candidate_path           = local.journald_candidate
    state_dir                         = local.state_dir
    cursor_dir                        = local.cursor_dir
    queue_dir                         = local.queue_dir
    journal_max_use_bytes             = var.journal_max_use_bytes
    journal_keep_free_bytes           = var.journal_keep_free_bytes
    otel_config                       = local.otel_config
    otel_service                      = local.otel_service
    otel_release_version              = var.otel_release_version
    otel_release_url                  = var.otel_release_url
    otel_release_sha256               = var.otel_release_sha256
    otel_binary_path                  = var.otel_binary_path
    package_operation_timeout_seconds = var.package_operation_timeout_seconds
    heartbeat_interval_seconds        = var.heartbeat_interval_seconds
    otel_queue_max_bytes              = var.otel_queue_max_bytes
  })
  validate_script = templatefile("${path.module}/templates/validate.sh.tftpl", {
    candidate_config_path   = local.candidate_config_path
    journald_candidate_path = local.journald_candidate
    otel_release_version    = var.otel_release_version
    otel_binary_path        = var.otel_binary_path
    cursor_dir              = local.cursor_dir
    queue_dir               = local.queue_dir
    journal_max_use_bytes   = var.journal_max_use_bytes
    journal_keep_free_bytes = var.journal_keep_free_bytes
    otel_queue_max_bytes    = var.otel_queue_max_bytes
  })
}

# The dedicated log process has one Terraform/OS Config owner. It remains
# separate from the existing metrics collector and from any legacy policy
# retained during the controlled east migration.
resource "google_os_config_os_policy_assignment" "host_logging" {
  project  = var.project_id
  location = var.zone
  name     = var.assignment_name

  instance_filter {
    all = false
    inclusion_labels { labels = var.selector_labels }
  }

  os_policies {
    id   = "superserve-otel-host-logging"
    mode = "ENFORCEMENT"

    resource_groups {
      inventory_filters { os_short_name = "ubuntu" }

      resources {
        id = "otel-logs-config"
        file {
          state       = "PRESENT"
          path        = local.candidate_config_path
          permissions = "0644"
          file {
            gcs {
              bucket     = google_storage_bucket.host_logging_artifacts.name
              object     = google_storage_bucket_object.otel_config.name
              generation = tostring(google_storage_bucket_object.otel_config.generation)
            }
          }
        }
      }

      resources {
        id = "otel-logs-service"
        file {
          state       = "PRESENT"
          path        = local.candidate_service_path
          permissions = "0644"
          file {
            gcs {
              bucket     = google_storage_bucket.host_logging_artifacts.name
              object     = google_storage_bucket_object.otel_service.name
              generation = tostring(google_storage_bucket_object.otel_service.generation)
            }
          }
        }
      }

      resources {
        id = "journald-retention"
        file {
          state       = "CONTENTS_MATCH"
          path        = local.journald_candidate
          permissions = "0644"
          content     = <<-EOT
            [Journal]
            Storage=persistent
            SystemMaxUse=${var.journal_max_use_bytes}B
            SystemKeepFree=${var.journal_keep_free_bytes}B
            EOT
        }
      }

      resources {
        id = "validate-script"
        file {
          state       = "PRESENT"
          path        = "${local.state_dir}/validate.sh"
          permissions = "0755"
          file {
            gcs {
              bucket     = google_storage_bucket.host_logging_artifacts.name
              object     = google_storage_bucket_object.validate_script.name
              generation = tostring(google_storage_bucket_object.validate_script.generation)
            }
          }
        }
      }

      resources {
        id = "reconcile-script"
        file {
          state       = "PRESENT"
          path        = "${local.state_dir}/reconcile.sh"
          permissions = "0755"
          file {
            gcs {
              bucket     = google_storage_bucket.host_logging_artifacts.name
              object     = google_storage_bucket_object.reconcile_script.name
              generation = tostring(google_storage_bucket_object.reconcile_script.generation)
            }
          }
        }
      }

      resources {
        id = "reconcile-and-validate"
        exec {
          validate {
            interpreter = "SHELL"
            file { local_path = "${local.state_dir}/validate.sh" }
          }
          enforce {
            interpreter = "SHELL"
            file { local_path = "${local.state_dir}/reconcile.sh" }
          }
        }
      }
    }
  }

  rollout {
    disruption_budget { fixed = 1 }
    min_wait_duration = "60s"
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.legacy_policy_name == null || var.legacy_policy_name != var.assignment_name
      error_message = "The dedicated OTel assignment must not reuse the legacy policy identity."
    }
    precondition {
      condition     = var.journal_max_use_bytes > 0 && var.journal_keep_free_bytes > 0
      error_message = "Journald limits must be positive."
    }
  }

  depends_on = [google_storage_bucket_iam_member.artifact_reader]
}

resource "google_project_iam_member" "log_writer" {
  for_each = toset([for host in values(var.enrolled_hosts) : host.service_account_email])
  project  = var.project_id
  role     = "roles/logging.logWriter"
  member   = "serviceAccount:${each.value}"
}

resource "google_storage_bucket" "host_logging_artifacts" {
  project                     = var.project_id
  name                        = "superserve-host-logging-${var.environment}-${replace(var.region, "-", "")}"
  location                    = var.region
  uniform_bucket_level_access = true
  versioning { enabled = true }
  lifecycle { prevent_destroy = true }
}

resource "google_storage_bucket_object" "otel_config" {
  bucket  = google_storage_bucket.host_logging_artifacts.name
  name    = "${var.assignment_name}/${var.assignment_revision}/otel-logs.yaml"
  content = local.otel_config
}

resource "google_storage_bucket_object" "otel_service" {
  bucket  = google_storage_bucket.host_logging_artifacts.name
  name    = "${var.assignment_name}/${var.assignment_revision}/otel-logs.service"
  content = local.otel_service
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
  for_each = toset([for host in values(var.enrolled_hosts) : host.service_account_email])
  bucket   = google_storage_bucket.host_logging_artifacts.name
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${each.value}"
}

output "assignment_name" {
  value = google_os_config_os_policy_assignment.host_logging.name
}

output "legacy_transition" {
  value = var.legacy_transition
}
