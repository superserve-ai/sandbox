terraform {
  required_version = ">= 1.5.0"
}

resource "google_cloud_ids_endpoint" "this" {
  project     = var.project_id
  name        = var.endpoint_name
  network     = var.network_self_link
  location    = var.zone
  severity    = var.endpoint_severity
  description = var.endpoint_description
}

resource "google_compute_packet_mirroring" "this" {
  project = var.project_id
  region  = var.region
  name    = "${var.endpoint_name}-mirror"

  network {
    url = var.network_self_link
  }

  collector_ilb {
    url = google_cloud_ids_endpoint.this.endpoint_forwarding_rule
  }

  mirrored_resources {
    dynamic "subnetworks" {
      for_each = var.mirrored_subnet_self_links

      content {
        url = subnetworks.value
      }
    }
  }
}

resource "google_monitoring_alert_policy" "ids_threats" {
  project               = var.project_id
  display_name          = "Security / ${var.endpoint_name} / Cloud IDS threats"
  combiner              = "OR"
  enabled               = true
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel for Cloud IDS alerts"
    }
    precondition {
      condition = alltrue([
        for channel_id in var.notification_channel_ids : can(regex(
          "^projects/${var.project_id}/notificationChannels/[0-9]+$",
          channel_id
        ))
      ])
      error_message = "notification_channel_ids must reference monitored channels in the configured project using full resource names"
    }
  }

  conditions {
    display_name = "${var.endpoint_name} threat log"

    condition_matched_log {
      filter = <<-EOT
        log_id("ids.googleapis.com/threat")
        AND resource.type="ids.googleapis.com/Endpoint"
        AND resource.labels.id="${var.endpoint_name}"
        AND jsonPayload.alert_severity!="INFORMATIONAL"
      EOT
    }
  }

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "1800s"
  }

  documentation {
    content   = <<-EOT
      Cloud IDS reported a threat on ${var.endpoint_name}.

      Owner: Infrastructure Operations. Response: review the threat log in Cloud Logging, inspect the mirrored source and destination traffic, confirm whether the finding is expected, and record the remediation or suppression decision before closing the incident.
    EOT
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "cloud_ids_threat_activity"
    endpoint   = var.endpoint_name
    managed_by = "terraform"
  })
}
