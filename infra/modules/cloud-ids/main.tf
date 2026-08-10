terraform {
  required_version = ">= 1.5.0"
}

moved {
  from = google_monitoring_alert_policy.ids_threats
  to   = google_monitoring_alert_policy.ids_high_critical
}

locals {
  ids_log_filter = <<-EOT
    log_id("ids.googleapis.com/threat")
    AND resource.type="ids.googleapis.com/Endpoint"
    AND resource.labels.id="${var.endpoint_name}"
  EOT

  ids_label_extractors = {
    ids_severity           = "EXTRACT(jsonPayload.alert_severity)"
    threat_name            = "EXTRACT(jsonPayload.name)"
    threat_id              = "EXTRACT(jsonPayload.threat_id)"
    uri_or_filename        = "EXTRACT(jsonPayload.uri_or_filename)"
    source_ip_address      = "EXTRACT(jsonPayload.source_ip_address)"
    destination_ip_address = "EXTRACT(jsonPayload.destination_ip_address)"
    destination_port       = "EXTRACT(jsonPayload.destination_port)"
  }

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

resource "google_monitoring_alert_policy" "ids_medium" {
  project               = var.project_id
  display_name          = "Security / ${var.endpoint_name} / Cloud IDS MEDIUM threats"
  combiner              = "OR"
  enabled               = true
  severity              = "ERROR"
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel for Cloud IDS MEDIUM alerts"
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
    display_name = "${var.endpoint_name} MEDIUM threat log"

    condition_matched_log {
      filter           = "${local.ids_log_filter}\nAND jsonPayload.alert_severity=\"MEDIUM\""
      label_extractors = local.ids_label_extractors
    }
  }

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "1800s"
  }

  documentation {
    subject   = "Cloud IDS MEDIUM: $${log.extracted_label.ids_severity} $${log.extracted_label.threat_name}"
    content   = <<-EOT
      Cloud IDS reported a MEDIUM threat on ${var.endpoint_name}.

      IDS severity: $${log.extracted_label.ids_severity}
      Threat name: $${log.extracted_label.threat_name}
      Threat ID: $${log.extracted_label.threat_id}
      Source IP: $${log.extracted_label.source_ip_address}
      Destination IP: $${log.extracted_label.destination_ip_address}
      Destination port: $${log.extracted_label.destination_port}
      URI or filename: $${log.extracted_label.uri_or_filename}

      This policy routes MEDIUM findings with an error-severity incident so responders can triage them separately from LOW findings.
    EOT
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "cloud_ids_threat_activity"
    endpoint   = var.endpoint_name
    managed_by = "terraform"
    severity   = "medium"
  })
}

resource "google_monitoring_alert_policy" "ids_high_critical" {
  project               = var.project_id
  display_name          = "Security / ${var.endpoint_name} / Cloud IDS HIGH and CRITICAL threats"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel for Cloud IDS HIGH and CRITICAL alerts"
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
    display_name = "${var.endpoint_name} HIGH and CRITICAL threat log"

    condition_matched_log {
      filter           = <<-EOT
        ${local.ids_log_filter}
        AND (
          jsonPayload.alert_severity="HIGH"
          OR jsonPayload.alert_severity="CRITICAL"
        )
      EOT
      label_extractors = local.ids_label_extractors
    }
  }

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "1800s"
  }

  documentation {
    subject   = "Cloud IDS HIGH/CRITICAL: $${log.extracted_label.ids_severity} $${log.extracted_label.threat_name}"
    content   = <<-EOT
      Cloud IDS reported a HIGH or CRITICAL threat on ${var.endpoint_name}.

      IDS severity: $${log.extracted_label.ids_severity}
      Threat name: $${log.extracted_label.threat_name}
      Threat ID: $${log.extracted_label.threat_id}
      Source IP: $${log.extracted_label.source_ip_address}
      Destination IP: $${log.extracted_label.destination_ip_address}
      Destination port: $${log.extracted_label.destination_port}
      URI or filename: $${log.extracted_label.uri_or_filename}

      This policy keeps the highest-severity findings on the immediate response path.
    EOT
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "cloud_ids_threat_activity"
    endpoint   = var.endpoint_name
    managed_by = "terraform"
    severity   = "high_critical"
  })
}
