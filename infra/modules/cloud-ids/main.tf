terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

moved {
  from = google_monitoring_alert_policy.ids_threats
  to   = google_monitoring_alert_policy.ids_high_critical
}

moved {
  from = google_monitoring_alert_policy.ids_high_critical
  to   = google_monitoring_alert_policy.ids_triage
}

locals {
  # Keep full destinations out of routine plan output; Notion controls access.
  runbook_urls = sensitive({
    for role, id in var.runbook_ids : role => "${replace(var.runbook_base_url, "/[/]+$/", "")}/${id}"
  })

  ids_log_filter = <<-EOT
    log_id("ids.googleapis.com/threat")
    AND resource.type="ids.googleapis.com/Endpoint"
    AND resource.labels.id="${var.endpoint_name}"
  EOT

  # Every extracted label contributes to incident identity. Keep variable
  # evidence in raw logs so it cannot split a related burst into new timelines.
  ids_label_extractors = {
    threat_name       = "EXTRACT(jsonPayload.name)"
    threat_id         = "EXTRACT(jsonPayload.threat_id)"
    source_ip_address = "EXTRACT(jsonPayload.source_ip_address)"
  }

  ids_logs_url = "https://console.cloud.google.com/logs/query;query=${urlencode(local.ids_log_filter)};duration=PT1H?project=${urlencode(var.project_id)}"
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

resource "google_monitoring_alert_policy" "ids_triage" {
  project               = var.project_id
  display_name          = "Security / ${var.endpoint_name} / Cloud IDS security triage"
  combiner              = "OR"
  enabled               = true
  severity              = "WARNING"
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel for Cloud IDS triage alerts"
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
    display_name = "${var.endpoint_name} triage threat log"

    condition_matched_log {
      filter           = <<-EOT
        ${local.ids_log_filter}
        AND (
          jsonPayload.alert_severity="MEDIUM"
          OR jsonPayload.alert_severity="HIGH"
          OR jsonPayload.alert_severity="CRITICAL"
        )
      EOT
      label_extractors = local.ids_label_extractors
    }
  }

  alert_strategy {
    # This limit applies to the whole policy, including unrelated activities.
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "1800s"
  }

  documentation {
    subject   = "Cloud IDS triage: $${log.extracted_label.threat_name}"
    content   = <<-EOT
      Routine security/abuse triage on ${var.endpoint_name} (${var.region}).
      Superserve urgency: WARNING; no page or immediate escalation based on IDS severity alone.
      Upstream IDS severity: MEDIUM/HIGH/CRITICAL evidence; inspect each finding's value in the linked raw logs.
      The on-call responder owns triage in #on-call through the normal workflow; no new response SLA.

      Threat name: $${log.extracted_label.threat_name}
      Threat ID: $${log.extracted_label.threat_id}
      Observed source IP: $${log.extracted_label.source_ip_address}
      Traffic direction: unknown (inbound/outbound/internal is not established).
      Sandbox/team attribution: unknown; host/platform origin is also unproven.

      [Investigate raw IDS findings in Logs Explorer](${local.ids_logs_url}).
      The link opens the last hour; for delayed triage, set an absolute time range around the incident event time.
      Filter by the threat ID/name and observed source above. Inspect IDS severity, destination IP/port,
      URI/filename, and protocol direction in the matching raw entries. Client/server direction does not establish inbound/outbound.
      Correlate the event timestamp and both addresses/ports with available network and host logs, then
      event-time sandbox lifecycle records to establish sandbox/team ownership. A translated IP or current
      host mapping alone is insufficient; keep attribution unknown when historical evidence is missing.

      Notifications share a five-minute policy-wide rate limit across all threats, sources, and IDS severities.
      A finding can suppress notifications for unrelated activity during that interval; extracted labels
      do not provide independent notification limits. Inactive incidents auto-close after 30 minutes.
      Changing destinations, filenames, URIs, or detector severity does not create separate activity labels.
      Unrelated activity sharing a signature and translated source can share a timeline;
      policy-wide quotas also limit notifications for distinct activity. Raw findings remain queryable.
      Unknown attribution is not evidence of safety. If independent evidence shows platform compromise,
      customer impact, or another immediate security impact, manually contact the on-call responder and
      open a separate urgent incident with that evidence; do not wait for this routine policy's suppression window.
      Use the existing on-call incident-response process for manual escalation.
      Runbook: ${local.runbook_urls.investigation}
      Correlation: [Correlate an IDS finding with VMD proxy activity](${local.runbook_urls.correlation})
      Containment: [Contain and remove an abusive sandbox team](${local.runbook_urls.containment})
      Any older runbook instruction to escalate on detector severity alone is superseded by this triage policy.
    EOT
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    superserve_family         = "cloud_ids"
    superserve_component      = "vmd"
    superserve_failure_family = "security_finding"
    alert_type                = "cloud_ids_threat_activity"
    endpoint                  = var.endpoint_name
    managed_by                = "terraform"
    severity                  = "triage"
  })
}

# Keep the retired address until all regions have migrated. Ordering the disable
# after triage expansion avoids deleting MEDIUM coverage before its replacement.
resource "google_monitoring_alert_policy" "ids_medium" {
  depends_on = [google_monitoring_alert_policy.ids_triage]

  project               = var.project_id
  display_name          = "Security / ${var.endpoint_name} / Cloud IDS MEDIUM (retired)"
  combiner              = "OR"
  enabled               = false
  severity              = "WARNING"
  notification_channels = var.notification_channel_ids

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
    content   = google_monitoring_alert_policy.ids_triage.documentation[0].content
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    superserve_family         = "cloud_ids"
    superserve_component      = "vmd"
    superserve_failure_family = "security_finding"
    alert_type                = "cloud_ids_threat_activity"
    endpoint                  = var.endpoint_name
    managed_by                = "terraform"
    severity                  = "triage"
  })
}
