locals {
  host_logging_alerts_enabled = var.host_logging_alerts != null
}

resource "google_monitoring_alert_policy" "host_logging_export_failures" {
  for_each = local.host_logging_alerts_enabled ? var.host_logging_alerts.expected_hosts : {}

  project               = var.project_id
  display_name          = "${var.host_logging_alerts.display_prefix} / ${each.value.instance_name} / export failure"
  combiner              = "OR"
  enabled               = true
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = contains(keys(var.runbook_urls), "host_logging_export")
      error_message = "Missing host_logging_export runbook URL."
    }
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must be configured for host logging alerts."
    }
  }

  conditions {
    display_name = "Ops Agent export errors on ${each.value.instance_name}"
    condition_matched_log {
      filter = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND log_id(\"google-cloud-ops-agent\") AND severity>=ERROR"
    }
  }

  alert_strategy {
    notification_rate_limit { period = "300s" }
    auto_close = "1800s"
  }

  documentation {
    content   = "Ops Agent reported an export error on ${each.value.instance_name}. Check agent health, Cloud Logging permissions, network egress, and retained journal/buffer growth before restarting anything.\n\nRunbook: ${lookup(var.runbook_urls, "host_logging_export", "")}"
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    superserve_family         = "host_logging"
    superserve_component      = "host"
    superserve_failure_family = "export_failure"
    alert_type                = "host_logging_export_failure"
    instance_name             = each.value.instance_name
    managed_by                = "terraform"
  })
}

resource "google_monitoring_alert_policy" "host_logging_lag" {
  for_each = local.host_logging_alerts_enabled ? var.host_logging_alerts.expected_hosts : {}

  project               = var.project_id
  display_name          = "${var.host_logging_alerts.display_prefix} / ${each.value.instance_name} / delivery lag"
  combiner              = "OR"
  enabled               = true
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = contains(keys(var.runbook_urls), "host_logging_lag")
      error_message = "Missing host_logging_lag runbook URL."
    }
  }

  conditions {
    display_name = "Ops Agent delivery lag on ${each.value.instance_name}"
    condition_matched_log {
      filter = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND jsonPayload.host_logging_lag_seconds>${var.host_logging_alerts.lag_threshold_seconds}"
    }
  }

  alert_strategy {
    notification_rate_limit { period = "900s" }
    auto_close = "3600s"
  }

  documentation {
    content   = "Retained host logs are arriving later than the configured ${var.host_logging_alerts.lag_threshold_seconds}s threshold on ${each.value.instance_name}. Distinguish outage catch-up from a persistent gap and account for journal/buffer expiry.\n\nRunbook: ${lookup(var.runbook_urls, "host_logging_lag", "")}"
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    superserve_family         = "host_logging"
    superserve_component      = "host"
    superserve_failure_family = "delivery_lag"
    alert_type                = "host_logging_delivery_lag"
    instance_name             = each.value.instance_name
    managed_by                = "terraform"
  })
}

# Compute Engine uptime is independent of the Ops Agent/export path. A broken
# exporter therefore cannot make this absence signal appear healthy.
resource "google_monitoring_alert_policy" "host_logging_heartbeat" {
  for_each = local.host_logging_alerts_enabled ? var.host_logging_alerts.expected_hosts : {}

  project               = var.project_id
  display_name          = "${var.host_logging_alerts.display_prefix} / ${each.value.instance_name} / missing heartbeat"
  combiner              = "OR"
  enabled               = true
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = contains(keys(var.runbook_urls), "host_logging_heartbeat")
      error_message = "Missing host_logging_heartbeat runbook URL."
    }
  }

  conditions {
    display_name = "Serving host heartbeat absent on ${each.value.instance_name}"
    condition_absent {
      filter   = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND metric.type=\"compute.googleapis.com/instance/uptime\""
      duration = var.host_logging_alerts.heartbeat_duration
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  documentation {
    content   = "The independent Compute Engine uptime signal for ${each.value.instance_name} was absent. This is evaluated separately from Ops Agent log delivery, so it can expose a never-seen or stopped host.\n\nRunbook: ${lookup(var.runbook_urls, "host_logging_heartbeat", "")}"
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    superserve_family         = "host_logging"
    superserve_component      = "host"
    superserve_failure_family = "missing_telemetry"
    alert_type                = "host_logging_heartbeat_absent"
    instance_name             = each.value.instance_name
    managed_by                = "terraform"
  })
}
