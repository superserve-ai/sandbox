locals {
  host_logging_alerts_enabled = var.host_logging_alerts != null
  active_host_logging_alerts = local.host_logging_alerts_enabled ? {
    for key, host in var.host_logging_alerts.expected_hosts : key => host
    if try(host.active, true)
  } : {}

}

# A host-generated minute heartbeat is converted to a logs-based metric. The
# metric point uses the journal entry timestamp, so replaying an old buffered
# entry cannot satisfy the current freshness window. Terraform's expected-host
# inventory scopes the metric to the current GCE instance ID. A replacement
# receives a new provider instance ID, which is the authoritative identity
# Terraform can know without guessing the UUID generated on the host.
resource "google_logging_metric" "host_logging_heartbeat" {
  for_each = local.active_host_logging_alerts

  project = var.project_id
  name    = "superserve_host_logging_heartbeat_${each.key}"
  filter  = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND log_id(\"superserve_host_logs\") AND labels.journal_unit=\"superserve-host-logging-heartbeat.service\" AND labels.host_logging_heartbeat=\"true\"${each.value.incarnation == null ? "" : " AND labels.incarnation=\"${each.value.incarnation}\""}"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "collector_host_id"
      value_type  = "STRING"
      description = "Stable VM identity for the active host incarnation."
    }
    labels {
      key         = "incarnation"
      value_type  = "STRING"
      description = "Expected serving-host incarnation from the trusted log payload."
    }
  }

  label_extractors = {
    # GCE's monitored resource provides instance_id, project_id, and zone; it
    # does not provide instance_name. Use the numeric instance identity for
    # producer, metric, inventory, and alert matching. Runtime host_id,
    # instance name, and incarnation remain separate log labels.
    collector_host_id = "EXTRACT(resource.labels.instance_id)"
    incarnation       = "EXTRACT(labels.incarnation)"
  }
}

resource "google_monitoring_alert_policy" "host_logging_export_failures" {
  for_each = local.active_host_logging_alerts

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
    display_name = "OTel logs export errors on ${each.value.instance_name}"
    condition_matched_log {
      filter = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND log_id(\"superserve_host_logs\") AND (labels.host_logging_export_error=\"true\" OR labels.message =~ \"(?i)(export failed|permission denied|\\bdrop\\b|\\bdropped\\b)\" OR textPayload =~ \"(?i)(export failed|permission denied|\\bdrop\\b|\\bdropped\\b)\")"
    }
  }

  alert_strategy {
    notification_rate_limit { period = "300s" }
    auto_close = "1800s"
  }

  documentation {
    content   = "The dedicated OTel logs collector reported an export error on ${each.value.instance_name}. Check collector health, Cloud Logging permissions, network egress, and retained journal/queue growth before restarting anything.\n\nRunbook: ${lookup(var.runbook_urls, "host_logging_export", "")}"
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
  for_each = local.active_host_logging_alerts

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

  # Delivery lag is sampled once per host heartbeat, bounding metric volume
  # independently of application log volume. It is intentionally independent from the heartbeat absence policy
  # below: an exporter that is stopped or has never emitted a heartbeat cannot
  # manufacture a lag sample, and is handled by the separate absence alert.
  conditions {
    display_name = "OTel logs delivery lag on ${each.value.instance_name}"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.host_logging_delivery_lag[each.key].name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.host_logging_alerts.lag_threshold_seconds
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_PERCENTILE_99"
      }
    }
  }



  documentation {
    content   = "Retained host logs are arriving later than the configured ${var.host_logging_alerts.lag_threshold_seconds}s threshold on ${each.value.instance_name}. Distinguish outage catch-up from a persistent gap and account for journal/queue expiry.\n\nRunbook: ${lookup(var.runbook_urls, "host_logging_lag", "")}"
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

resource "google_logging_metric" "host_logging_delivery_lag" {
  for_each = local.active_host_logging_alerts

  project         = var.project_id
  name            = "superserve_host_logging_delivery_lag_${each.key}"
  filter          = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND log_id(\"superserve_host_logs\") AND labels.journal_unit=\"superserve-host-logging-heartbeat.service\" AND labels.host_logging_heartbeat=\"true\" AND labels.host_logging_retained_history_lag_seconds:*"
  value_extractor = "EXTRACT(labels.host_logging_retained_history_lag_seconds)"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "DISTRIBUTION"
    unit        = "s"
  }
  bucket_options {
    exponential_buckets {
      num_finite_buckets = 20
      growth_factor      = 2
      scale              = 1
    }
  }
}

# This policy is driven by the logs-based heartbeat metric above, not the
# standalone metrics collector. Missing or never-seen log heartbeats therefore
# remain visible even while metrics continue to report healthy. The
# heartbeat_metric_type input is retained for configuration compatibility but
# is intentionally not used as the absence source.
resource "google_monitoring_alert_policy" "host_logging_heartbeat" {
  for_each = local.active_host_logging_alerts

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
    condition_prometheus_query_language {
      # The zero fallback covers never-seen series as well as present series
      # containing only zero-valued points. The provider instance
      # ID prevents a replacement VM from satisfying the predecessor's series;
      # the trusted incarnation remains available in the emitted record for
      # investigations and collision-resistant correlation.
      query                     = <<-EOT
        (sum(sum_over_time({
          "__name__" = "logging_googleapis_com:user_${google_logging_metric.host_logging_heartbeat[each.key].name}",
          "collector_host_id" = "${each.value.instance_id}"${each.value.incarnation == null ? "" : ",\n          \"incarnation\" = \"${each.value.incarnation}\""}
        }[5m])) or vector(0)) == 0
      EOT
      duration                  = var.host_logging_alerts.heartbeat_duration
      evaluation_interval       = "60s"
      disable_metric_validation = true
    }
  }

  documentation {
    content   = "The expected OTel host-log heartbeat for ${each.value.instance_name} was absent or stale. This signal is derived from Cloud Logging receipt and remains independent of the application-metrics collector.\n\nRunbook: ${lookup(var.runbook_urls, "host_logging_heartbeat", "")}"
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
