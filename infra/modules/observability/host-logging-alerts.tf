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
# inventory scopes the metric to the current instance incarnation; replacement
# and retirement therefore converge by changing/removing one map entry.
resource "google_logging_metric" "host_logging_heartbeat" {
  for_each = local.active_host_logging_alerts

  project = var.project_id
  name    = "superserve_host_logging_heartbeat_${each.key}"
  filter  = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND jsonPayload.host_logging_heartbeat=true"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "collector_host_id"
      value_type  = "STRING"
      description = "Stable VM identity for the active host incarnation."
    }
  }

  label_extractors = {
    # GCE's monitored resource provides instance_id, project_id, and zone; it
    # does not provide instance_name. Use the numeric instance identity for
    # producer, metric, inventory, and alert matching. Runtime host_id,
    # instance name, and incarnation remain separate log labels.
    collector_host_id = "EXTRACT(labels.instance_id)"
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
    display_name = "Ops Agent export errors on ${each.value.instance_name}"
    condition_matched_log {
      filter = "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"${each.value.instance_id}\" AND log_id(\"google-cloud-ops-agent\") AND (severity>=ERROR OR textPayload =~ \"(?i)(failed to flush chunk|exporting failed|permission denied)\" OR jsonPayload.MESSAGE =~ \"(?i)(failed to flush chunk|exporting failed|permission denied)\")"
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

  # Monitoring conditions are typed one-per-block.  Keep the retained-log
  # absence signal and the independent never-seen heartbeat threshold as
  # separate blocks so the provider can represent both valid condition types.
  conditions {
    display_name = "Ops Agent delivery lag on ${each.value.instance_name}"
    condition_absent {
      filter   = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.host_logging_heartbeat[each.key].name}\" AND metric.labels.collector_host_id=\"${each.value.instance_id}\""
      duration = format("%ds", var.host_logging_alerts.lag_threshold_seconds)
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  conditions {
    display_name = "No independent heartbeat for ${each.value.instance_name}"
    condition_threshold {
      # A threshold condition with missing-data-as-active covers a host that
      # has never emitted its first independent heartbeat series. Once the
      # series exists, only a positive current uptime satisfies it.
      filter                  = "metric.type=\"${var.host_logging_alerts.heartbeat_metric_type}\" AND metric.labels.collector_host_id=\"${coalesce(each.value.collector_host_id, each.value.instance_name)}\""
      comparison              = "COMPARISON_LT"
      threshold_value         = 1
      duration                = var.host_logging_alerts.heartbeat_duration
      evaluation_missing_data = "EVALUATION_MISSING_DATA_ACTIVE"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
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

# The standalone OTel collector's self metric is independent of the Ops
# Agent/export path. A broken exporter therefore cannot make this absence
# signal appear healthy.
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
    condition_absent {
      # GMP may use its prometheus_target monitored resource rather than a
      # GCE resource for this series, so scope by the stable metric label and
      # not by a resource type that would make never-seen hosts invisible.
      filter   = "metric.type=\"${var.host_logging_alerts.heartbeat_metric_type}\" AND metric.labels.collector_host_id=\"${coalesce(each.value.collector_host_id, each.value.instance_name)}\""
      duration = var.host_logging_alerts.heartbeat_duration
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  documentation {
    content   = "The standalone OTel collector heartbeat for ${each.value.instance_name} was absent. This metric is delivered on the existing application-metrics path, separately from Ops Agent log export, so a broken exporter cannot satisfy the expected-host signal.\n\nRunbook: ${lookup(var.runbook_urls, "host_logging_heartbeat", "")}"
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
