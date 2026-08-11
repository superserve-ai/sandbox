terraform {
  required_version = ">= 1.5.0"
}

resource "google_monitoring_dashboard" "dashboards" {
  for_each = var.dashboards

  project        = var.project_id
  dashboard_json = each.value.definition
}

resource "google_monitoring_alert_policy" "compute_instance_cpu" {
  for_each = var.compute_instance_cpu_alerts

  project               = var.project_id
  display_name          = each.value.display_name
  combiner              = "OR"
  enabled               = true
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel when CPU alerts are configured"
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
    precondition {
      condition     = each.value.threshold > 0 && each.value.threshold <= 1
      error_message = "CPU alert thresholds must be greater than 0 and no greater than 1"
    }
  }

  conditions {
    display_name = "${each.value.instance_name} CPU utilization"

    condition_threshold {
      filter          = "resource.type = \"gce_instance\" AND resource.labels.instance_id = \"${each.value.instance_id}\" AND metric.type = \"compute.googleapis.com/instance/cpu/utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = each.value.threshold
      duration        = each.value.evaluation_duration

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  alert_strategy {
    # notification_rate_limit is only valid on log-based alert policies; this is
    # a metric-threshold policy, so GCP rejects it (Error 400: "only log-based
    # alert policies may specify a notification rate limit"). auto_close is valid
    # for metric policies and is kept.
    auto_close = "1800s"
  }

  documentation {
    content = coalesce(each.value.documentation, <<-EOT
      Sustained CPU utilization above ${format("%.0f", each.value.threshold * 100)}% was observed on ${each.value.instance_name} for ${each.value.evaluation_duration}.

      Owner: Infrastructure Operations. Response: confirm host saturation in Cloud Monitoring, inspect running sandbox workload and host services, and scale or drain the host when capacity remains constrained. Record the incident and link the remediation before closing the alert.
    EOT
    )
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type    = "compute_cpu_saturation"
    instance_name = each.value.instance_name
    managed_by    = "terraform"
  })
}

locals {
  observability_contract = {
    project_id                  = var.project_id
    environment                 = var.environment
    notification_email          = var.notification_email
    notification_channel_ids    = var.notification_channel_ids
    compute_instance_cpu_alerts = var.compute_instance_cpu_alerts
    log_buckets                 = var.log_buckets
    uptime_checks               = var.uptime_checks
    alert_policies              = var.alert_policies
    dashboards                  = var.dashboards
    labels                      = var.labels
  }
}

resource "google_monitoring_alert_policy" "sandbox_failures" {
  for_each = var.sandbox_failure_alerts

  project               = var.project_id
  display_name          = each.value.display_name
  combiner              = "OR"
  enabled               = true
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel when sandbox failure alerts are configured"
    }
    precondition {
      condition     = each.value.threshold > 0
      error_message = "Sandbox failure alert thresholds must be greater than 0"
    }
  }

  conditions {
    display_name = "Failed sandbox transitions"

    condition_prometheus_query_language {
      query = <<-EOT
        sum(increase(sandbox_transition_total{environment="${var.environment}",operation="fail",result="success"}[${each.value.lookback}])) > ${each.value.threshold}
      EOT

      duration            = each.value.evaluation_duration
      evaluation_interval = "60s"
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = coalesce(each.value.documentation, <<-EOT
      More than ${each.value.threshold} sandboxes were successfully transitioned into the terminal failed state during the preceding ${each.value.lookback} in ${var.environment}.

      This is distinct from lifecycle API errors: the failure transition itself is recorded with operation="fail", result="success". Inspect the Sandbox Telemetry Operations dashboard, then correlate the affected host and VMD logs.
    EOT
    )
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "sandbox_failed_transitions"
    managed_by = "terraform"
  })
}
