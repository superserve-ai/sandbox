# Fleet-wide customer-visible lifecycle alerts. These use the control-plane
# phase histogram rather than the internal vmd phases: create/resume/pause/delete
# are what customers experience, while restore/launch/network remain drill-down
# signals for diagnosing an incident without producing duplicate pages.

resource "google_monitoring_alert_policy" "sandbox_lifecycle_latency" {
  for_each = var.lifecycle_latency_alerts

  project               = var.project_id
  display_name          = "Sandbox lifecycle / ${each.key} p${floor(each.value.quantile * 100)} latency above ${each.value.latency_seconds}s"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel when sandbox lifecycle alerts are configured"
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
    display_name = "${each.key} p${floor(each.value.quantile * 100)} > ${each.value.latency_seconds}s"

    condition_prometheus_query_language {
      query = <<-EOT
        histogram_quantile(
          ${each.value.quantile},
          sum by (le, host_id) (
            rate(
              sandbox_phase_duration_seconds_bucket{
                plane="controlplane",
                op="${each.key}",
                phase="total"
              }[5m]
            )
          )
        ) > ${each.value.latency_seconds}
      EOT

      # A single slow request should not page. The p33 must remain above the
      # operation's threshold for the full window.
      duration            = each.value.duration
      evaluation_interval = "60s"
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = <<-EOT
      Customer-visible sandbox ${each.key} latency is degraded: p${floor(each.value.quantile * 100)} end-to-end control-plane latency has remained above ${each.value.latency_seconds}s for ${each.value.duration}.

      The condition is grouped by host_id so a degraded cell/host cannot be hidden by healthy fleet traffic. Use the sandbox latency dashboard's internal vmd restore/launch/network phase panels to identify where the operation is spending time.

      Owner: Infrastructure Operations.
    EOT
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "sandbox_${each.key}_latency"
    severity   = "critical"
    managed_by = "terraform"
  })
}

# Any failed lifecycle transition matters today. The threshold is deliberately
# one event, not N failures in a five-minute period. The five-minute lookback
# keeps one incident open across a short burst (including repeated failures of
# the same sandbox) instead of paging once per failure.
resource "google_monitoring_alert_policy" "sandbox_failed" {
  count = var.failed_sandbox_alert_enabled ? 1 : 0

  project               = var.project_id
  display_name          = "Sandbox lifecycle / sandbox failure"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel when sandbox lifecycle alerts are configured"
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
    display_name = "Any failed sandbox transition in 5m"

    condition_prometheus_query_language {
      query = <<-EOT
        sum by (operation, result, region, host_id) (
          increase(
            sandbox_transition_total{
              result=~"error|timeout"
            }[5m]
          )
        ) > 0
      EOT

      # Fire on the first evaluation containing a failure. The range vector,
      # rather than a confirmation duration, intentionally keeps the condition
      # true for roughly five minutes after the most recent failure.
      duration            = "0s"
      evaluation_interval = "60s"
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = <<-EOT
      At least one sandbox lifecycle transition reported an error, timeout, or client_error during the last five minutes. Conflict results are intentionally excluded because they represent expected concurrency/idempotency behavior rather than an infrastructure failure. One failure is sufficient to open this incident; additional failures during the lookback intentionally remain part of the same fleet-wide incident.

      The condition is evaluated separately for each operation, result, region, and host_id combination. These bounded dimensions preserve the affected operation and cell in the alert while keeping the policy fleet-wide; us-central1 is only the static Terraform root that owns this shared policy, not a restriction on the metric regions it evaluates.

      Sandbox IDs are intentionally not metric labels. Use structured logs to identify the affected sandbox(es) and failure details without introducing unbounded Prometheus cardinality.

      Owner: Infrastructure Operations.
    EOT
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "sandbox_failed"
    severity   = "critical"
    managed_by = "terraform"
  })
}
