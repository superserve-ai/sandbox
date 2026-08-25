# Launch-path alerting. vmd normally starts Firecracker inside a pruned
# "launcher" mount namespace so a VM start costs a ~30-entry mount table
# instead of the host's full one. That pin is built at startup and, when the
# build fails, every launch silently falls back to the legacy path and walks
# the whole table — VM starts go from tens of milliseconds to seconds while
# the service stays "healthy" and nothing errors.
#
# These two policies exist because that degradation has no other signal: the
# unit is active, creates succeed, and only per-launch latency moves. They
# watch the same bounded host_id label as the backup metrics.

locals {
  # These policies use classic threshold conditions with an explicit
  # metric.type, NOT PromQL: the managed-Prometheus policy validator rejects
  # a bare gauge name ending in _total (it resolves it as a counter) AND any
  # reference to a metric that has not emitted yet — vmd_launcher_ready ships
  # in the same change as its policy, so PromQL validation can never pass on
  # first apply. Threshold conditions skip that validation entirely and are
  # already the pattern the module's CPU policies use.
  launch_path_filter_suffix = var.launch_path_alerts == null ? "" : " AND metric.labels.host_id = \"${var.launch_path_alerts.host_id}\""

  launch_path_alert_conditions = var.launch_path_alerts == null ? {} : {
    launcher_not_ready = {
      display_name = "${var.launch_path_alerts.display_prefix} / launcher pin down, launches on legacy path"
      # vmd_launcher_ready is 1 while launches use the pruned namespace and 0
      # the moment they fall back. A rebuild is retried on a 5 minute
      # interval, so a short 0 is self-healing and uninteresting; the window
      # here is long enough to let a retry succeed and short enough that a
      # host stuck on the legacy path is caught well before it becomes a
      # multi-hour latency incident.
      metric_type   = "prometheus.googleapis.com/vmd_launcher_ready/gauge"
      comparison    = "COMPARISON_LT"
      threshold     = 1
      aligner       = "ALIGN_MIN"
      duration      = var.launch_path_alerts.launcher_not_ready_duration
      documentation = <<-EOT
        Firecracker launches on ${var.launch_path_alerts.host_id} are running on the legacy path (vmd_launcher_ready=0), so every VM start walks the host's full mount table instead of the pruned launcher namespace. Expect VM start latency in the hundreds of milliseconds to seconds, growing with the host's mount table, while creates still succeed and nothing errors.

        Owner: Infrastructure Operations. Response: check vmd logs for "launcher pin rebuild failed" and "launcher pin not built" to see why the build is failing. Rebuilds retry every 5 minutes, so a policy that stays firing means the build fails repeatedly rather than transiently. Host mount-table size (vmd_network_mounts_total) is the usual aggravating factor; a vmd restart rebuilds the pin against the current table.
      EOT
    }

    netns_accumulation = {
      display_name = "${var.launch_path_alerts.display_prefix} / live network namespaces above threshold"
      # Live namespaces should track concurrently running VMs plus the warm
      # pool, not accumulate with every sandbox ever resumed. Each one adds
      # ~2 host mount entries, and the mount table is walked by daemon-reload
      # (deploy duration), ssh session setup, and the launcher pin build — so
      # sustained growth degrades deploys and host access before it degrades
      # anything customers see.
      metric_type   = "prometheus.googleapis.com/vmd_network_netns_total/gauge"
      comparison    = "COMPARISON_GT"
      threshold     = var.launch_path_alerts.netns_total_threshold
      aligner       = "ALIGN_MAX"
      duration      = var.launch_path_alerts.netns_total_duration
      documentation = <<-EOT
        ${var.launch_path_alerts.host_id} is carrying more than ${var.launch_path_alerts.netns_total_threshold} live network namespaces. Each contributes roughly two host mount-table entries, and that table is walked on every process start, every systemctl daemon-reload, and every ssh login — so deploys slow down, the host gets harder to reach, and the launcher pin build (which protects VM start latency) becomes more likely to fail.

        Owner: Infrastructure Operations. Response: confirm the paused-network reclaim controller is enabled and draining (vmd_network_slots_reclaimed_paused_total should be rising, vmd_network_netns_total falling). If the count is flat or rising while the controller is engaged, the per-pass reclaim cap is at or below the rate at which new namespaces are being created.
      EOT
    }

    netns_runaway = {
      display_name = "${var.launch_path_alerts.display_prefix} / live network namespaces climbing fast"
      # Same signal as the policy above, higher bar and a short window. The
      # 30 minute confirmation is appropriate for a count sitting just over
      # the reclaim ceiling, but a host whose inflow has outrun the drain
      # covers thousands of namespaces in that time, and every mount-table
      # operation gets more expensive the whole way. Reaching this level at
      # all means the controller is not merely lagging but losing.
      metric_type   = "prometheus.googleapis.com/vmd_network_netns_total/gauge"
      comparison    = "COMPARISON_GT"
      threshold     = var.launch_path_alerts.netns_critical_threshold
      aligner       = "ALIGN_MAX"
      duration      = var.launch_path_alerts.netns_critical_duration
      documentation = <<-EOT
        ${var.launch_path_alerts.host_id} has passed ${var.launch_path_alerts.netns_critical_threshold} live network namespaces. Unlike the sustained-growth policy, this fires quickly: at this level the reclaim controller has engaged and is losing to inflow, and the count typically keeps climbing rather than levelling off. Deploys, ssh logins, and the launcher pin build all degrade as the mount table grows, and a vmd restart in this state is likely to fail its pin build and leave every VM start on the slow path.

        Owner: Infrastructure Operations. Response: check whether the reclaim controller is draining at all (vmd_network_slots_reclaimed_paused_total rate) and compare it against the rate new namespaces are appearing. If the drain is running at its per-pass cap and still not winning, the cap (VMD_PAUSED_NETWORK_MAX_RECLAIMS) is the constraint. Confirm vmd_launcher_ready is still 1 before considering a restart.
      EOT
    }
  }
}

resource "google_monitoring_alert_policy" "launch_path" {
  for_each = local.launch_path_alert_conditions

  project               = var.project_id
  display_name          = each.value.display_name
  combiner              = "OR"
  enabled               = true
  notification_channels = var.notification_channel_ids

  conditions {
    display_name = each.value.display_name

    condition_threshold {
      filter          = "metric.type = \"${each.value.metric_type}\" AND resource.type = \"prometheus_target\"${local.launch_path_filter_suffix}"
      comparison      = each.value.comparison
      threshold_value = each.value.threshold
      duration        = each.value.duration
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = each.value.aligner
      }
      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = each.value.documentation
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "launch_path_${each.key}"
    managed_by = "terraform"
  })
}

# Cloud Run replacement signals belong with the launch-path safety alerts: the
# readiness/liveness configuration removes a bad replica, while these metrics
# page when that safety mechanism churns unexpectedly.
locals {
  # Cloud Run documents instance-start records in varlog/system with a
  # reason-bearing textPayload. Match that documented record shape, then
  # exclude deployment rollout starts by their platform reason. The observed
  # reason is deliberately not hard-coded: staging validation confirms which
  # non-rollout reason accompanies a replacement in the deployed environment.
  cloud_run_churn_log_filter = <<-EOT
    log_id("varlog/system")
    resource.type="cloud_run_revision"
    resource.labels.service_name="%s"
    labels.instanceId:*
    textPayload =~ "^Starting new instance\\. Reason: [A-Z_]+ - "
    NOT textPayload:"Reason: DEPLOYMENT_ROLLOUT"
  EOT
}

resource "google_logging_metric" "cloud_run_churn" {
  for_each = var.cloud_run_churn_alerts

  project = var.project_id
  name    = "${each.key}-${replace(each.value.service_name, "-", "_")}-cloud-run-replacements"
  filter  = format(local.cloud_run_churn_log_filter, each.value.service_name)

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "revision_name"
      value_type  = "STRING"
      description = "Cloud Run revision associated with the replacement event."
    }
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Cloud Run instance associated with the replacement event."
    }
  }

  label_extractors = {
    revision_name = "EXTRACT(resource.labels.revision_name)"
    instance_id   = "EXTRACT(labels.instanceId)"
  }
}

resource "google_monitoring_alert_policy" "cloud_run_churn" {
  for_each = var.cloud_run_churn_alerts

  project               = var.project_id
  display_name          = each.value.display_name
  combiner              = "OR"
  enabled               = true
  notification_channels = var.notification_channel_ids

  lifecycle {
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
      condition     = each.value.repeat_threshold > 0 && each.value.fleet_threshold > 0
      error_message = "Cloud Run churn thresholds must be greater than zero"
    }
  }

  conditions {
    display_name = "${each.value.service_name} unexpected replacement churn"

    condition_threshold {
      filter          = "metric.type = \"logging.googleapis.com/user/${google_logging_metric.cloud_run_churn[each.key].name}\" AND resource.type = \"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = each.value.repeat_threshold
      # Compare one complete evaluation window so the threshold represents
      # roughly N replacements in the configured window, rather than N per
      # minute for the entire duration.
      duration = "0s"
      aggregations {
        alignment_period   = each.value.duration
        per_series_aligner = "ALIGN_SUM"
        group_by_fields    = ["metric.label.revision_name"]
      }
    }
  }

  conditions {
    display_name = "${each.value.service_name} correlated replacement churn"

    condition_threshold {
      filter          = "metric.type = \"logging.googleapis.com/user/${google_logging_metric.cloud_run_churn[each.key].name}\" AND resource.type = \"global\""
      comparison      = "COMPARISON_GE"
      threshold_value = each.value.fleet_threshold
      duration        = "0s"
      aggregations {
        alignment_period     = each.value.duration
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_COUNT"
      }
    }
  }

  alert_strategy { auto_close = "1800s" }

  documentation {
    content   = coalesce(each.value.documentation, "Unexpected Cloud Run replacement churn was detected for ${each.value.service_name}. The metric is limited to verified liveness-failure replacement events.")
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type   = "cloud_run_replacement_churn"
    service_name = each.value.service_name
    managed_by   = "terraform"
  })
}
