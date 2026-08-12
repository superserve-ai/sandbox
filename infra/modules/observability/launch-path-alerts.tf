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
  launch_path_host_matcher = var.launch_path_alerts == null ? "" : "host_id=\"${var.launch_path_alerts.host_id}\""

  launch_path_alert_conditions = var.launch_path_alerts == null ? {} : {
    launcher_not_ready = {
      display_name = "${var.launch_path_alerts.display_prefix} / launcher pin down, launches on legacy path"
      # vmd_launcher_ready is 1 while launches use the pruned namespace and 0
      # the moment they fall back. A rebuild is retried on a 5 minute
      # interval, so a short 0 is self-healing and uninteresting; the window
      # here is long enough to let a retry succeed and short enough that a
      # host stuck on the legacy path is caught well before it becomes a
      # multi-hour latency incident.
      query         = "min(vmd_launcher_ready{${local.launch_path_host_matcher}}) < 1"
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
      query         = "max(vmd_network_netns_total{${local.launch_path_host_matcher}}) > ${var.launch_path_alerts.netns_total_threshold}"
      duration      = "1800s"
      documentation = <<-EOT
        ${var.launch_path_alerts.host_id} is carrying more than ${var.launch_path_alerts.netns_total_threshold} live network namespaces. Each contributes roughly two host mount-table entries, and that table is walked on every process start, every systemctl daemon-reload, and every ssh login — so deploys slow down, the host gets harder to reach, and the launcher pin build (which protects VM start latency) becomes more likely to fail.

        Owner: Infrastructure Operations. Response: confirm the paused-network reclaim controller is enabled and draining (vmd_network_slots_reclaimed_paused_total should be rising, vmd_network_netns_total falling). If the count is flat or rising while the controller is engaged, the per-pass reclaim cap is at or below the rate at which new namespaces are being created.
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

    condition_prometheus_query_language {
      query               = each.value.query
      duration            = each.value.duration
      evaluation_interval = "30s"
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
