# Backup pipeline alerting. The vmd daemon exports backup metrics through
# the host-local OTel collector into Managed Prometheus; these policies
# watch one cell's host via the bounded host_id label (never sandbox or
# customer identifiers). PromQL conditions fire while the query returns a
# series, so each query folds its threshold into the expression.
#
# The set exists for two failure classes: pause-path latency regressions
# that only a pause-hook duration metric can catch, and a production host
# running with backup silently disabled (backup_enabled=0).

locals {
  backup_host_matcher = var.backup_alerts == null ? "" : "host_id=\"${var.backup_alerts.host_id}\""

  backup_alert_conditions = var.backup_alerts == null ? {} : merge({
    upload_failures = {
      display_name = "${var.backup_alerts.display_prefix} / upload failures sustained"
      # Failed attempts per hour over a 30m window. Retry backoff caps at
      # 10m, so one permanently failing generation alone produces ~6
      # attempts/hour; the threshold catches a single stuck task on any
      # cell regardless of its pause volume, without firing on
      # transient bucket errors that clear on retry.
      query         = "sum(rate(backup_upload_total{result=\"failed\", ${local.backup_host_matcher}}[30m])) * 3600 > ${var.backup_alerts.upload_failures_per_hour}"
      duration      = "1800s"
      documentation = <<-EOT
        Backup upload attempts on ${var.backup_alerts.host_id} have been failing at more than ${var.backup_alerts.upload_failures_per_hour}/hour for 30 minutes. The journal retries with capped backoff, so sustained failures mean the bucket, credentials, or network path is broken and the backlog is growing.

        Owner: Infrastructure Operations. Response: check vmd backup logs on the host for the failing generation and error, verify bucket IAM and connectivity, and confirm backup_journal_pending drains after the fix.
      EOT
    }

    backlog_age = {
      display_name = "${var.backup_alerts.display_prefix} / oldest pending generation too old"
      # Sparse-packed overlays ship in seconds under the default
      # bandwidth cap, so queue residence is normally well under a
      # minute even on a busy cell. A 30 minute
      # old queue head means the drain loop is stalled or falling behind,
      # and every queued pause is unmet durability (RPO) exposure.
      # Scoped to the pause tier: pause generations should ship in
      # seconds, while checkpoint and best-effort backlogs (the backfill
      # sweep in particular) are deliberately patient, drain only in
      # idle pipe time, and would otherwise hold this alert firing for
      # the whole enablement window.
      query         = "max(backup_oldest_pending_age_seconds{priority=\"pause\", ${local.backup_host_matcher}}) > ${var.backup_alerts.oldest_pending_age_seconds}"
      duration      = "900s"
      documentation = <<-EOT
        The oldest queued backup generation on ${var.backup_alerts.host_id} has been waiting more than ${var.backup_alerts.oldest_pending_age_seconds}s. Queued pauses are not yet durable in the bucket, so this is direct restore-point exposure.

        Owner: Infrastructure Operations. Response: check whether the uploader is failing (backup_upload_total{result="failed"}), bandwidth-capped behind a large template upload, or wedged; drain must resume before the local staging tier fills.
      EOT
    }

    pause_hook_p99 = {
      display_name = "${var.backup_alerts.display_prefix} / pause hook p99 regression"
      # The synchronous hook is bounded by design to a marker write, an
      # O(dirtied-bytes) staging copy, and a tens-of-KB vmstate hash:
      # tens to low hundreds of ms. The class this alert exists for is a
      # synchronous term that scales with disk size instead of dirtied
      # bytes; 2s p99 catches that while tolerating the occasional large
      # staged overlay. The 1h rate window keeps the quantile meaningful
      # on a low-traffic cell.
      query         = "histogram_quantile(0.99, sum by (le) (rate(backup_pause_hook_duration_seconds_bucket{${local.backup_host_matcher}}[1h]))) > ${var.backup_alerts.pause_hook_p99_seconds}"
      duration      = "1800s"
      documentation = <<-EOT
        The p99 of the synchronous backup hook on the pause RPC path on ${var.backup_alerts.host_id} exceeded ${var.backup_alerts.pause_hook_p99_seconds}s for 30 minutes. This latency is paid by every pause the control plane issues.

        Owner: Infrastructure Operations. Response: compare backup_stage_duration_seconds and backup_pause_hook_duration_seconds to find the regressing stage, and check recent vmd deploys for work added to the pause path; size-dependent hashing belongs on the detached worker, never on the RPC path.
      EOT
    }

    outbox_stalled = {
      display_name = "${var.backup_alerts.display_prefix} / completion write-back stalled"
      # The notification outbox drains on every ack and on idle ticks
      # (seconds end to end), so entries standing for an hour mean
      # completion signals are not reaching downstream bookkeeping and
      # staging GC is pinned. Until a notification consumer is wired
      # onto the uploader (its own change), the gauge sits at zero and
      # this policy is armed but structurally quiet; it cannot false
      # positive, only wake once a consumer exists.
      query         = "min(backup_outbox_pending{${local.backup_host_matcher}}) > 0"
      duration      = var.backup_alerts.outbox_stalled_duration
      documentation = <<-EOT
        Completed backup generations on ${var.backup_alerts.host_id} have had undelivered completion notifications for the whole alert window. Downstream coverage bookkeeping and staging cleanup key on these signals.

        Owner: Infrastructure Operations. Response: check vmd logs for "backup notification" failures (outbox read or clear errors point at the journal DB; callback errors point at the write-back consumer) and confirm backup_outbox_pending returns to zero.
      EOT
    }
    },
    var.backup_alerts.alert_disabled_host ? {
      backup_disabled = {
        display_name = "${var.backup_alerts.display_prefix} / backup disabled on host"
        # vmd emits backup_enabled from outside the BACKUP_BUCKET gate
        # precisely so a host with backup misconfigured reports 0 instead
        # of nothing; without it, a misconfigured host is indistinguishable
        # from one emitting no metrics. 30 minutes tolerates deploy churn.
        query         = "max(backup_enabled{${local.backup_host_matcher}}) < 1"
        duration      = "1800s"
        documentation = <<-EOT
          ${var.backup_alerts.host_id} is running with the backup pipeline disabled (backup_enabled=0, meaning BACKUP_BUCKET is unset). Every pause on this host is currently without a durable copy.

          Owner: Infrastructure Operations. Response: restore BACKUP_BUCKET in the host's vmd environment and restart vmd; the pending-marker sweep re-enqueues pauses that were owed a backup while disabled.
        EOT
      }
    } : {}
  )
}

resource "google_monitoring_alert_policy" "backup" {
  for_each = local.backup_alert_conditions

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
    alert_type = "backup_${each.key}"
    managed_by = "terraform"
  })
}

# Host root-filesystem alerting. The host-local collector's hostmetrics
# receiver exports utilization for the root mountpoint only (the sandbox
# data arrays are separate filesystems with their own reclaim logic), so
# these policies watch the OS disk that the host's control services live
# on. Series carry the same bounded host_id label as the backup metrics.

locals {
  host_disk_matcher = var.host_disk_alerts == null ? "" : "host_id=\"${var.host_disk_alerts.host_id}\""

  host_disk_alert_conditions = var.host_disk_alerts == null ? {} : {
    root_fs_warning = {
      display_name = "${var.host_disk_alerts.display_prefix} / root filesystem filling"
      severity     = "WARNING"
      # 85% still leaves working headroom for logs, package state, and
      # deploy artifacts, so cleanup can happen deliberately instead of
      # under pressure. Sustaining it for 30 minutes filters spikes from
      # transient files that free themselves.
      query         = "max(system_filesystem_utilization{mountpoint=\"/\", ${local.host_disk_matcher}}) > ${var.host_disk_alerts.warning_utilization}"
      duration      = var.host_disk_alerts.warning_duration
      documentation = <<-EOT
        Root filesystem utilization on ${var.host_disk_alerts.host_id} has stayed above ${format("%.0f", var.host_disk_alerts.warning_utilization * 100)}% for the alert window. This is the OS disk, not the sandbox data arrays; it holds logs, journals, package state, and deployed binaries, and it has no automatic reclaim.

        Owner: Infrastructure Operations. Response: find the growth with `sudo du -x -d1 /` on the host (journal, /var/log, and /tmp are the usual suspects), clean up or rotate, and confirm utilization drops back below the threshold. If steady-state usage has genuinely grown, resize before it reaches the paging threshold.
      EOT
    }

    root_fs_critical = {
      display_name = "${var.host_disk_alerts.display_prefix} / root filesystem near capacity"
      severity     = "CRITICAL"
      # At 95% the OS disk is close to exhaustion: writes for logs,
      # journals, and system state start failing shortly after, which
      # takes down the host's control services and blocks deploys. That
      # is worth a page while there is still room to act; the short
      # window only debounces single-scrape blips.
      query         = "max(system_filesystem_utilization{mountpoint=\"/\", ${local.host_disk_matcher}}) > ${var.host_disk_alerts.critical_utilization}"
      duration      = var.host_disk_alerts.critical_duration
      documentation = <<-EOT
        Root filesystem utilization on ${var.host_disk_alerts.host_id} is above ${format("%.0f", var.host_disk_alerts.critical_utilization * 100)}%. The OS disk is close to exhaustion; once writes fail, the host's control services (vmd, the collector, systemd journal) degrade and deploys to the host stop working.

        Owner: Infrastructure Operations. Response: free space immediately (`sudo journalctl --vacuum-size=500M`, clear /tmp and old artifacts under /var), then chase the source of growth. Treat sustained utilization at this level as a capacity problem, not a cleanup problem.
      EOT
    }
  }
}

resource "google_monitoring_alert_policy" "host_disk" {
  for_each = local.host_disk_alert_conditions

  project               = var.project_id
  display_name          = each.value.display_name
  combiner              = "OR"
  enabled               = true
  severity              = each.value.severity
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
    alert_type = "host_disk_${each.key}"
    managed_by = "terraform"
  })
}
