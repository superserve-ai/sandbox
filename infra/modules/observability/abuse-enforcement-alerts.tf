resource "google_monitoring_alert_policy" "abuse_enforcement_cache_warning" {
  count = var.abuse_enforcement_alerts_enabled ? 1 : 0

  project               = var.project_id
  display_name          = "Abuse enforcement cache utilization warning"
  combiner              = "OR"
  enabled               = true
  severity              = "WARNING"
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel when abuse enforcement alerts are enabled"
    }
  }

  conditions {
    display_name = "Abuse cache utilization above 70 percent"
    condition_prometheus_query_language {
      query               = "abuse_enforcement_utilization >= 0.7"
      duration            = "0s"
      evaluation_interval = "60s"
    }
  }

  alert_strategy { auto_close = "1800s" }

  documentation {
    content   = "The local abuse-enforcement cache is above 70% utilization. Investigate cache pressure before restrictions are evicted."
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "abuse_enforcement_cache_warning"
    managed_by = "terraform"
  })
}

resource "google_monitoring_alert_policy" "abuse_enforcement_cache_critical" {
  count = var.abuse_enforcement_alerts_enabled ? 1 : 0

  project               = var.project_id
  display_name          = "Abuse enforcement cache critical pressure"
  combiner              = "OR"
  enabled               = true
  severity              = "CRITICAL"
  notification_channels = var.notification_channel_ids

  lifecycle {
    precondition {
      condition     = length(var.notification_channel_ids) > 0
      error_message = "notification_channel_ids must contain an existing monitored channel when abuse enforcement alerts are enabled"
    }
  }

  conditions {
    display_name = "Abuse cache critical pressure or eviction"
    condition_prometheus_query_language {
      query               = "abuse_enforcement_utilization >= 0.9 or increase(abuse_enforcement_capacity_evictions_total[5m]) > 0 or increase(abuse_enforcement_admission_rejections_total[5m]) > 0"
      duration            = "0s"
      evaluation_interval = "60s"
    }
  }

  alert_strategy { auto_close = "1800s" }

  documentation {
    content   = "The local abuse-enforcement cache is at critical pressure or has evicted restrictions to admit newer entries."
    mime_type = "text/markdown"
  }

  user_labels = merge(var.labels, {
    alert_type = "abuse_enforcement_cache_critical"
    managed_by = "terraform"
  })
}
