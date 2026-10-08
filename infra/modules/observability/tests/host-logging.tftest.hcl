mock_provider "google" {}

run "host_logging_alerts_contract" {
  command = plan

  variables {
    project_id  = "example-project"
    environment = "staging"
    runbook_urls = {
      host_cpu               = "https://example.invalid/runbooks/host-cpu"
      host_maintenance       = "https://example.invalid/runbooks/host-maintenance"
      host_logging_export    = "https://example.invalid/runbooks/host-logging-export"
      host_logging_lag       = "https://example.invalid/runbooks/host-logging-lag"
      host_logging_heartbeat = "https://example.invalid/runbooks/host-logging-heartbeat"
    }
    notification_channel_ids = ["projects/example-project/notificationChannels/123"]
    host_logging_alerts = {
      display_prefix        = "Host logging / example"
      lag_threshold_seconds = 600
      expected_hosts = {
        pilot = {
          instance_name = "example-vmd-1"
          instance_id   = "123"
          # The runtime host_id and VM name are intentionally different and are
          # not used by this heartbeat consumer; the producer extracts the
          # numeric instance identity.
          collector_host_id = "example-vmd-1"
          incarnation       = "incarnation-a"
        }
      }
    }
  }

  assert {
    condition = alltrue([
      for metric in values(google_logging_metric.host_logging_heartbeat) :
      metric.label_extractors["collector_host_id"] == "EXTRACT(resource.labels.instance_id)"
    ])
    error_message = "Heartbeat producer must use the stable VM identity, not runtime host_id."
  }

  assert {
    condition = alltrue([
      for metric in values(google_logging_metric.host_logging_heartbeat) :
      strcontains(metric.filter, "labels.journal_unit=\"superserve-host-logging-heartbeat.service\"") &&
      strcontains(metric.filter, "labels.incarnation=\"incarnation-a\"")
    ])
    error_message = "Heartbeat metric must accept only the managed heartbeat unit."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_lag) :
      alltrue([for condition in policy.conditions : (
        length(condition.condition_prometheus_query_language) == 1 &&
        strcontains(one(condition.condition_prometheus_query_language).query, "logging_googleapis_com:user_") &&
        strcontains(one(condition.condition_prometheus_query_language).query, "sum_over_time") &&
        strcontains(one(condition.condition_prometheus_query_language).query, "[600s]") &&
        one(condition.condition_prometheus_query_language).duration == "300s"
      )])
    ])
    error_message = "Freshness must use the existing heartbeat metric and a bounded recent source-timestamp window."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_heartbeat) :
      length(one(policy.conditions).condition_prometheus_query_language) == 1 &&
      strcontains(one(policy.conditions).condition_prometheus_query_language[0].query, "or vector(0)") &&
      strcontains(one(policy.conditions).condition_prometheus_query_language[0].query, "\"incarnation\" = \"incarnation-a\"") &&
      one(policy.conditions).condition_prometheus_query_language[0].disable_metric_validation
    ])
    error_message = "Heartbeat absence must alert on an empty expected-host series, including never-seen replacements."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_export_failures) :
      strcontains(one(one(policy.conditions).condition_matched_log).filter, "log_id(\"superserve_host_logs\")")
    ])
    error_message = "Export failure alert must consume the dedicated OTel host-log stream."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_heartbeat) :
      strcontains(one(policy.conditions).condition_prometheus_query_language[0].query, "logging_googleapis_com:user_") &&
      strcontains(one(policy.conditions).condition_prometheus_query_language[0].query, "collector_host_id")
    ])
    error_message = "Independent heartbeat must select the Cloud Logging-derived heartbeat series and provider instance identity."
  }
}

run "replacement_and_retired_hosts" {
  command = plan
  variables {
    project_id               = "example-project"
    environment              = "staging"
    notification_channel_ids = ["projects/example-project/notificationChannels/123"]
    runbook_urls = {
      host_cpu               = "https://example.invalid/host-cpu"
      host_maintenance       = "https://example.invalid/host-maintenance"
      host_logging_export    = "https://example.invalid/export"
      host_logging_lag       = "https://example.invalid/lag"
      host_logging_heartbeat = "https://example.invalid/heartbeat"
    }
    host_logging_alerts = {
      display_prefix = "Example"
      expected_hosts = {
        retired     = { instance_name = "example-old", instance_id = "123", active = false }
        replacement = { instance_name = "example-new", instance_id = "456" }
      }
    }
  }
  assert {
    condition     = keys(google_logging_metric.host_logging_heartbeat) == ["replacement"] && keys(google_monitoring_alert_policy.host_logging_heartbeat) == ["replacement"]
    error_message = "Only the active replacement must have a heartbeat metric and absence alert."
  }
  assert {
    condition     = strcontains(google_logging_metric.host_logging_heartbeat["replacement"].filter, "instance_id=\"456\"") && !strcontains(google_logging_metric.host_logging_heartbeat["replacement"].filter, "123")
    error_message = "The predecessor must not satisfy the replacement's heartbeat metric."
  }
  assert {
    condition     = strcontains(one(google_monitoring_alert_policy.host_logging_heartbeat["replacement"].conditions).condition_prometheus_query_language[0].query, "\"456\"")
    error_message = "The absence query must select the replacement identity."
  }
}

run "pause_only_selected_host_freshness" {
  command = plan
  variables {
    project_id               = "example-project"
    environment              = "staging"
    notification_channel_ids = ["projects/example-project/notificationChannels/123"]
    runbook_urls = {
      host_logging_export    = "https://example.invalid/export"
      host_logging_lag       = "https://example.invalid/lag"
      host_logging_heartbeat = "https://example.invalid/heartbeat"
    }
    host_logging_alerts = {
      display_prefix = "Example"
      expected_hosts = {
        pending_retirement = { instance_name = "example-old", instance_id = "123", freshness_alerts_enabled = false }
        serving            = { instance_name = "example-serving", instance_id = "456" }
      }
    }
  }
  assert {
    condition = (
      !google_monitoring_alert_policy.host_logging_heartbeat["pending_retirement"].enabled &&
      !google_monitoring_alert_policy.host_logging_lag["pending_retirement"].enabled &&
      google_monitoring_alert_policy.host_logging_export_failures["pending_retirement"].enabled &&
      google_monitoring_alert_policy.host_logging_heartbeat["serving"].enabled &&
      google_monitoring_alert_policy.host_logging_lag["serving"].enabled &&
      google_monitoring_alert_policy.host_logging_export_failures["serving"].enabled
    )
    error_message = "Pausing one host's freshness must retain its export-error alert and every serving-host alert."
  }
  assert {
    condition = (
      keys(google_logging_metric.host_logging_heartbeat) == ["pending_retirement", "serving"] &&
      google_monitoring_alert_policy.host_logging_heartbeat["pending_retirement"].notification_channels == var.notification_channel_ids &&
      google_monitoring_alert_policy.host_logging_lag["pending_retirement"].notification_channels == var.notification_channel_ids
    )
    error_message = "Paused policies must retain their metrics and notification channels for re-enablement."
  }
}
