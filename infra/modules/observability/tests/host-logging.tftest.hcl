run "host_logging_alerts_contract" {
  command = plan

  variables {
    project_id  = "example-project"
    environment = "staging"
    runbook_urls = {
      host_cpu              = "https://example.invalid/runbooks/host-cpu"
      host_maintenance      = "https://example.invalid/runbooks/host-maintenance"
      host_logging_export   = "https://example.invalid/runbooks/host-logging-export"
      host_logging_lag      = "https://example.invalid/runbooks/host-logging-lag"
      host_logging_heartbeat = "https://example.invalid/runbooks/host-logging-heartbeat"
    }
    notification_channel_ids = ["projects/example-project/notificationChannels/123"]
    host_logging_alerts = {
      display_prefix = "Host logging / example"
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
      strcontains(metric.filter, "labels.journal_unit=\"superserve-host-logging-heartbeat.service\"")
    ])
    error_message = "Heartbeat metric must accept only the managed heartbeat unit."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_lag) :
      alltrue([for condition in policy.conditions : (
        (length(condition.condition_prometheus_query_language) == 1 &&
          strcontains(one(condition.condition_prometheus_query_language).query, "absent_over_time(") &&
          one(condition.condition_prometheus_query_language).disable_metric_validation)
      )])
    ])
    error_message = "Each Monitoring condition block must contain exactly one supported condition type."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_heartbeat) :
      length(one(policy.conditions).condition_prometheus_query_language) == 1 &&
      strcontains(one(policy.conditions).condition_prometheus_query_language[0].query, "absent(") &&
      one(policy.conditions).condition_prometheus_query_language[0].disable_metric_validation
    ])
    error_message = "Heartbeat absence must alert on an empty expected-host series, including never-seen replacements."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_export_failures) :
      strcontains(one(policy.conditions).condition_matched_log.filter, "log_id(\"ops_agent_self_log_files\")")
    ])
    error_message = "Export failure alert must consume the explicit bounded Ops Agent self-log receiver."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_heartbeat) :
      strcontains(one(policy.conditions).condition_prometheus_query_language[0].query, "otelcol_process_uptime")
    ])
    error_message = "Independent heartbeat must select the GMP-exported collector self metric."
  }
}
