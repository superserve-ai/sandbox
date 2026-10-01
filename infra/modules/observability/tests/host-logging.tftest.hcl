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
          # The runtime host_id is intentionally different and is not used by
          # this heartbeat consumer; the producer extracts instance_name.
          collector_host_id = "example-vmd-1"
          incarnation       = "incarnation-a"
        }
      }
    }
  }

  assert {
    condition = alltrue([
      for metric in values(google_logging_metric.host_logging_heartbeat) :
      metric.label_extractors["collector_host_id"] == "EXTRACT(labels.instance_name)"
    ])
    error_message = "Heartbeat producer must use the stable VM identity, not runtime host_id."
  }

  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_logging_lag) :
      alltrue([for condition in policy.conditions : (
        (length(condition.condition_absent) == 1 && length(condition.condition_threshold) == 0) ||
        (length(condition.condition_absent) == 0 && length(condition.condition_threshold) == 1)
      )])
    ])
    error_message = "Each Monitoring condition block must contain exactly one supported condition type."
  }
}
