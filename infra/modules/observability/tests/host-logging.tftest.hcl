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
        }
      }
    }
  }
}
