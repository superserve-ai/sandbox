mock_provider "google" {}

variables {
  project_id               = "example-project"
  environment              = "production"
  notification_channel_ids = ["projects/example-project/notificationChannels/123"]
  cells = {
    east = {
      metric_location         = "us-east4-c"
      cloud_run_service       = "example-api-east"
      cloud_run_region        = "us-east4"
      coverage_checks_enabled = true
    }
    west = {
      metric_location         = "us-west2-a"
      cloud_run_service       = "example-api-west"
      cloud_run_region        = "us-west2"
      coverage_checks_enabled = true
    }
  }
}

run "enabled" {
  command = plan
  assert {
    condition = (
      strcontains(local.recovery_log_filter, "textPayload:") &&
      strcontains(local.recovery_log_filter, "textPayload=~") &&
      strcontains(local.recovery_log_filter, "jsonPayload.message=") &&
      strcontains(local.recovery_log_filter, "example-api-east") &&
      strcontains(local.recovery_log_filter, "example-api-west")
    )
    error_message = "Recovery logs must cover current console ERR output and structured ERROR output in both API cells."
  }
  assert {
    condition = (
      google_monitoring_alert_policy.entitlement_recovery.conditions[0].condition_matched_log[0].label_extractors == null &&
      google_monitoring_alert_policy.entitlement_recovery.alert_strategy[0].notification_rate_limit[0].period == "300s"
    )
    error_message = "Recovery bursts must share an incident and suppress duplicate notifications for five minutes."
  }
}

run "disabled_issuance" {
  command = plan
  variables {
    cells = {
      staging = {
        metric_location         = "us-central1-a"
        cloud_run_service       = "example-api"
        cloud_run_region        = "us-central1"
        coverage_checks_enabled = false
      }
    }
  }
  assert {
    condition     = length(local.sampler_checks) == 1 && local.sampler_checks["staging-usage_entitlement_backlog"].operation == "usage_entitlement_backlog"
    error_message = "Disabling issuance must omit coverage liveness while retaining independent backlog liveness."
  }
}

run "wrong_project_channel" {
  command = plan
  variables {
    notification_channel_ids = ["projects/other-project/notificationChannels/123"]
  }
  expect_failures = [google_monitoring_alert_policy.entitlement_metric, google_monitoring_alert_policy.entitlement_recovery]
}
