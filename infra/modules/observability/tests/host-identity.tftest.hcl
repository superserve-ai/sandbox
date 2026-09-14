mock_provider "google" {}

variables {
  project_id  = "example-project"
  environment = "staging"
  backup_alerts = {
    host_id        = "legacy-host"
    display_prefix = "Backup / example-host"
  }
  launch_path_alerts = {
    host_id        = "legacy-host"
    display_prefix = "Launch / example-host"
  }
}

run "legacy_collectors_remain_covered" {
  command = plan
  assert {
    condition = alltrue([
      for policy in concat(values(google_monitoring_alert_policy.backup), values(google_monitoring_alert_policy.launch_path)) :
      endswith(one(one(policy.conditions).condition_threshold).filter, " AND metric.labels.host_id = \"legacy-host\"")
    ])
    error_message = "Existing callers must retain their legacy host filter."
  }
}

run "generated_host_ids_use_stable_collector_identity" {
  command = plan
  variables {
    backup_alerts = {
      host_id           = "legacy-host"
      collector_host_id = "example-host"
      display_prefix    = "Backup / example-host"
    }
    launch_path_alerts = {
      host_id           = "legacy-host"
      collector_host_id = "example-host"
      display_prefix    = "Launch / example-host"
    }
  }
  assert {
    condition = alltrue([
      for policy in concat(values(google_monitoring_alert_policy.backup), values(google_monitoring_alert_policy.launch_path)) :
      endswith(one(one(policy.conditions).condition_threshold).filter, " AND (metric.labels.host_id = \"legacy-host\" OR metric.labels.collector_host_id = \"example-host\")")
    ])
    error_message = "All backup and launch alerts must select generated IDs through the collector and preserve legacy coverage."
  }
  assert {
    condition     = one(one(one(google_monitoring_alert_policy.backup["pause_hook_p99"].conditions).condition_threshold).aggregations).group_by_fields == tolist(["metric.label.host_id"])
    error_message = "Latency reduction must keep different host IDs separate during replacement."
  }
  assert {
    condition = (
      strcontains(one(one(google_monitoring_alert_policy.backup["upload_failures"].conditions).condition_threshold).filter, "metric.labels.collector_host_id") &&
      contains(yamldecode(file("../../../deploy/otel/collector-gmp.yaml")).service.pipelines.metrics.processors, "attributes/collector_host_id") &&
      yamldecode(file("../../../deploy/otel/collector-gmp.yaml")).processors["attributes/collector_host_id"].actions == [
        { key = "collector_host_id", value = "$${env:HOST_ID}", action = "upsert" }
      ] &&
      !contains(yamldecode(file("../../../deploy/otel/collector-gmp.yaml")).service.pipelines.metrics.processors, "attributes/host_id")
    )
    error_message = "The OTLP pipeline must stamp the stable collector identity without overwriting the sender's authoritative host_id."
  }
}
