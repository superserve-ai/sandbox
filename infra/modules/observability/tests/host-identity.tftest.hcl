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
      for key, expected in {
        upload_failures = { metric = "backup_upload_total/counter", label = "result", value = "failed", threshold = 4 / 3600, duration = "1800s", aligner = "ALIGN_RATE" }
        backlog_age     = { metric = "backup_oldest_pending_age_seconds/gauge", label = "priority", value = "pause", threshold = 1800, duration = "900s", aligner = "ALIGN_MAX" }
        } : (
        google_monitoring_alert_policy.backup[key].combiner == "OR" &&
        toset([for condition in google_monitoring_alert_policy.backup[key].conditions : one(condition.condition_threshold).filter]) == toset([
          for label, value in { host_id = "legacy-host", collector_host_id = "example-host" } :
          "metric.type = \"prometheus.googleapis.com/${expected.metric}\" AND resource.type = \"prometheus_target\" AND metric.labels.${expected.label} = \"${expected.value}\" AND metric.labels.${label} = \"${value}\""
        ]) &&
        length(google_monitoring_alert_policy.backup[key].conditions) == 2 &&
        alltrue([for condition in google_monitoring_alert_policy.backup[key].conditions : (
          one(condition.condition_threshold).comparison == "COMPARISON_GT" &&
          one(condition.condition_threshold).threshold_value == expected.threshold &&
          one(condition.condition_threshold).duration == expected.duration &&
          one(one(condition.condition_threshold).aggregations).alignment_period == "60s" &&
          one(one(condition.condition_threshold).aggregations).per_series_aligner == expected.aligner &&
          one(one(condition.condition_threshold).trigger).count == 1
        )])
      )
    ])
    error_message = "Both identity conditions must retain exact host and result/priority restrictions, thresholds, windows, and OR semantics."
  }
  assert {
    condition = alltrue(flatten([
      for policy in concat(values(google_monitoring_alert_policy.backup), values(google_monitoring_alert_policy.launch_path)) : [
        for condition in policy.conditions : !(
          strcontains(one(condition.condition_threshold).filter, " OR ") &&
          length(regexall("metric[.]labels[.]", one(condition.condition_threshold).filter)) > 2
        )
      ]
    ]))
    error_message = "Monitoring rejects a host-label OR combined with additional AND metric-label restrictions."
  }
  assert {
    condition = alltrue([
      for policy in concat([for key, policy in google_monitoring_alert_policy.backup : policy if !contains(["upload_failures", "backlog_age"], key)], values(google_monitoring_alert_policy.launch_path)) :
      endswith(one(one(policy.conditions).condition_threshold).filter, " AND (metric.labels.host_id = \"legacy-host\" OR metric.labels.collector_host_id = \"example-host\")")
    ])
    error_message = "Unconstrained backup and launch alerts must keep one host-label union, preserving aggregation semantics."
  }
  assert {
    condition     = one(one(one(google_monitoring_alert_policy.backup["pause_hook_p99"].conditions).condition_threshold).aggregations).group_by_fields == tolist(["metric.label.host_id"])
    error_message = "Latency reduction must keep different host IDs separate during replacement."
  }
  assert {
    condition = (
      anytrue([for condition in google_monitoring_alert_policy.backup["upload_failures"].conditions : strcontains(one(condition.condition_threshold).filter, "metric.labels.collector_host_id")]) &&
      contains(yamldecode(file("../../../deploy/otel/collector-gmp.yaml")).service.pipelines.metrics.processors, "attributes/collector_host_id") &&
      yamldecode(file("../../../deploy/otel/collector-gmp.yaml")).processors["attributes/collector_host_id"].actions == [
        { key = "collector_host_id", value = "$${env:COLLECTOR_HOST_ID}", action = "upsert" }
      ] &&
      !contains(yamldecode(file("../../../deploy/otel/collector-gmp.yaml")).service.pipelines.metrics.processors, "attributes/host_id")
    )
    error_message = "The OTLP pipeline must stamp the stable collector identity without overwriting the sender's authoritative host_id."
  }
}

run "disabled_alerts_create_no_policies" {
  command = plan
  variables {
    backup_alerts      = null
    launch_path_alerts = null
  }
  assert {
    condition     = length(google_monitoring_alert_policy.backup) == 0 && length(google_monitoring_alert_policy.launch_path) == 0
    error_message = "Null configurations must continue disabling the policy sets."
  }
}

run "disk_alerts_select_the_collector_instance_identity" {
  command = plan
  variables {
    host_disk_alerts = {
      host_id        = "example-host"
      display_prefix = "Infrastructure / example-host"
    }
  }
  assert {
    condition = alltrue([
      for key, expected in {
        root_fs_warning  = { threshold = 0.85, duration = "1800s" }
        root_fs_critical = { threshold = 0.95, duration = "300s" }
        } : (
        google_monitoring_alert_policy.host_disk[key].combiner == "OR" &&
        one(one(google_monitoring_alert_policy.host_disk[key].conditions).condition_threshold).filter ==
        "metric.type = \"prometheus.googleapis.com/system_filesystem_utilization/gauge\" AND resource.type = \"prometheus_target\" AND metric.labels.mountpoint = \"/\" AND metric.labels.host_id = \"example-host\"" &&
        one(one(google_monitoring_alert_policy.host_disk[key].conditions).condition_threshold).comparison == "COMPARISON_GT" &&
        one(one(google_monitoring_alert_policy.host_disk[key].conditions).condition_threshold).threshold_value == expected.threshold &&
        one(one(google_monitoring_alert_policy.host_disk[key].conditions).condition_threshold).duration == expected.duration &&
        one(one(one(google_monitoring_alert_policy.host_disk[key].conditions).condition_threshold).aggregations).alignment_period == "60s" &&
        one(one(one(google_monitoring_alert_policy.host_disk[key].conditions).condition_threshold).aggregations).per_series_aligner == "ALIGN_MAX" &&
        one(one(one(google_monitoring_alert_policy.host_disk[key].conditions).condition_threshold).trigger).count == 1
      )
    ])
    error_message = "Disk alerts must select the collector's instance identity with unchanged root-only thresholds and windows."
  }
  assert {
    condition = (
      length(google_monitoring_alert_policy.host_disk) == 2 &&
      contains(yamldecode(file("../../../deploy/otel/collector-gmp.yaml")).service.pipelines["metrics/host"].processors, "attributes/collector_host_id") &&
      yamldecode(file("../../../deploy/otel/collector-gmp.yaml")).processors["attributes/host_id"].actions == [
        { key = "host_id", value = "$${env:HOST_ID}", action = "upsert" }
      ]
    )
    error_message = "Host metrics must keep HOST_ID and also stamp the stable collector identity the alerts will move to."
  }
}

# The disk alert filter cannot name collector_host_id until every collector has
# reported it on the host series; Monitoring 404s an unknown label.
run "disk_alerts_do_not_reference_an_unreported_label" {
  command = plan
  variables {
    host_disk_alerts = {
      host_id        = "example-host"
      display_prefix = "Infrastructure / example-host"
    }
  }
  assert {
    condition = alltrue([
      for policy in values(google_monitoring_alert_policy.host_disk) :
      !anytrue([for condition in policy.conditions : strcontains(one(condition.condition_threshold).filter, "collector_host_id")])
    ])
    error_message = "Disk alert filters must not reference collector_host_id before the collectors emit it."
  }
}
