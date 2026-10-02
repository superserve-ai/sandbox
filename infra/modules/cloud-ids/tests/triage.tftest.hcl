mock_provider "google" {}

variables {
  runbook_base_url           = "https://example.com/runbooks"
  project_id                 = "example-production"
  region                     = "us-east4"
  zone                       = "us-east4-a"
  endpoint_name              = "example-ids-east"
  network_self_link          = "projects/example-production/global/networks/example"
  mirrored_subnet_self_links = ["projects/example-production/regions/us-east4/subnetworks/example"]
  notification_channel_ids   = ["projects/example-production/notificationChannels/123456"]
  labels = {
    superserve_family         = "caller_value"
    superserve_component      = "caller_value"
    superserve_failure_family = "caller_value"
    environment               = "production"
  }
}

run "east_triage" {
  command = apply

  assert {
    condition = replace(
      google_monitoring_alert_policy.ids_triage.conditions[0].condition_matched_log[0].filter,
      "/\\s+/", ""
      ) == replace(<<-EOT
        log_id("ids.googleapis.com/threat")
        AND resource.type="ids.googleapis.com/Endpoint"
        AND resource.labels.id="${var.endpoint_name}"
        AND (
          jsonPayload.alert_severity="MEDIUM"
          OR jsonPayload.alert_severity="HIGH"
          OR jsonPayload.alert_severity="CRITICAL"
        )
      EOT
      , "/\\s+/", ""
    )
    error_message = "The endpoint filter must match MEDIUM, HIGH, or CRITICAL with OR semantics and exclude LOW and INFORMATIONAL."
  }

  assert {
    condition = (
      google_monitoring_alert_policy.ids_triage.enabled &&
      google_monitoring_alert_policy.ids_triage.severity == "WARNING" &&
      google_monitoring_alert_policy.ids_triage.notification_channels == tolist(var.notification_channel_ids)
    )
    error_message = "All actionable detector severities must use the same WARNING destination."
  }

  assert {
    condition = (
      google_monitoring_alert_policy.ids_triage.conditions[0].condition_matched_log[0].label_extractors == tomap({
        threat_id         = "EXTRACT(jsonPayload.threat_id)"
        threat_name       = "EXTRACT(jsonPayload.name)"
        source_ip_address = "EXTRACT(jsonPayload.source_ip_address)"
      }) &&
      google_monitoring_alert_policy.ids_triage.alert_strategy[0].notification_rate_limit[0].period == "300s" &&
      google_monitoring_alert_policy.ids_medium.alert_strategy[0].notification_rate_limit[0].period == "300s" &&
      google_monitoring_alert_policy.ids_triage.alert_strategy[0].auto_close == "1800s"
    )
    error_message = "Changing evidence must not split activity identity; active and retired policies must retain five-minute policy-wide limits and triage must retain 30-minute auto-close."
  }

  assert {
    condition = (
      google_cloud_ids_endpoint.this.severity == "INFORMATIONAL" &&
      google_cloud_ids_endpoint.this.network == var.network_self_link &&
      google_cloud_ids_endpoint.this.location == var.zone &&
      google_compute_packet_mirroring.this.network[0].url == var.network_self_link &&
      toset([
        for subnet in google_compute_packet_mirroring.this.mirrored_resources[0].subnetworks : subnet.url
      ]) == toset(var.mirrored_subnet_self_links) &&
      google_compute_packet_mirroring.this.region == var.region &&
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "Traffic direction: unknown") &&
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "Sandbox/team attribution: unknown") &&
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "open a separate urgent incident")
    )
    error_message = "Collection, conservative attribution, and separate manual escalation must remain intact."
  }
  assert {
    condition = strcontains(
      google_monitoring_alert_policy.ids_triage.documentation[0].content,
      format(
        "](https://console.cloud.google.com/logs/query;query=%s;duration=PT1H?project=%s)",
        urlencode(<<-EOT
          log_id("ids.googleapis.com/threat")
          AND resource.type="ids.googleapis.com/Endpoint"
          AND resource.labels.id="${var.endpoint_name}"
        EOT
        ),
        urlencode(var.project_id)
      )
    )
    error_message = "Investigation must link directly to Logs Explorer with a one-hour window and the encoded IDS endpoint filter in the configured project."
  }

  assert {
    condition = alltrue([
      for id in values(var.runbook_ids) :
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "https://example.com/runbooks/${id}")
    ])
    error_message = "Every canonical runbook must render as a direct notification link."
  }

  assert {
    condition = alltrue([
      for policy in [google_monitoring_alert_policy.ids_triage, google_monitoring_alert_policy.ids_medium] :
      length(regexall("(?m)^Runbook: https://example.com/runbooks/[^\\s]+$", policy.documentation[0].content)) == 1 &&
      policy.user_labels.superserve_family == "cloud_ids" &&
      policy.user_labels.superserve_component == "vmd" &&
      policy.user_labels.superserve_failure_family == "security_finding" &&
      policy.user_labels.environment == "production"
    ])
    error_message = "Active and retired Cloud IDS policies must retain one primary runbook and reserved triage labels."
  }

  assert {
    condition = (
      !google_monitoring_alert_policy.ids_medium.enabled &&
      output.alert_policy_name == google_monitoring_alert_policy.ids_triage.name &&
      output.alert_policy_names.medium == output.alert_policy_name &&
      output.alert_policy_names.high_critical == output.alert_policy_name
    )
    error_message = "Retired policy must be disabled and historical output aliases must resolve to triage."
  }

}

run "west_triage" {
  command = apply

  variables {
    runbook_base_url           = "https://example.com/runbooks///"
    region                     = "us-west2"
    zone                       = "us-west2-a"
    endpoint_name              = "example-ids-west"
    mirrored_subnet_self_links = ["projects/example-production/regions/us-west2/subnetworks/example"]
  }

  assert {
    condition = replace(
      google_monitoring_alert_policy.ids_triage.conditions[0].condition_matched_log[0].filter,
      "/\\s+/", ""
      ) == replace(<<-EOT
        log_id("ids.googleapis.com/threat")
        AND resource.type="ids.googleapis.com/Endpoint"
        AND resource.labels.id="${var.endpoint_name}"
        AND (
          jsonPayload.alert_severity="MEDIUM"
          OR jsonPayload.alert_severity="HIGH"
          OR jsonPayload.alert_severity="CRITICAL"
        )
      EOT
      , "/\\s+/", ""
    )
    error_message = "The endpoint filter must match MEDIUM, HIGH, or CRITICAL with OR semantics and exclude LOW and INFORMATIONAL."
  }

  assert {
    condition = (
      google_monitoring_alert_policy.ids_triage.enabled &&
      google_monitoring_alert_policy.ids_triage.severity == "WARNING" &&
      google_monitoring_alert_policy.ids_triage.notification_channels == tolist(var.notification_channel_ids) &&
      strcontains(google_monitoring_alert_policy.ids_triage.conditions[0].condition_matched_log[0].filter, "resource.labels.id=\"example-ids-west\"") &&
      google_cloud_ids_endpoint.this.severity == "INFORMATIONAL" &&
      google_compute_packet_mirroring.this.region == "us-west2"
    )
    error_message = "The western region must receive the same triage behavior and its own investigation scope."
  }

  assert {
    condition = (
      google_monitoring_alert_policy.ids_triage.conditions[0].condition_matched_log[0].label_extractors == tomap({
        threat_id         = "EXTRACT(jsonPayload.threat_id)"
        threat_name       = "EXTRACT(jsonPayload.name)"
        source_ip_address = "EXTRACT(jsonPayload.source_ip_address)"
      }) &&
      google_monitoring_alert_policy.ids_triage.alert_strategy[0].notification_rate_limit[0].period == "300s" &&
      google_monitoring_alert_policy.ids_medium.alert_strategy[0].notification_rate_limit[0].period == "300s" &&
      google_monitoring_alert_policy.ids_triage.alert_strategy[0].auto_close == "1800s" &&
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "Traffic direction: unknown") &&
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "Sandbox/team attribution: unknown") &&
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "open a separate urgent incident")
    )
    error_message = "The western region must preserve stable grouping, five-minute policy-wide limits on active and retired policies, 30-minute auto-close, unknown attribution, and independent manual escalation."
  }
  assert {
    condition = strcontains(
      google_monitoring_alert_policy.ids_triage.documentation[0].content,
      format(
        "](https://console.cloud.google.com/logs/query;query=%s;duration=PT1H?project=%s)",
        urlencode(<<-EOT
          log_id("ids.googleapis.com/threat")
          AND resource.type="ids.googleapis.com/Endpoint"
          AND resource.labels.id="${var.endpoint_name}"
        EOT
        ),
        urlencode(var.project_id)
      )
    )
    error_message = "Investigation must link directly to Logs Explorer with a one-hour window and the encoded IDS endpoint filter in the configured project."
  }

  assert {
    condition = alltrue([
      for id in values(var.runbook_ids) :
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "https://example.com/runbooks/${id}")
    ])
    error_message = "Every canonical runbook must render as a direct notification link."
  }

  assert {
    condition = (
      !google_monitoring_alert_policy.ids_medium.enabled &&
      output.alert_policy_name == google_monitoring_alert_policy.ids_triage.name &&
      output.alert_policy_names.medium == output.alert_policy_name &&
      output.alert_policy_names.high_critical == output.alert_policy_name
    )
    error_message = "Retired policy must be disabled and historical output aliases must resolve to triage."
  }

}

run "missing_destination_rejected" {
  command = plan

  variables {
    notification_channel_ids = []
  }

  expect_failures = [google_monitoring_alert_policy.ids_triage]
}

run "foreign_project_destination_rejected" {
  command = plan

  variables {
    notification_channel_ids = ["projects/another-project/notificationChannels/123456"]
  }

  expect_failures = [google_monitoring_alert_policy.ids_triage]
}


run "missing_runbook_id_rejected" {
  command = plan
  variables {
    runbook_ids = {
      investigation = "example-investigation"
      correlation   = ""
      containment   = "example-containment"
    }
  }
  expect_failures = [var.runbook_ids]
}

run "whitespace_runbook_id_rejected" {
  command = plan
  variables {
    runbook_ids = {
      investigation = "example-investigation"
      correlation   = "   "
      containment   = "example-containment"
    }
  }
  expect_failures = [var.runbook_ids]
}

run "single_trailing_slash" {
  command = plan
  variables {
    runbook_base_url = "https://example.com/runbooks/"
  }
  assert {
    condition = alltrue([
      for id in values(var.runbook_ids) :
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "https://example.com/runbooks/${id}")
    ])
    error_message = "A trailing slash must produce exactly one separator before each page ID."
  }
}

run "host_only_base" {
  command = plan
  variables {
    runbook_base_url = "https://example.com"
  }
  assert {
    condition = alltrue([
      for id in values(var.runbook_ids) :
      strcontains(google_monitoring_alert_policy.ids_triage.documentation[0].content, "https://example.com/${id}")
    ])
    error_message = "A host-only HTTPS base must produce clickable links with a path separator."
  }
}

run "missing_runbook_base_rejected" {
  command = plan
  variables {
    runbook_base_url = ""
  }
  expect_failures = [var.runbook_base_url]
}

run "hostless_runbook_base_rejected" {
  command = plan
  variables {
    runbook_base_url = "https://"
  }
  expect_failures = [var.runbook_base_url]
}

run "insecure_runbook_base_rejected" {
  command = plan
  variables {
    runbook_base_url = "http://example.com/runbooks"
  }
  expect_failures = [var.runbook_base_url]
}

run "whitespace_runbook_base_rejected" {
  command = plan
  variables {
    runbook_base_url = "https://example.com/run books"
  }
  expect_failures = [var.runbook_base_url]
}

run "query_runbook_base_rejected" {
  command = plan
  variables {
    runbook_base_url = "https://example.com/runbooks?view=all"
  }
  expect_failures = [var.runbook_base_url]
}

run "fragment_runbook_base_rejected" {
  command = plan
  variables {
    runbook_base_url = "https://example.com/runbooks#section"
  }
  expect_failures = [var.runbook_base_url]
}
