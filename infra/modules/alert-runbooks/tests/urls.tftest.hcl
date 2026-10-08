variables {
  runbook_base_url = "https://example.com/runbooks"
  runbook_ids = {
    lifecycle_latency      = "latency-page"
    lifecycle_failure      = "failure-page"
    backup_pipeline        = "backup-page"
    backup_coverage        = "coverage-page"
    host_disk              = "disk-page"
    host_cpu               = "cpu-page"
    host_maintenance       = "maintenance-page"
    vmd_launch             = "launch-page"
    vmd_network            = "network-page"
    host_logging_export    = "host-logging-export-page"
    host_logging_lag       = "host-logging-lag-page"
    host_logging_heartbeat = "host-logging-heartbeat-page"
  }
}

run "build_direct_urls" {
  command = plan
  assert {
    condition = alltrue([
      for key, id in var.runbook_ids : output.urls[key] == "https://example.com/runbooks/${id}"
    ])
    error_message = "Every procedure must link to its own page under the configured base."
  }
}

run "normalize_trailing_slashes" {
  command = plan
  variables {
    runbook_base_url = "https://example.com/runbooks///"
  }
  assert {
    condition     = output.urls["host_cpu"] == "https://example.com/runbooks/cpu-page"
    error_message = "Trailing slashes must not produce duplicate path separators."
  }
}

run "reject_missing_base" {
  command = plan
  variables {
    runbook_base_url = ""
  }
  expect_failures = [var.runbook_base_url]
}

run "reject_query_in_base" {
  command = plan
  variables {
    runbook_base_url = "https://example.com/runbooks?query=value"
  }
  expect_failures = [var.runbook_base_url]
}

run "reject_path_in_page_id" {
  command = plan
  variables {
    runbook_ids = { host_cpu = "../another-page" }
  }
  expect_failures = [var.runbook_ids]
}
