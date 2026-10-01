mock_provider "google" {}
variables {
  project_id         = "example-project"
  zone               = "us-central1-a"
  environment        = "staging"
  region             = "us-central1"
  assignment_name    = "example-host-logging"
  legacy_policy_name = "example-installation-only-policy"
  enrolled_hosts = {
    pilot = {
      instance_name         = "example-vmd-1"
      instance_id           = "123"
      host_id               = "example-vmd-1"
      incarnation           = "inc-1"
      service_account_email = "vmd@example-project.iam.gserviceaccount.com"
    }
  }
}
run "preserve_without_guessing_baseline" {
  command = plan
  assert {
    condition     = jsondecode(google_storage_bucket_object.legacy_migration_target[0].content).baseline == null && strcontains(google_storage_bucket_object.reconcile_script.content, "legacy_enabled=1")
    error_message = "Preserve must stop the new writer without inventing a legacy config."
  }
}
run "missing_audit_fails" {
  command = plan
  variables { legacy_transition = "overlap" }
  expect_failures = [terraform_data.legacy_migration]
}
run "replacement_without_receipt_fails" {
  command = plan
  variables {
    legacy_transition = "retire"
    legacy_migration = {
      baseline_user_config  = ""
      overlap_deadline      = "2026-01-01T00:00:00Z"
      verified_instance_ids = ["old-instance"]
      drained_instance_ids  = ["old-instance"]
    }
  }
  expect_failures = [terraform_data.legacy_migration]
}
run "retirement_preserves_metrics_and_disables_all_log_pipelines" {
  command = plan
  variables {
    legacy_transition = "retire"
    legacy_migration = {
      baseline_user_config  = "metrics:\n  service:\n    pipelines:\n      custom:\n        receivers: [hostmetrics]\nlogging:\n  receivers:\n    custom:\n      type: files\n      include_paths: [/var/log/example.log]\n  service:\n    pipelines:\n      extra:\n        receivers: [custom]\n      default_pipeline:\n        receivers: [syslog]\n        processors: [exclude_logs]\n"
      overlap_deadline      = "2026-01-01T00:00:00Z"
      verified_instance_ids = ["123"]
      drained_instance_ids  = ["123"]
    }
  }
  assert {
    condition     = jsondecode(jsondecode(google_storage_bucket_object.legacy_migration_target[0].content).retired).metrics.service.pipelines.custom.receivers == ["hostmetrics"] && jsondecode(jsondecode(google_storage_bucket_object.legacy_migration_target[0].content).retired).logging.service.pipelines.extra.receivers == [] && jsondecode(jsondecode(google_storage_bucket_object.legacy_migration_target[0].content).retired).logging.service.pipelines.default_pipeline == { receivers = [] } && jsondecode(jsondecode(google_storage_bucket_object.legacy_migration_target[0].content).retired).logging.receivers.custom.include_paths == ["/var/log/example.log"]
    error_message = "Retirement must disable every log pipeline and must not mutate metrics."
  }
}

run "first_install_identity_is_bound_to_target" {
  command = plan
  variables {
    legacy_transition = "overlap"
    legacy_migration = {
      baseline_user_config    = "{}"
      overlap_deadline        = "2026-01-01T00:00:00Z"
      initialize_instance_ids = ["123"]
      verified_instance_ids   = []
      drained_instance_ids    = []
    }
  }
  assert {
    condition     = jsondecode(google_storage_bucket_object.legacy_migration_target[0].content).initialize_instance_ids == ["123"]
    error_message = "First-install authorization must be included in the exact migration target."
  }
}
