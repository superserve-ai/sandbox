mock_provider "google" {}

run "host_logging_contract" {
  command = apply

  variables {
    otel_memory_limit_mb = 256
    project_id           = "example-project"
    zone                 = "us-central1-a"
    environment          = "staging"
    region               = "us-central1"
    assignment_name      = "example-host-logging"
    selector_labels = {
      application = "sandbox-host"
      environment = "staging"
    }
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

  assert {
    condition     = google_storage_bucket.host_logging_artifacts.name == "ss-host-logging-${substr(sha256("example-project/staging/us-central1"), 0, 32)}"
    error_message = "Artifact bucket identity must be stable and scoped to project, environment, and region."
  }

  assert {
    condition     = strcontains(google_storage_bucket_object.otel_config.content, "limit_mib: 192") && strcontains(google_storage_bucket_object.otel_config.content, "spike_limit_mib: 32") && strcontains(google_storage_bucket_object.otel_service.content, "MemoryHigh=224M") && strcontains(google_storage_bucket_object.otel_service.content, "MemoryMax=256M") && strcontains(google_storage_bucket_object.otel_service.content, "GOMEMLIMIT=192MiB")
    error_message = "Collector limiter and service thresholds must scale with the configured memory ceiling."
  }

  assert {
    condition     = resource.google_os_config_os_policy_assignment.host_logging.os_policies[0].resource_groups[0].resources[1].file[0].state == "CONTENTS_MATCH"
    error_message = "the candidate configuration must enforce candidate contents"
  }

  assert {
    condition     = resource.google_os_config_os_policy_assignment.host_logging.os_policies[0].resource_groups[0].resources[1].file[0].path == "/var/lib/superserve/host-logging/otel-logs.yaml.candidate"
    error_message = "candidate path must remain outside the active configuration"
  }

  assert {
    condition     = resource.google_os_config_os_policy_assignment.host_logging.os_policies[0].resource_groups[0].resources[1].file[0].file[0].gcs[0].generation != null
    error_message = "candidate source must retain its generation-pinned GCS object"
  }

}

run "host_logging_deployment_plan" {
  command = plan
  variables {
    project_id      = "example-project"
    zone            = "us-central1-a"
    environment     = "staging"
    region          = "us-central1"
    assignment_name = "example-host-logging"
    enrolled_hosts = {
      pilot = {
        instance_name         = "example-vmd-1"
        instance_id           = "123"
        host_id               = "example-vmd-1"
        incarnation           = "incarnation-a"
        service_account_email = "vmd@example-project.iam.gserviceaccount.com"
      }
    }
  }
}

run "artifact_bucket_other_project" {
  command = plan
  variables {
    project_id      = "another-project"
    zone            = "us-central1-a"
    environment     = "staging"
    region          = "us-central1"
    assignment_name = "example-host-logging"
    enrolled_hosts  = {}
  }

  assert {
    condition     = google_storage_bucket.host_logging_artifacts.name != "ss-host-logging-${substr(sha256("example-project/staging/us-central1"), 0, 32)}" && length(google_storage_bucket.host_logging_artifacts.name) <= 63
    error_message = "Identical regional deployments in different projects must not share the global bucket name."
  }
}
