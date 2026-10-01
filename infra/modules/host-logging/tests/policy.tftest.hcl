run "host_logging_contract" {
  command = plan

  variables {
    project_id      = "example-project"
    zone            = "us-central1-a"
    environment     = "staging"
    region          = "us-central1"
    assignment_name = "example-host-logging"
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
    condition = resource.google_os_config_os_policy_assignment.host_logging.os_policies[0].resource_groups[0].resources[0].file[0].state == "PRESENT"
    error_message = "the candidate configuration must be a PRESENT file resource"
  }

  assert {
    condition = resource.google_os_config_os_policy_assignment.host_logging.os_policies[0].resource_groups[0].resources[0].file[0].path == "/var/lib/superserve/host-logging/config.yaml.candidate"
    error_message = "candidate path must remain outside the active configuration"
  }

  assert {
    condition = resource.google_os_config_os_policy_assignment.host_logging.os_policies[0].resource_groups[0].resources[0].file[0].permissions == "0644"
    error_message = "candidate permissions must be enforced at the file-resource level"
  }

  assert {
    condition = resource.google_os_config_os_policy_assignment.host_logging.os_policies[0].resource_groups[0].resources[0].file[0].file[0].gcs[0].generation != null
    error_message = "candidate source must retain its generation-pinned GCS object"
  }

  assert {
    condition = resource.google_os_config_os_policy_assignment.host_logging.rollout[0].mode == null
    error_message = "unsupported rollout.mode must not be rendered"
  }
}
