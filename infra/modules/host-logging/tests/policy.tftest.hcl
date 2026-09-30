run "host_logging_contract" {
  command = plan

  variables {
    project_id  = "example-project"
    zone        = "us-central1-a"
    environment = "staging"
    region      = "us-central1"
    assignment_name = "example-host-logging"
    selector_labels = {
      application = "sandbox-host"
      environment = "staging"
    }
    enrolled_hosts = {
      pilot = {
        instance_name        = "example-vmd-1"
        instance_id          = "123"
        host_id              = "example-vmd-1"
        incarnation          = "inc-1"
        service_account_email = "vmd@example-project.iam.gserviceaccount.com"
      }
    }
  }
}
