mock_provider "google-beta" {}

variables {
  sandbox_data_disk         = "projects/example-project/zones/us-central1-a/disks/example-data"
  project_id                = "example-project"
  environment               = "staging"
  region                    = "us-central1"
  zone                      = "us-central1-a"
  instance_name             = "superserve-vmd-staging-2"
  machine_type              = "n2-standard-32"
  subnet                    = "projects/example-project/regions/us-central1/subnetworks/example"
  service_account_email     = "runtime@example-project.iam.gserviceaccount.com"
  boot_disk_image           = "projects/example-project/global/images/example"
  managed_workload_identity = "example.test/ns/vmd/sa/peer"
  labels = {
    component      = "vmd-staging-standby"
    sandbox_status = "provisioning"
  }
}

run "creation_request" {
  command = plan
  assert {
    condition     = google_compute_instance.this.workload_identity_config[0].identity == var.managed_workload_identity && google_compute_instance.this.workload_identity_config[0].identity_certificate_enabled
    error_message = "MWI identity and certificates must be enabled in the VM resource."
  }
  assert {
    condition     = google_compute_instance.this.labels.component == "vmd-staging-standby" && google_compute_instance.this.labels.sandbox_status == "provisioning"
    error_message = "Host 2 must remain excluded from serving discovery."
  }
  assert {
    condition     = google_compute_instance.this.service_account[0].email == var.service_account_email && google_compute_instance.this.boot_disk[0].auto_delete
    error_message = "Keep the dedicated runtime account and disposable boot disk."
  }
}

run "preserved_disk_attachment" {
  command = plan
  assert {
    condition     = google_compute_instance.this.attached_disk[0].source == var.sandbox_data_disk && google_compute_instance.this.attached_disk[0].device_name == "superserve-sandbox-data"
    error_message = "VM creation must reattach the existing independent data disk."
  }
}

run "admission_provisioning" {
  command = plan
  variables { labels = { component = "vmd", sandbox_status = "provisioning" } }
}

run "admission_ready" {
  command = plan
  variables { labels = { component = "vmd", sandbox_status = "ready" } }
}

run "reject_other_host" {
  command = plan
  variables { instance_name = "other-host" }
  expect_failures = [google_compute_instance.this]
}

run "reject_other_environment" {
  command = plan
  variables { environment = "production" }
  expect_failures = [google_compute_instance.this]
}
