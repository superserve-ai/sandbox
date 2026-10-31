mock_provider "google" {}

variables {
  project_id            = "example-project"
  environment           = "staging"
  region                = "us-central1"
  zone                  = "us-central1-a"
  instance_name         = "example-vmd-2"
  machine_type          = "n2-standard-32"
  subnet                = "projects/example-project/regions/us-central1/subnetworks/example"
  service_account_email = "runtime@example-project.iam.gserviceaccount.com"
  boot_disk_image       = "projects/example-project/global/images/example"
}

run "operator_managed_power_state" {
  command = plan
  variables {
    desired_status = null
  }
  assert {
    condition     = var.desired_status == null
    error_message = "Null must remain valid for operator-managed power state."
  }
}

run "running_power_state" {
  command = plan
  variables {
    desired_status = "RUNNING"
  }
  assert {
    condition     = google_compute_instance.this.desired_status == "RUNNING"
    error_message = "The requested running state must reach the VM request."
  }
}

run "terminated_power_state" {
  command = plan
  variables {
    desired_status = "TERMINATED"
  }
  assert {
    condition     = google_compute_instance.this.desired_status == "TERMINATED"
    error_message = "The requested terminated state must reach the VM request."
  }
}

run "invalid_power_state" {
  command = plan
  variables {
    desired_status = "INVALID"
  }
  expect_failures = [var.desired_status]
}

run "reassert_identity_before_caller_boot_commands" {
  command = plan
  assert {
    condition = alltrue([
      startswith(trimspace(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0]), "set -eu\n"),
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "systemctl stop \"$unit\""),
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "superserve-vmd.socket.d/10-identity-required.conf"),
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "ConditionPathExists=/etc/sandbox/host-identity.json"),
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "ConditionPathExists=/etc/sandbox/host-identity.env"),
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "Environment=HOST_IDENTITY_REQUIRED=1"),
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "ExecStartPre=/usr/bin/test -s /etc/sandbox/host-identity.json"),
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "EnvironmentFile=/etc/sandbox/host-identity.env"),
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "systemctl daemon-reload"),
    ])
    error_message = "Provisioning must reassert the baked identity gate before caller boot commands."
  }
}

run "preserve_caller_cloud_config" {
  command = plan
  variables {
    metadata = {
      user-data      = <<-EOT
        #cloud-config
        bootcmd:
          - echo caller-bootstrap
        write_files:
          - path: /etc/example-config
            content: example
      EOT
      startup-script = "#!/bin/bash\necho caller-startup"
    }
  }
  assert {
    condition = (
      length(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd) == 2 &&
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "10-identity-required.conf") &&
      yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[1] == "echo caller-bootstrap" &&
      yamldecode(google_compute_instance.this.metadata["user-data"]).write_files[0].path == "/etc/example-config" &&
      endswith(google_compute_instance.this.metadata["startup-script"], "echo caller-startup")
    )
    error_message = "Require identity before caller boot commands while preserving cloud-config and startup settings."
  }
}

run "forward_boot_image_unchanged" {
  command = plan
  assert {
    condition     = google_compute_instance.this.boot_disk[0].initialize_params[0].image == var.boot_disk_image
    error_message = "The VM request must use the CI/CD image reference unchanged."
  }
}

run "provisioning_hold" {
  command = plan
  variables {
    provisioning = true
    labels       = { component = "vmd", sandbox_status = "ready" }
    metadata = {
      user-data      = "#cloud-config\nbootcmd:\n  - echo unsafe-caller\n"
      startup-script = "echo unsafe-startup"
    }
  }
  assert {
    condition = (
      google_compute_instance.this.labels["component"] == "vmd-provisioning" &&
      google_compute_instance.this.labels["sandbox_status"] == "provisioning" &&
      strcontains(google_compute_instance.this.metadata["user-data"], "provisioning-hold") &&
      strcontains(google_compute_instance.this.metadata["user-data"], "unsafe-caller") &&
      strcontains(google_compute_instance.this.metadata["startup-script"], "unsafe-startup") &&
      strcontains(google_compute_instance.this.metadata["startup-script"], "if [ -f /etc/sandbox/provisioning-complete ]; then") &&
      strcontains(google_compute_instance.this.metadata["startup-script"], "ConditionPathExists=!/etc/sandbox/provisioning-hold")
    )
    error_message = "Provisioning must exclude the host and hold both service and socket before runtime handoff."
  }
}

run "restore_boot_preparation_after_release" {
  command = plan
  variables {
    provisioning = true
    metadata = {
      user-data = "#cloud-config\nbootcmd:\n  - echo caller-bootstrap\n  - [echo, 'two words']\n"
    }
  }
  assert {
    condition = (
      length(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd) == 4 &&
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[0], "10-identity-required.conf") &&
      strcontains(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[1], "if [ ! -f /etc/sandbox/provisioning-complete ]; then") &&
      jsonencode(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[2]) == jsonencode([
        "sh", "-c", "if [ -f /etc/sandbox/provisioning-complete ]; then exec \"$@\"; fi", "provisioning-boot", "sh", "-c", "echo caller-bootstrap"
      ]) &&
      jsonencode(yamldecode(google_compute_instance.this.metadata["user-data"]).bootcmd[3]) == jsonencode([
        "sh", "-c", "if [ -f /etc/sandbox/provisioning-complete ]; then exec \"$@\"; fi", "provisioning-boot", "echo", "two words"
      ]) &&
      endswith(google_compute_instance.this.metadata["startup-script"], "then\n:\n:\nfi")
    )
    error_message = "Persist caller shell and argv boot commands behind explicit release, with identity gates first and a valid empty startup script."
  }
}
