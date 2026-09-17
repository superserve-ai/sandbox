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
