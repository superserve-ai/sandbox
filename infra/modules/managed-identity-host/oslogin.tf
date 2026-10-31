# The instance retains blanket metadata protection. Reconcile the OS Login policy
# against fresh metadata, including when refresh observes out-of-band drift.
resource "terraform_data" "oslogin_2fa" {
  count = contains(keys(var.metadata), "enable-oslogin-2fa") ? 1 : 0

  triggers_replace = {
    instance_id = google_compute_instance.this.instance_id
    desired     = var.metadata["enable-oslogin-2fa"]
    observed    = { for key in ["enable-oslogin", "enable-oslogin-2fa"] : key => lookup(google_compute_instance.this.metadata, key, null) }
    script      = filesha256("${path.module}/../../scripts/oslogin-2fa.py")
  }

  lifecycle {
    precondition {
      condition     = contains(["TRUE", "FALSE"], var.metadata["enable-oslogin-2fa"])
      error_message = "OS Login 2FA must be explicitly TRUE or FALSE."
    }
  }

  provisioner "local-exec" {
    command = "python3 \"${path.module}/../../scripts/oslogin-2fa.py\""
    environment = {
      OSLOGIN_2FA_CONFIG = jsonencode({
        project_id    = var.project_id
        zone          = var.zone
        instance_name = var.instance_name
        instance_id   = google_compute_instance.this.instance_id
        value         = var.metadata["enable-oslogin-2fa"]
      })
    }
  }
}
