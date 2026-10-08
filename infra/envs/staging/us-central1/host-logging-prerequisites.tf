# Running hosts ignore the metadata map to preserve externally managed keys.
# Reconcile only this key, with a fresh fingerprint and immutable VM identity.
resource "terraform_data" "host_logging_enablement" {
  for_each = {
    sandbox_host = {
      instance_name = module.sandbox_host.instance_name
      instance_id   = module.sandbox_host.instance_id
    }
    sandbox_host_b = {
      instance_name = module.sandbox_host_b.instance_name
      instance_id   = module.sandbox_host_b.instance_id
    }
  }
  # Replacement VMs already receive this key in their creation metadata. Keep
  # this existing-host repair stable across VM IDs so provisioning stays scoped.
  triggers_replace = [local.project_id, local.zone, each.value.instance_name, filesha256("${path.module}/../../../modules/host-logging/prerequisites.py")]
  provisioner "local-exec" {
    command = "python3 \"${path.module}/../../../modules/host-logging/prerequisites.py\""
    environment = {
      HOST_LOGGING_PREREQUISITE = jsonencode(merge(each.value, {
        phase      = "instance"
        project_id = local.project_id
        zone       = local.zone
      }))
    }
  }
  depends_on = [google_project_service.host_log_os_config]
}
