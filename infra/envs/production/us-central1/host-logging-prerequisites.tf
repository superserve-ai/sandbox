resource "google_project_iam_member" "cd_vm_manager_features" {
  project = local.project_id
  role    = "roles/osconfig.projectFeatureSettingsEditor"
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"
}

# The pinned provider lacks projectFeatureSettings. Do not downgrade on destroy.
# Remote drift requires an explicit replacement of this adapter resource.
resource "terraform_data" "host_logging_project_features" {
  triggers_replace = [local.project_id, "OSCONFIG_C", filesha256("${path.module}/../../../modules/host-logging/prerequisites.py")]
  provisioner "local-exec" {
    command = "python3 \"${path.module}/../../../modules/host-logging/prerequisites.py\""
    environment = {
      HOST_LOGGING_PREREQUISITE = jsonencode({ phase = "project", project_id = local.project_id })
    }
  }
  depends_on = [google_project_service.host_log_os_config, google_project_iam_member.cd_vm_manager_features]
}

resource "google_project_iam_custom_role" "cd_heartbeat_view_iam" {
  project     = local.project_id
  role_id     = "hostLoggingViewIam"
  title       = "Host logging view IAM"
  description = "Manage the dedicated host logging heartbeat view IAM policy."
  permissions = ["logging.views.getIamPolicy", "logging.views.setIamPolicy"]
}

resource "google_project_iam_member" "cd_heartbeat_view_iam" {
  project = local.project_id
  role    = google_project_iam_custom_role.cd_heartbeat_view_iam.name
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"
  condition {
    title       = "host-logging-heartbeat-view-only"
    description = "Manage IAM only on the east host logging heartbeat view."
    expression  = "resource.type == 'logging.googleapis.com/LogView' && resource.name == 'projects/${local.project_id}/locations/global/buckets/_Default/views/superserve-otel-host-logging-us-east4-a-heartbeats'"
  }
}
