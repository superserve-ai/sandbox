# CD manages the dedicated policy and waits for its rollout operations.
resource "google_project_iam_member" "cd_host_logging" {
  project = local.project_id
  role    = "roles/osconfig.osPolicyAssignmentAdmin"
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"
}

# us-east4 still carries a legacy ops-agent policy, so the module also binds a
# reader on the cutover heartbeat log view. Setting IAM on a log view is not
# covered by the policy-assignment role above, and the apply fails 403 without
# this. Staging never hits it: that root sets no legacy_policy_name.
resource "google_project_iam_member" "cd_host_logging_views" {
  project = local.project_id
  role    = "roles/logging.admin"
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"
}

# Enabling the OS Config API is not the same as turning VM Manager on for the
# project: the zonal API answers reads either way, but a policy assignment is
# refused 400 until full VM Manager is enabled, which is this metadata key.
resource "google_compute_project_metadata_item" "enable_osconfig" {
  project = local.project_id
  key     = "enable-osconfig"
  value   = "TRUE"

  depends_on = [google_project_service.compute, google_project_service.host_log_os_config]
}
