# CD manages the dedicated policy and waits for its rollout operations.
resource "google_project_iam_member" "cd_host_logging" {
  project = local.project_id
  role    = "roles/osconfig.osPolicyAssignmentAdmin"
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"
}
