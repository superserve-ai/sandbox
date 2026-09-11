# Temporary bootstrap permissions for the staging Host 2 identity migration.
# These let the existing GitHub Actions deployment principal manage the
# Private CA pool and trust-domain workload identity resources required by
# SS-329. This file lives only on the temporary migration branch.
resource "google_project_iam_member" "host2_migration_cd_privateca_admin" {
  project = local.project_id
  role    = "roles/privateca.admin"
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "host2_migration_cd_workload_identity_pool_admin" {
  project = local.project_id
  role    = "roles/iam.workloadIdentityPoolAdmin"
  member  = "serviceAccount:superserve-github-actions@${local.project_id}.iam.gserviceaccount.com"
}
