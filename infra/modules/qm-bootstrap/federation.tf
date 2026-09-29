resource "google_iam_workload_identity_pool" "deploy" {
  project                   = google_project.qm.project_id
  workload_identity_pool_id = "qm-deploy"
  depends_on                = [google_project_service.enabled]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = google_project.qm.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.deploy.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.repository_id" = "assertion.repository_id"
  }
  attribute_condition = "assertion.repository_owner_id == '${var.github.owner_id}' && assertion.repository_id == '${var.github.repository_id}' && assertion.ref == 'refs/heads/main' && assertion.workflow_ref in ['${var.github.repository}/.github/workflows/terraform-cd.yml@refs/heads/main', '${var.github.repository}/.github/workflows/deploy-qm-api.yml@refs/heads/main']"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "federation" {
  for_each           = toset(["qm-infra", "qm-api-deployer", "qm-provisioner-deployer"])
  service_account_id = google_service_account.platform[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.deploy.name}/subject/repo:${var.github.repository}:environment:${var.project_id}-${each.key}"
}
