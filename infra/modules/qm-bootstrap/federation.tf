locals {
  github_workflow_refs = {
    terraform     = "${var.github.repository}/.github/workflows/terraform-cd.yml@refs/heads/main"
    deploy_qm_api = "${var.github.repository}/.github/workflows/deploy-qm-api.yml@refs/heads/main"
  }
}

# Keep infrastructure and application deployment federation in separate pools.
# The pool is part of the IAM principal, so a token minted by one workflow can
# never satisfy the service-account binding for the other workflow, even when
# both jobs use the same GitHub environment naming convention.
resource "google_iam_workload_identity_pool" "deploy" {
  project                   = google_project.qm.project_id
  workload_identity_pool_id = "qm-deploy"
  depends_on                = [google_project_service.enabled]
}

resource "google_iam_workload_identity_pool" "application_deploy" {
  project                   = google_project.qm.project_id
  workload_identity_pool_id = "qm-application-deploy"
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
  attribute_condition = "assertion.repository_owner_id == '${var.github.owner_id}' && assertion.repository_id == '${var.github.repository_id}' && assertion.ref == 'refs/heads/main' && assertion.workflow_ref == '${local.github_workflow_refs.terraform}'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_iam_workload_identity_pool_provider" "github_application" {
  project                            = google_project.qm.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.application_deploy.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.repository_id" = "assertion.repository_id"
  }
  attribute_condition = "assertion.repository_owner_id == '${var.github.owner_id}' && assertion.repository_id == '${var.github.repository_id}' && assertion.ref == 'refs/heads/main' && assertion.workflow_ref == '${local.github_workflow_refs.deploy_qm_api}'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "federation" {
  for_each           = toset(["qm-infra", "qm-api-deployer", "qm-provisioner-deployer"])
  service_account_id = google_service_account.platform[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  member = format(
    "principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/repo:%s:environment:%s-%s",
    google_project.qm.number,
    each.key == "qm-infra" ? google_iam_workload_identity_pool.deploy.workload_identity_pool_id : google_iam_workload_identity_pool.application_deploy.workload_identity_pool_id,
    var.github.repository,
    var.project_id,
    each.key,
  )
}
