mock_provider "google" {}
mock_provider "google-beta" {}

variables {
  project_id        = "example-qm-dev"
  paired_project_id = "example-dev"
  folder_id         = "123456789012"
  billing_account   = "000000-000000-000000"
  regions           = ["us-central1", "us-west2"]
  github = {
    owner_id      = "12345"
    repository_id = "67890"
    repository    = "example-team/example-repo"
  }
  registry = {
    location   = "us-central1"
    repository = "example-images"
  }
}

run "dormant_authority" {
  command = plan
  assert {
    condition = (
      length(google_project_iam_member.tenant_create) == 0 &&
      length(google_project_iam_member.tenant_untagged) == 0 &&
      length(google_cloud_run_v2_service_iam_member.deploy) == 0
    )
    error_message = "An initial bootstrap must not enable provisioning or assume platform services exist."
  }
  assert {
    condition = alltrue([for permission in google_project_iam_custom_role.bounded["network"].permissions :
      !strcontains(permission, "setIamPolicy") &&
      !startswith(permission, "iam.") &&
      !startswith(permission, "secretmanager.") &&
      !startswith(permission, "run.") &&
      !startswith(permission, "resourcemanager.projects.create")
    ])
    error_message = "Routine network infrastructure must not gain IAM, secret, runtime deployment, or project creation authority."
  }
  assert {
    condition = alltrue([for name in ["tenant_create", "tenant_accounts"] : alltrue([
      for permission in google_project_iam_custom_role.bounded[name].permissions :
      !strcontains(permission, "setIamPolicy") && !strcontains(permission, "getAccessToken") && !strcontains(permission, "serviceAccountKeys")
    ])])
    error_message = "Tenant identity management must not mint keys/tokens or mutate service account IAM."
  }
  assert {
    condition = (
      contains(keys(google_tags_tag_binding.account), "qm-api") &&
      contains(keys(google_tags_tag_binding.account), "qm-provisioner") &&
      contains(keys(google_tags_tag_binding.account), "qm-infra") &&
      contains(keys(google_tags_tag_binding.account), "compute")
    )
    error_message = "Every locally owned platform/default identity must be protected before the provisioner receives authority."
  }
}

run "activation_requires_platform_services" {
  command = plan
  variables {
    provisioning_enabled = true
  }
  expect_failures = [google_project_iam_member.tenant_create]
}
