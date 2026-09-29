mock_provider "google" {}
mock_provider "google-beta" {}

variables {
  project_id            = "example-qm-dev"
  paired_project_id     = "example-dev"
  paired_project_number = "123456789012"
  folder_id             = "123456789012"
  billing_account       = "000000-000000-000000"
  regions               = ["us-central1", "us-west2"]
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

run "active_account_boundary" {
  command = plan
  variables {
    provisioning_enabled    = true
    platform_services_ready = true
  }
  override_resource {
    target          = google_project.qm
    override_during = plan
    values          = { number = "123456789012" }
  }
  override_resource {
    target          = google_tags_tag_key.account_scope
    override_during = plan
    values          = { id = "tagKeys/100" }
  }
  override_resource {
    target          = google_tags_tag_value.account_scope
    override_during = plan
    values          = { id = "tagValues/101" }
  }
  override_resource {
    target          = google_tags_tag_key.protected
    override_during = plan
    values          = { id = "tagKeys/200" }
  }
  override_resource {
    target          = google_tags_tag_value.protected
    override_during = plan
    values          = { id = "tagValues/201" }
  }
  assert {
    condition = (
      google_tags_tag_binding.account_scope.parent == "//cloudresourcemanager.googleapis.com/projects/123456789012" &&
      google_tags_tag_binding.account_scope.tag_value == "tagValues/101" &&
      google_tags_tag_value.account_scope.parent == "tagKeys/100"
    )
    error_message = "The positive account scope must be inherited only from the QM project."
  }
  assert {
    condition = (
      google_project_iam_member.tenant_untagged["tenant_accounts"].condition[0].expression ==
      "resource.matchTagId('tagKeys/100', 'tagValues/101') && !resource.matchTagId('tagKeys/200', 'tagValues/201')"
    )
    error_message = "Account access must reject service agents/foreign accounts without the project tag and local platform/default accounts with the protected tag."
  }
  assert {
    condition = (
      google_project_iam_member.tenant_untagged["tenant_services"].condition[0].expression ==
      "!resource.matchTagId('tagKeys/200', 'tagValues/201')"
    )
    error_message = "Platform Cloud Run services must remain excluded from tenant lifecycle authority."
  }
  assert {
    condition = alltrue([for name in ["tenant_create", "tenant_accounts", "tenant_services", "tenant_secrets", "tenant_buckets", "tenant_network"] : alltrue([
      for permission in google_project_iam_custom_role.bounded[name].permissions :
      !strcontains(lower(permission), "tag") && (name == "tenant_accounts" || permission != "iam.serviceAccounts.actAs")
    ])])
    error_message = "The provisioner must not change its tag boundary or receive actAs through another tenant role."
  }
}
