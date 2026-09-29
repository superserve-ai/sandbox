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

run "federation_workflow_identity_boundary" {
  command = plan

  override_resource {
    target          = google_project.qm
    override_during = plan
    values          = { number = "123456789012" }
  }

  assert {
    condition = (
      google_iam_workload_identity_pool.deploy.workload_identity_pool_id == "qm-deploy" &&
      google_iam_workload_identity_pool.application_deploy.workload_identity_pool_id == "qm-application-deploy" &&
      google_iam_workload_identity_pool_provider.github.workload_identity_pool_id == google_iam_workload_identity_pool.deploy.workload_identity_pool_id &&
      google_iam_workload_identity_pool_provider.github_application.workload_identity_pool_id == google_iam_workload_identity_pool.application_deploy.workload_identity_pool_id
    )
    error_message = "Infrastructure and application workflows must use separate workload identity pools."
  }
  assert {
    condition = (
      strcontains(google_iam_workload_identity_pool_provider.github.attribute_condition, "workflow_ref == 'example-team/example-repo/.github/workflows/terraform-cd.yml@refs/heads/main'") &&
      !strcontains(google_iam_workload_identity_pool_provider.github.attribute_condition, "deploy-qm-api.yml") &&
      strcontains(google_iam_workload_identity_pool_provider.github_application.attribute_condition, "workflow_ref == 'example-team/example-repo/.github/workflows/deploy-qm-api.yml@refs/heads/main'") &&
      !strcontains(google_iam_workload_identity_pool_provider.github_application.attribute_condition, "terraform-cd.yml")
    )
    error_message = "Each WIF provider must admit only its intended GitHub workflow."
  }
  assert {
    condition = (
      google_service_account_iam_member.federation["qm-infra"].member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/qm-deploy/subject/repo:example-team/example-repo:environment:example-qm-dev-qm-infra" &&
      google_service_account_iam_member.federation["qm-api-deployer"].member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/qm-application-deploy/subject/repo:example-team/example-repo:environment:example-qm-dev-qm-api-deployer" &&
      google_service_account_iam_member.federation["qm-provisioner-deployer"].member == "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/qm-application-deploy/subject/repo:example-team/example-repo:environment:example-qm-dev-qm-provisioner-deployer"
    )
    error_message = "Each deploy identity must bind to the pool for its intended workflow."
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
