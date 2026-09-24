mock_provider "google" {}

variables {
  organization_id = "123456789012"
  deployment_service_accounts = [
    "deployer@example-staging.iam.gserviceaccount.com",
    "deployer@example-production.iam.gserviceaccount.com",
  ]
}

run "ancestor_read_only" {
  command = plan
  assert {
    condition = (
      toset(google_organization_iam_custom_role.ancestor_policy_reader.permissions) == toset([
        "resourcemanager.organizations.getIamPolicy", "iam.roles.get",
      ]) &&
      length(google_organization_iam_member.ancestor_policy_reader) == 2
    )
    error_message = "Organization inspection must not grant descendant folder/deny-policy reads, payload access, or mutation."
  }
}
