terraform {
  required_version = ">= 1.7.0"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

variable "organization_id" {
  type = string
}

variable "deployment_service_accounts" {
  type = set(string)
}

# Applied by an organization IAM administrator, never by the rollout itself.
# Project-level policy readers cannot inspect policies on their ancestors.
resource "google_organization_iam_custom_role" "ancestor_policy_reader" {
  org_id      = var.organization_id
  role_id     = "controlPlaneAncestorPolicyReader"
  title       = "Control plane ancestor policy reader"
  description = "Read inherited policies and custom roles for rollout verification."
  permissions = [
    "resourcemanager.organizations.getIamPolicy",
    "resourcemanager.folders.getIamPolicy",
    "iam.roles.get",
    "iam.denypolicies.get",
    "iam.denypolicies.list",
  ]
}

resource "google_organization_iam_member" "ancestor_policy_reader" {
  for_each = var.deployment_service_accounts

  org_id = var.organization_id
  role   = google_organization_iam_custom_role.ancestor_policy_reader.name
  member = "serviceAccount:${each.value}"
}
