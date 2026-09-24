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
# Project-level readers cannot inspect their organization policy or custom roles.
resource "google_organization_iam_custom_role" "ancestor_policy_reader" {
  org_id      = var.organization_id
  role_id     = "controlPlaneAncestorPolicyReader"
  title       = "Control plane organization policy reader"
  description = "Read the organization policy and custom-role definitions for rollout verification."
  # Role definitions must be readable, including this custom role itself.
  permissions = [
    "resourcemanager.organizations.getIamPolicy",
    "iam.roles.get",
  ]
}

resource "google_organization_iam_member" "ancestor_policy_reader" {
  for_each = var.deployment_service_accounts

  org_id = var.organization_id
  role   = google_organization_iam_custom_role.ancestor_policy_reader.name
  member = "serviceAccount:${each.value}"
}
