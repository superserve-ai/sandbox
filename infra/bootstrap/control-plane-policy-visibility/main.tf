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

# Cleanup-only root: an administrator uses the original backend to revoke any
# grants created by an earlier rollout version. It creates no new permissions.
removed {
  from = google_organization_iam_member.ancestor_policy_reader
  lifecycle {
    destroy = true
  }
}

removed {
  from = google_organization_iam_custom_role.ancestor_policy_reader
  lifecycle {
    destroy = true
  }
}
