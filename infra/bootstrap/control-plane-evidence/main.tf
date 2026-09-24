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

provider "google" {
  project = var.project_id
}

variable "project_id" {
  type = string
}

variable "deployment_service_account" {
  type = string
}

variable "retention_days" {
  description = "Minimum evidence retention and age at which lifecycle deletion becomes eligible."
  type        = number
  default     = 90
  validation {
    condition     = var.retention_days >= 1 && floor(var.retention_days) == var.retention_days
    error_message = "Retention must be a positive whole number of days."
  }
}

# Separate state lets the rollout create its evidence store before any
# service-account transition, even while ordinary Terraform CD is blocked.
resource "google_storage_bucket" "evidence" {
  project                     = var.project_id
  name                        = "${var.project_id}-control-plane-evidence"
  location                    = "US-CENTRAL1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels = {
    managed_by = "terraform"
    purpose    = "control-plane-evidence"
  }

  # Google-managed encryption at rest; retention is deliberately not locked.
  retention_policy {
    retention_period = var.retention_days * 86400
  }
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = var.retention_days
    }
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "upload" {
  # gcloud cp discovers destination objects before creating them.
  for_each = toset(["roles/storage.objectCreator", "roles/storage.objectViewer"])

  bucket = google_storage_bucket.evidence.name
  role   = each.value
  member = "serviceAccount:${var.deployment_service_account}"
}

output "bucket_name" {
  value = google_storage_bucket.evidence.name
}
