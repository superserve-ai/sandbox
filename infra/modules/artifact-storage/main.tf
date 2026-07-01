terraform {
  required_version = ">= 1.5.0"
}

resource "google_artifact_registry_repository" "repositories" {
  for_each = var.artifact_registry

  project       = var.project_id
  location      = var.region
  repository_id = each.value.repository_id
  format        = each.value.format
  description   = each.value.description
}

resource "google_storage_bucket" "buckets" {
  for_each = var.buckets

  project                     = var.project_id
  name                        = each.value.name
  location                    = each.value.location
  storage_class               = each.value.storage_class
  uniform_bucket_level_access = each.value.uniform_bucket_level_access
  public_access_prevention    = each.value.public_access_prevention
  force_destroy               = each.value.force_destroy
  labels                      = var.labels

  versioning {
    enabled = each.value.versioning_enabled
  }
}

locals {
  artifact_storage_contract = {
    project_id        = var.project_id
    environment       = var.environment
    region            = var.region
    artifact_registry = { for key, repo in google_artifact_registry_repository.repositories : key => repo.id }
    buckets           = { for key, bucket in google_storage_bucket.buckets : key => bucket.url }
    labels            = var.labels
  }
}
