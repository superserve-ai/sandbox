terraform {
  required_version = ">= 1.5.0"
}

# Durability tier for host-local VM artifacts (sandbox snapshots, template
# builds). The bucket is the only copy of customer data that survives the loss
# of a host's ephemeral local SSD, so it is deliberately hard to destroy:
# prevent_destroy, versioning, soft delete, and no delete permission for the
# writers that feed it.
resource "google_storage_bucket" "backup" {
  project                     = var.project_id
  name                        = var.bucket_name
  location                    = var.location
  storage_class               = var.storage_class
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = var.labels

  versioning {
    enabled = true
  }

  # Safety net under bugs in the control-plane GC job: even a permitted delete
  # is recoverable for this window.
  soft_delete_policy {
    retention_duration_seconds = var.soft_delete_retention_seconds
  }

  # Bound versioning growth. Live-object deletion is owned by the control-plane
  # GC job (which knows artifact deletion times from the database); lifecycle
  # only reaps versions that have already been superseded or deleted.
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      days_since_noncurrent_time = var.noncurrent_version_retention_days
    }
  }

  # Reap leftovers of resumable uploads abandoned mid-flight (host crash,
  # vmd restart) — these are invisible in listings but billed.
  lifecycle_rule {
    action {
      type = "AbortIncompleteMultipartUpload"
    }
    condition {
      age = 7
    }
  }

  # CMEK note: the shared credentials KEK lives in us-central1 and a bucket's
  # default KMS key must match the bucket's location, so regional backup
  # buckets outside us-central1 cannot use it. Left null (Google-managed
  # encryption) until a per-region key exists.
  dynamic "encryption" {
    for_each = var.kms_key_name != null ? [var.kms_key_name] : []
    content {
      default_kms_key_name = encryption.value
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Writers (the vmd host SA) can create objects and nothing else: objectCreator
# carries storage.objects.create only. No read (a compromised host or API
# cannot exfiltrate backups, its own cell's or another's, since the runtime
# identity is currently shared across cells), no delete, and no overwrite
# (replacing an existing object name also requires storage.objects.delete).
# Uploader idempotency therefore cannot rely on get/list: uploads use an
# ifGenerationMatch=0 precondition, and a 412 means the object already exists,
# which the uploader treats as success.
resource "google_storage_bucket_iam_member" "writer_create" {
  for_each = toset(var.writer_members)

  bucket = google_storage_bucket.backup.name
  role   = "roles/storage.objectCreator"
  member = each.value
}

# Reads are reserved for a dedicated per-cell restore identity that nothing on
# the hosts or in the runtime serves as. Restore tooling and drills impersonate
# it; the impersonation grants are managed out-of-band (admin-held, same
# pattern as the KMS grants) so the shared runtime identity never gains read.
resource "google_service_account" "restore" {
  project      = var.project_id
  account_id   = var.restore_service_account_id
  display_name = "Artifact backup restore reader (${var.environment})"
  description  = "Read-only access to the ${var.bucket_name} backup bucket for restore tooling and drills. No host or runtime service may run as this identity; impersonation is granted out-of-band."
}

resource "google_storage_bucket_iam_member" "restore_view" {
  bucket = google_storage_bucket.backup.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.restore.email}"
}

# Deletes are reserved for a dedicated control-plane GC identity that nothing
# on the hosts runs as. The retention window itself is enforced by the GC job;
# this SA existing is the IAM half of that contract.
resource "google_service_account" "gc" {
  project      = var.project_id
  account_id   = var.gc_service_account_id
  display_name = "Artifact backup GC (${var.environment})"
  description  = "Control-plane-only deleter for the ${var.bucket_name} backup bucket. No host or runtime service may run as this identity."
}

resource "google_storage_bucket_iam_member" "gc_admin" {
  bucket = google_storage_bucket.backup.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.gc.email}"
}

locals {
  backup_storage_contract = {
    project_id              = var.project_id
    environment             = var.environment
    bucket                  = google_storage_bucket.backup.name
    location                = var.location
    writer_members          = var.writer_members
    gc_service_account      = google_service_account.gc.email
    restore_service_account = google_service_account.restore.email
    soft_delete_seconds     = var.soft_delete_retention_seconds
    noncurrent_days         = var.noncurrent_version_retention_days
    kms_key_name            = var.kms_key_name
    labels                  = var.labels
  }
}
