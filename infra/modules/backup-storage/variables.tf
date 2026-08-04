variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "bucket_name" {
  description = "Backup bucket name."
  type        = string
}

variable "location" {
  description = "Bucket location. Regional, matching the cell's hosts — backup data stays in the cell's home region."
  type        = string
}

variable "storage_class" {
  description = "Bucket storage class."
  type        = string
  default     = "STANDARD"
}

variable "writer_members" {
  description = "IAM members (serviceAccount:... form) granted object create only: no read, no delete, no overwrite. The vmd host SA belongs here."
  type        = list(string)
}

variable "restore_service_account_id" {
  description = "Account ID for the dedicated read-only restore service account. Nothing runs as it; restore tooling impersonates it via out-of-band grants."
  type        = string

  validation {
    condition     = length(var.restore_service_account_id) >= 6 && length(var.restore_service_account_id) <= 30
    error_message = "Service account account_id must be 6-30 characters."
  }
}

variable "gc_service_account_id" {
  description = "Account ID for the dedicated control-plane GC service account that owns object deletion."
  type        = string

  validation {
    condition     = length(var.gc_service_account_id) >= 6 && length(var.gc_service_account_id) <= 30
    error_message = "Service account account_id must be 6-30 characters."
  }
}

variable "soft_delete_retention_seconds" {
  description = "Bucket soft-delete retention. Recovery window for objects deleted by the GC job itself."
  type        = number
  default     = 604800 # 7 days
}

variable "noncurrent_version_retention_days" {
  description = "Days a noncurrent object version is kept before lifecycle deletes it."
  type        = number
  default     = 30
}

variable "kms_key_name" {
  description = "Optional CMEK key resource name for bucket default encryption. Must be in the bucket's location; null uses Google-managed encryption. Prerequisite: the project's Cloud Storage service agent must already hold roles/cloudkms.cryptoKeyEncrypterDecrypter on the key, or bucket creation and object writes fail. That grant is managed out-of-band, like the other KMS grants in this repo — the CD Terraform SA cannot set KMS IAM policy."
  type        = string
  default     = null
}

variable "labels" {
  description = "Labels to apply to supported resources."
  type        = map(string)
  default     = {}
}
