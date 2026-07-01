variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "region" {
  description = "Primary region."
  type        = string
}

variable "artifact_registry" {
  description = "Artifact Registry repositories keyed by logical name."
  type = map(object({
    repository_id = string
    format        = string
    description   = optional(string, null)
  }))
  default = {}
}

variable "buckets" {
  description = "Storage buckets keyed by logical name."
  type = map(object({
    name                        = string
    location                    = string
    storage_class               = optional(string, "STANDARD")
    uniform_bucket_level_access = optional(bool, true)
    public_access_prevention    = optional(string, "inherited")
    versioning_enabled          = optional(bool, false)
    force_destroy               = optional(bool, false)
  }))
  default = {}
}

variable "labels" {
  description = "Labels to apply to supported resources."
  type        = map(string)
  default     = {}
}
