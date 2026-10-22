variable "project_id" {
  description = "GCP project hosting devboxes. Staging shares it, which is why devbox IAM is name-scoped."
  type        = string
}

variable "region" {
  description = "Region for the devbox subnet, NAT and buckets."
  type        = string
}

variable "zones" {
  description = "Zones devbox VMs and disks may be created in, in the order create tries them; the IAM name conditions cover each."
  type        = list(string)

  validation {
    condition     = length(var.zones) > 0 && length(distinct(var.zones)) == length(var.zones) && alltrue([for zone in var.zones : can(regex("^${var.region}-[a-z]$", zone))])
    error_message = "zones must be a non-empty list of distinct zones in region."
  }
}

variable "subnet_cidr" {
  description = "Primary range of the dedicated devbox subnet."
  type        = string
}

variable "network_tag" {
  description = "Network tag every devbox VM carries; the IAP SSH rule targets it."
  type        = string
}

variable "resource_name_prefix" {
  description = "Prefix every devbox VM and disk name starts with."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*-$", var.resource_name_prefix))
    error_message = "resource_name_prefix must be a lowercase GCE name fragment ending in '-'."
  }
}

variable "bucket_name_prefix" {
  description = "Prefix every per-box bucket name starts with."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*-$", var.bucket_name_prefix))
    error_message = "bucket_name_prefix must be a lowercase bucket name fragment ending in '-'."
  }
}

variable "github_repository" {
  description = "owner/name of the only repository whose workflows may use the devbox identity."
  type        = string
}

variable "github_repository_id" {
  description = "Numeric GitHub ID of github_repository."
  type        = string
}

variable "github_repository_owner_id" {
  description = "Numeric GitHub ID of the repository owner."
  type        = string
}

variable "github_environment" {
  description = "GitHub environment every devbox job must run in to obtain credentials."
  type        = string
}

variable "engineer_members" {
  description = "IAM principals (for example group:devs@example.com) allowed to reach devboxes over IAP SSH."
  type        = list(string)
  default     = []
}

variable "hostprep_bucket" {
  description = "Read-only bucket holding the verified guest kernel and base rootfs for box bootstrap."
  type        = string
}

variable "hostprep_seeder" {
  description = "Principal that seeds the hostprep bucket from a staging host."
  type        = string
}
