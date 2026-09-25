variable "project_id" {
  description = "GCP project ID for the new region rollout."
  type        = string
  default     = "rayai-prod"
}

variable "environment" {
  description = "Logical environment name."
  type        = string
  default     = "us-west2"
}

variable "region" {
  description = "Target GCP region."
  type        = string
  default     = "us-west2"
}

variable "zone" {
  description = "Primary zone for the deployment."
  type        = string
  default     = "us-west2-a"
}

variable "resource_suffix" {
  description = "Project-global naming suffix. Set this explicitly when the same environment exists in multiple regions."
  type        = string
  default     = null
}

variable "service_account_suffix" {
  description = "Service-account naming suffix. Override if a shorter suffix is needed to satisfy GCP account_id limits."
  type        = string
  default     = null
}

variable "subnet_cidr" {
  description = "Primary subnet CIDR."
  type        = string
  default     = "10.20.0.0/24"
}

variable "connector_subnet_cidr" {
  description = "Connector subnet CIDR."
  type        = string
  default     = "10.20.1.0/28"
}

variable "machine_type" {
  description = "Sandbox/VMD host machine type."
  type        = string
  default     = "n2-standard-16"
}

variable "supabase_url" {
  description = "Supabase project URL for this deployment."
  type        = string
  default     = "https://usw.supabase.co"
}

variable "database_url_secret_name" {
  description = "Secret Manager secret name containing the DATABASE_URL for this deployment."
  type        = string
  default     = null
}

variable "internal_api_token_secret_name" {
  description = "Secret Manager secret name for INTERNAL_API_TOKEN."
  type        = string
  default     = null
}

variable "sandbox_access_token_seed_secret_name" {
  description = "Secret Manager secret name for SANDBOX_ACCESS_TOKEN_SEED."
  type        = string
  default     = null
}

variable "secrets_signing_key_secret_name" {
  description = "Secret Manager secret name for SECRETS_SIGNING_KEY."
  type        = string
  default     = null
}

variable "sentry_dsn_secret_name" {
  description = "Secret Manager secret name for SENTRY_DSN."
  type        = string
  default     = null
}

variable "system_team_id_secret_name" {
  description = "Secret Manager secret name for SYSTEM_TEAM_ID."
  type        = string
  default     = null
}

variable "notification_channel_ids" {
  description = "Existing monitored Cloud Monitoring notification channel resource names for infrastructure alerts."
  type        = list(string)
  default     = []
}

variable "create_network" {
  type    = bool
  default = false
}

variable "network_name" {
  type    = string
  default = "superserve-production-vpc"
}

variable "standby_host_id" {
  description = "The host's HOST_ID as vmd registers it (the installed host identity, not the slot name); DEFAULT_HOST_ID and alert filters follow it."
  type        = string
  default     = "usw2-2"
}

variable "cloud_ids_runbook_base_url" {
  description = "Shared HTTPS runbook base URL supplied through the RUNBOOK_BASE_URL repository Actions variable."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?(/[^\\s<>?#()\\[\\]]*)?$", var.cloud_ids_runbook_base_url))
    error_message = "Set RUNBOOK_BASE_URL to a nonempty HTTPS base URL without whitespace, query, or fragment."
  }
}

variable "boot_disk_image" {
  default     = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"
  description = "Regional creation-time image default; existing boot disks remain unchanged."
  type        = string
  nullable    = false
}

variable "host_image_overrides" {
  description = "Creation-time image overrides keyed by configured host module name."
  type        = map(string)
  default     = {}
}

variable "provisioning_hosts" {
  description = "Host module names held outside scheduling and runtime deployment during maintenance. Remove only after readiness and explicit admission."
  type        = set(string)
  default     = []
}

variable "compute_restrictions_secret_name" {
  description = "Existing operator-managed compute restriction secret ID, supplied through deployment configuration."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.compute_restrictions_secret_name))
    error_message = "Set compute_restrictions_secret_name to an existing Secret Manager secret ID."
  }
}
