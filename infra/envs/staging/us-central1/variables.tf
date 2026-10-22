variable "promotion_evidence_enabled" {
  description = "Attach promotion evidence secrets only after operators publish all four versions and prepare shared Auth. Does not enable device policy."
  type        = bool
  default     = false
  nullable    = false
}

variable "project_id" {
  description = "GCP project ID for staging."
  type        = string
  default     = "rayai-dev"
}

variable "environment" {
  description = "Logical environment name."
  type        = string
  default     = "staging"
}

variable "region" {
  description = "Primary region for staging."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Primary zone for staging."
  type        = string
  default     = "us-central1-a"
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

variable "supabase_url" {
  description = "Supabase project URL for this deployment."
  type        = string
  default     = "https://staging.supabase.co"
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

variable "team_creation_public_keys" {
  description = "JSON map of dedicated Console assertion key IDs to base64 Ed25519 public keys. Empty disables team creation."
  type        = string
  default     = "{}"
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

variable "boot_disk_image" {
  default     = "projects/rayai-dev/global/images/superserve-vmd-20260401-224137"
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

variable "build_host_id" {
  description = "Registered HOST_ID of the active host used for template builds and default routing."
  type        = string
  nullable    = false

  validation {
    condition     = length(trimspace(var.build_host_id)) > 0
    error_message = "build_host_id must identify the active registered host."
  }
}

variable "alert_runbook_base_url" {
  description = "Shared HTTPS runbook base URL supplied through the RUNBOOK_BASE_URL repository Actions variable."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?(/[^\\s<>?#()\\[\\]]*)?$", var.alert_runbook_base_url))
    error_message = "Set RUNBOOK_BASE_URL to a nonempty HTTPS base URL without whitespace, query, or fragment."
  }
}

variable "notification_channel_ids" {
  description = "Existing Cloud Monitoring notification channels for staging alerts."
  type        = list(string)
  default     = []
}

variable "qm_team_service" {
  description = "Enable the organization-team service only after authority installation and dedicated credential publication. References only; never supply token bytes."
  type = object({
    namespace                 = string
    authority_id              = string
    home_region               = string
    credential_secret_id      = string
    credential_secret_version = string
  })
  default = null

  validation {
    condition = var.qm_team_service == null ? true : alltrue([
      can(regex("^[a-z][a-z0-9-]{2,39}$", var.qm_team_service.namespace)),
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.qm_team_service.authority_id)),
      var.qm_team_service.authority_id != "00000000-0000-0000-0000-000000000000",
      contains(["use", "usw"], var.qm_team_service.home_region),
      can(regex("^qm-team-service-token-[a-z0-9-]+$", var.qm_team_service.credential_secret_id)),
      can(regex("^[1-9][0-9]*$", var.qm_team_service.credential_secret_version)),
    ])
    error_message = "Organization-team configuration requires a namespace, canonical nonzero authority UUID, use/usw region, dedicated qm-team-service-token-* secret ID and positive numeric secret version."
  }
}

variable "qm_machine_identity_activation" {
  description = "Reviewed machine-identity activation record. Null leaves issuance disabled; readiness predicates require deployed evidence."
  type = object({
    contract_revision = string
    environment       = string
    ownership_ready   = bool
    verifier_ready    = bool
    operator_ready    = bool
  })
  default  = null
  nullable = true

  validation {
    condition = var.qm_machine_identity_activation == null ? true : (
      var.qm_machine_identity_activation.contract_revision == "machine-identity-v1" &&
      var.qm_machine_identity_activation.environment == "staging" &&
      var.qm_machine_identity_activation.ownership_ready != null &&
      var.qm_machine_identity_activation.verifier_ready != null &&
      var.qm_machine_identity_activation.operator_ready != null
    )
    error_message = "Machine activation requires machine-identity-v1, staging, and three explicit readiness booleans."
  }

  validation {
    condition = var.qm_machine_identity_activation == null ? true : (
      var.project_id == "rayai-dev" && var.environment == "staging" && var.region == "us-central1"
    )
    error_message = "Machine activation is supported only by the rayai-dev staging us-central1 root."
  }
}
