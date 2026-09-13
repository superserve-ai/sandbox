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

variable "enable_qm" {
  description = "Create the hosted QM shared infrastructure (module qm). Off by default so the standing plan is a no-op."
  type        = bool
  default     = false
}

variable "qm_domain" {
  description = "Base hostname for QM tenant stacks (qm.<env-domain>); tenants are served at https://<slug>.<qm_domain>. Required when enable_qm is true."
  type        = string
  default     = null
}

variable "qm_marketing_url" {
  description = "Where the QM redirect service sends a bare request for /."
  type        = string
  default     = "https://superserve.ai"
}

variable "qm_api_image" {
  description = "qm-api container image. Must exist before the first apply; null keeps a placeholder that Cloud Run will reject."
  type        = string
  default     = null
}

variable "qm_provisioner_image" {
  description = "Provisioner job container image. Null uses qm_api_image: the service and the job are the same binary and deploy together."
  type        = string
  default     = null
}

variable "qm_tenant_image" {
  description = "Tagged QM image the provisioner deploys for new tenants (QM_TENANT_IMAGE). Null uses <tenant repository>/qm:latest."
  type        = string
  default     = null
}

variable "qm_redirect_image" {
  description = "qm-redirect container image. Same existence requirement as qm_api_image."
  type        = string
  default     = null
}

variable "qm_api_min_instances" {
  description = "qm-api minimum instance count."
  type        = number
  default     = 0
}

variable "qm_sql_tier" {
  description = "Cloud SQL tier for the shared QM tenant instance."
  type        = string
  default     = "db-custom-2-7680"
}

variable "qm_create_private_service_connection" {
  description = "Whether the qm module allocates the Private Service Access range and peering on the staging VPC. Set false if the VPC already has a servicenetworking connection and add the QM range to it out of band."
  type        = bool
  default     = true
}

variable "qm_dns_managed_zone" {
  description = "Cloud DNS managed zone (in this project) owning qm_domain, if Terraform should write the certificate authorization and load balancer records. Null leaves DNS to the zone owner."
  type        = string
  default     = null
}
