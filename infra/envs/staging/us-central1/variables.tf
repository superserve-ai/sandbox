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
