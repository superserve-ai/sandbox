variable "project_id" {
  description = "GCP project ID for the production central deployment."
  type        = string
  default     = "rayai-prod"
}

variable "environment" {
  description = "Logical environment name."
  type        = string
  default     = "production"
}

variable "region" {
  description = "Current production central region."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Current production central VMD zone."
  type        = string
  default     = "us-central1-c"
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

variable "create_network" {
  description = "Whether this environment should create its VPC instead of referencing the existing production VPC."
  type        = bool
  default     = false
}

variable "network_name" {
  description = "Existing production VPC name."
  type        = string
  default     = "superserve-production-vpc"
}

variable "subnet_cidr" {
  description = "Primary subnet CIDR."
  type        = string
  default     = "10.0.0.0/24"
}

variable "connector_subnet_cidr" {
  description = "Connector subnet CIDR."
  type        = string
  default     = "10.0.1.0/28"
}

variable "machine_type" {
  description = "Sandbox/VMD host machine type."
  type        = string
  default     = "c3-highcpu-192-metal"
}

variable "supabase_url" {
  description = "Supabase project URL for this deployment."
  type        = string
  default     = "https://use.supabase.co"
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
