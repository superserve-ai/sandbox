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

variable "create_network" {
  type    = bool
  default = false
}

variable "network_name" {
  type    = string
  default = "superserve-production-vpc"
}
