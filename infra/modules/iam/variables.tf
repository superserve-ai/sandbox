variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "service_accounts" {
  description = "Service accounts to manage."
  type = map(object({
    account_id   = string
    display_name = string
    description  = optional(string, null)
  }))
  default = {}
}

variable "project_bindings" {
  description = "Project-level IAM bindings keyed by logical name."
  type = map(object({
    role    = string
    members = list(string)
  }))
  default = {}
}

variable "service_bindings" {
  description = "Service-account IAM bindings keyed by logical name."
  type = map(object({
    service_account = string
    role            = string
    members         = list(string)
  }))
  default = {}
}

variable "workload_identity" {
  description = "Optional workload identity mappings."
  type = map(object({
    service_account = string
    principal       = string
  }))
  default = {}
}

variable "labels" {
  description = "Labels to apply to supported IAM resources."
  type        = map(string)
  default     = {}
}
