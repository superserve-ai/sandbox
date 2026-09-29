variable "environment" {
  type = string
  validation {
    condition     = contains(["development", "production"], var.environment)
    error_message = "Environment must be development or production."
  }
}
variable "paired_project_number" {
  description = "Resolved numeric project number for the paired Superserve project, from the reviewed rollout manifest."
  type        = string
  validation {
    condition     = can(regex("^[0-9]+$", var.paired_project_number))
    error_message = "The paired project number must contain only decimal digits."
  }
}
variable "folder_id" {
  type = string
}
variable "billing_account" {
  type = string
}
variable "github" {
  type = object({
    owner_id      = string
    repository_id = string
    repository    = string
  })
}
variable "registry" {
  type = object({
    location   = string
    repository = string
  })
}
variable "provisioning_enabled" {
  type    = bool
  default = false
}
variable "platform_services_ready" {
  type    = bool
  default = false
}
variable "cell_admin_secret_ids" {
  type    = set(string)
  default = []
}

variable "bootstrap_service_account" {
  description = "Environment-specific bootstrap identity in the protected administration project."
  type        = string
}
variable "bootstrap_state_bucket" {
  description = "Protected bucket supplied to terraform init for this environment; published as a reference only."
  type        = string
}
