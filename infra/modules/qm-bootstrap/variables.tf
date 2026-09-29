variable "project_id" {
  type = string
}
variable "paired_project_id" {
  type = string
}
variable "folder_id" {
  type = string
}
variable "billing_account" {
  type = string
}
variable "regions" {
  type = set(string)
}
variable "github" {
  description = "Numeric GitHub owner/repository IDs and repository slug; IDs prevent name-reuse impersonation."
  type = object({
    owner_id      = string
    repository_id = string
    repository    = string
  })
}
variable "registry" {
  description = "Existing paired-project repository. Its administrator authorizes bootstrap to manage the additive pull bindings."
  type = object({
    location   = string
    repository = string
  })
}
variable "provisioning_enabled" {
  description = "Enable only after protected service tags, inherited IAM audit, and downstream contracts are verified."
  type        = bool
  default     = false
}
variable "platform_services_ready" {
  description = "Platform service shells exist in every supported region; bootstrap can attach their protective tags."
  type        = bool
  default     = false
}
variable "cell_admin_secret_ids" {
  description = "Explicit cell administrator secret containers; values supplied by the database owner."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for id in var.cell_admin_secret_ids : can(regex("^qm-cell-[a-z0-9-]+-admin$", id))])
    error_message = "Only tenant cell administrator secrets may be included."
  }
}
