variable "project_id" {
  type = string
}

variable "environment" {
  type = string
}

variable "notification_channel_ids" {
  description = "Existing channels in this project. Credentials remain outside Terraform."
  type        = list(string)
}

variable "cells" {
  description = "Expected API cells. Location is the collector's GMP resource location, not the API region. Arm coverage liveness only while issuance is enabled."
  type = map(object({
    metric_location         = string
    cloud_run_service       = string
    cloud_run_region        = string
    coverage_checks_enabled = bool
  }))
  validation {
    condition = length(var.cells) > 0 && alltrue([
      for key, cell in var.cells : can(regex("^[a-z0-9-]+$", key)) &&
      can(regex("^[a-z0-9-]+$", cell.metric_location)) &&
      can(regex("^[a-z0-9-]+$", cell.cloud_run_service)) &&
      can(regex("^[a-z0-9-]+$", cell.cloud_run_region))
    ])
    error_message = "Provide at least one cell with lowercase alphanumeric/hyphen identifiers."
  }
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "runbook_url" {
  description = "Actionable billing recovery procedure; may use the public repository runbook."
  type        = string
  default     = "https://github.com/superserve-ai/sandbox/blob/b9d0f462cd59583657c6219c54677e1fd6e8ce4e/docs/pro-billing.md#entitlement-alert-response"
}

variable "manage_paid_missing" {
  description = "Create the paid-missing policy only when its existing owner has been transferred."
  type        = bool
  default     = true
}
