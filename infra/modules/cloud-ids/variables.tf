variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "Region that owns the packet mirroring policy."
  type        = string
}

variable "zone" {
  description = "Zonal Cloud IDS endpoint location."
  type        = string
}

variable "network_self_link" {
  description = "VPC self link used by the IDS endpoint and packet mirroring policy."
  type        = string
}

variable "endpoint_name" {
  description = "Cloud IDS endpoint name."
  type        = string
}

variable "mirrored_subnet_self_links" {
  description = "Subnet self links mirrored into Cloud IDS."
  type        = list(string)
}

variable "notification_channel_ids" {
  description = "Existing Cloud Monitoring notification channel resource names."
  type        = list(string)
  default     = []
}

variable "endpoint_severity" {
  description = "Minimum Cloud IDS severity to report."
  type        = string
  default     = "INFORMATIONAL"
}

variable "endpoint_description" {
  description = "Optional Cloud IDS endpoint description."
  type        = string
  default     = null
}

variable "labels" {
  description = "Labels to apply to supported resources."
  type        = map(string)
  default     = {}
}

variable "runbook_base_url" {
  description = "Shared HTTPS runbook base URL supplied through the RUNBOOK_BASE_URL repository Actions variable."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?(/[^\\s<>?#()\\[\\]]*)?$", var.runbook_base_url))
    error_message = "Set RUNBOOK_BASE_URL to a nonempty HTTPS base URL without whitespace, query, or fragment."
  }
}

variable "runbook_ids" {
  description = "Page IDs for the shared investigation, correlation, and containment runbooks."
  type = object({
    investigation = string
    correlation   = string
    containment   = string
  })
  default = {
    investigation = "3b1743ab8733814b8525eb393089deec"
    correlation   = "3b1743ab873381289015f1a8ccc8753e"
    containment   = "3a4743ab87338171ab19eafdbd3808d2"
  }
  nullable = false

  validation {
    condition = alltrue([
      for id in values(var.runbook_ids) : can(regex("^[A-Za-z0-9_-]+$", id))
    ])
    error_message = "All three runbook IDs must be nonempty page IDs containing only letters, digits, underscores, or hyphens."
  }
}
