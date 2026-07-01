variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "notification_email" {
  description = "Optional alerting email target."
  type        = string
  default     = null
}

variable "log_buckets" {
  description = "Logging bucket definitions keyed by logical name."
  type = map(object({
    bucket_id      = string
    location       = string
    retention_days = number
    description    = optional(string, null)
  }))
  default = {}
}

variable "uptime_checks" {
  description = "Uptime checks keyed by logical name."
  type = map(object({
    display_name = string
    host         = string
    path         = optional(string, "/")
    port         = optional(number, 443)
    use_ssl      = optional(bool, true)
  }))
  default = {}
}

variable "alert_policies" {
  description = "Alert policies keyed by logical name."
  type = map(object({
    display_name  = string
    combiner      = optional(string, "OR")
    documentation = optional(string, null)
  }))
  default = {}
}

variable "dashboards" {
  description = "Dashboard definitions keyed by logical name."
  type = map(object({
    display_name = string
    definition   = string
  }))
  default = {}
}

variable "labels" {
  description = "Labels to apply to supported resources."
  type        = map(string)
  default     = {}
}
