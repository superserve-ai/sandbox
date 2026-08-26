variable "lifecycle_latency_alerts" {
  description = "Fleet-wide customer-visible lifecycle latency alerts keyed by operation. Empty disables latency alerting."
  type = map(object({
    latency_seconds = number
    quantile        = optional(number, 0.33)
    duration        = optional(string, "300s")
  }))
  default = {}

  validation {
    condition = alltrue([
      for operation, alert in var.lifecycle_latency_alerts :
      contains(["create", "resume", "pause", "delete"], operation) &&
      alert.latency_seconds > 0 &&
      alert.quantile > 0 && alert.quantile < 1
    ])
    error_message = "Lifecycle alerts support create, resume, pause, and delete; latency_seconds must be positive and quantile must be between 0 and 1."
  }
}

variable "failed_sandbox_alert_enabled" {
  description = "Create the fleet-wide alert that fires when any sandbox lifecycle transition reports a non-success result in the preceding five minutes."
  type        = bool
  default     = false
}
