variable "project_id" {
  description = "Project containing the serving hosts and OS Config assignment."
  type        = string
}

variable "zone" {
  description = "Zonal OS Config assignment location."
  type        = string
}

variable "environment" {
  description = "Logical environment stamped into exported entries."
  type        = string
}

variable "region" {
  description = "Serving region stamped into exported entries."
  type        = string
}

variable "assignment_name" {
  description = "Dedicated OTel logs OS Config assignment identity."
  type        = string
}

variable "assignment_revision" {
  description = "Immutable rendered revision used for reconciliation and rollback."
  type        = string
  default     = "2026-10-01-otel-1"
}

variable "selector_labels" {
  description = "Narrow labels selecting only intended serving hosts."
  type        = map(string)
  default     = {}
}

variable "enrolled_hosts" {
  description = "Serving-host descriptors used for identity mapping and least-privilege IAM."
  type = map(object({
    instance_name         = string
    instance_id           = string
    host_id               = string
    incarnation           = string
    service_account_email = string
    proxy_units           = optional(list(string), ["proxy.service"])
  }))
}

variable "journal_max_use_bytes" {
  description = "Initial persistent journal budget (4 GiB)."
  type        = number
  default     = 4294967296
  validation {
    condition     = var.journal_max_use_bytes > 0
    error_message = "journal_max_use_bytes must be positive."
  }
}

variable "journal_keep_free_bytes" {
  description = "Persistent journal free-space reserve (10 GiB)."
  type        = number
  default     = 10737418240
  validation {
    condition     = var.journal_keep_free_bytes > 0
    error_message = "journal_keep_free_bytes must be positive."
  }
}

variable "otel_release_version" {
  description = "Pinned released OpenTelemetry Collector Contrib version."
  type        = string
  default     = "0.104.0"
  validation {
    condition     = can(regex("^0\\.[0-9]+\\.[0-9]+$", var.otel_release_version))
    error_message = "otel_release_version must be a pinned semantic release."
  }
}

variable "otel_release_url" {
  description = "Authenticated package URL for the selected amd64 OTel Contrib release."
  type        = string
  default     = "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.104.0/otelcol-contrib_0.104.0_linux_amd64.tar.gz"
  validation {
    condition     = can(regex("^https://", var.otel_release_url))
    error_message = "otel_release_url must use HTTPS."
  }
}

variable "otel_release_sha256" {
  description = "SHA-256 digest of the selected OTel Contrib archive."
  type        = string
  # This immutable value is replaced only by a reviewed release manifest;
  # staging must reject an archive whose bytes do not match it.
  default = "8931c2f158339a7607de1356224444be778c5da9608b9fd5be52aafee7c414c5"
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.otel_release_sha256))
    error_message = "otel_release_sha256 must be a reviewed 64-character hexadecimal digest."
  }
}

variable "otel_binary_path" {
  description = "Dedicated binary path; it must not overlap the metrics collector."
  type        = string
  default     = "/opt/superserve/otelcol-contrib/bin/otelcol-contrib"
  validation {
    condition     = !strcontains(var.otel_binary_path, "superserve-otel-collector")
    error_message = "The logs binary path must remain distinct from the metrics collector."
  }
}

variable "otel_memory_limit_mb" {
  description = "Bounded OTel logs service memory budget in MiB."
  type        = number
  default     = 512
  validation {
    condition     = var.otel_memory_limit_mb > 0
    error_message = "otel_memory_limit_mb must be positive."
  }
}

variable "otel_cpu_limit" {
  description = "Bounded OTel logs service CPU quota."
  type        = string
  default     = "1000m"
}

variable "package_operation_timeout_seconds" {
  description = "Bound for release download and staged package operations."
  type        = number
  default     = 120
  validation {
    condition     = var.package_operation_timeout_seconds >= 30
    error_message = "package_operation_timeout_seconds must be at least 30 seconds."
  }
}

variable "heartbeat_interval_seconds" {
  description = "Managed heartbeat period; no fleet-sized loop is used."
  type        = number
  default     = 60
  validation {
    condition     = var.heartbeat_interval_seconds >= 30
    error_message = "heartbeat_interval_seconds must be at least 30 seconds."
  }
}

variable "otel_queue_max_bytes" {
  description = "Explicit disk budget for the persistent OTel exporter queue."
  type        = number
  default     = 2147483648
  validation {
    condition     = var.otel_queue_max_bytes > 0
    error_message = "otel_queue_max_bytes must be positive."
  }
}
