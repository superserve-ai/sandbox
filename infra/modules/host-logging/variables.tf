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
  description = "Existing or new zonal OS Config assignment identity."
  type        = string
}

variable "assignment_revision" {
  description = "Versioned configuration revision used for reconciliation and rollback."
  type        = string
  default     = "2026-10-01"
}

variable "selector_labels" {
  description = "Narrow labels selecting only the intended serving hosts."
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
    service_account_email  = string
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

variable "agent_buffer_bytes" {
  description = "Conservative free-space reservation for the selected release's platform-managed Ops Agent buffer; the 2.52.0 release does not expose a configurable numeric cap, so this value is accounting/enforcement threshold rather than a claimed agent limit."
  type        = number
  default     = 1073741824

  validation {
    condition     = var.agent_buffer_bytes > 0
    error_message = "agent_buffer_bytes must be positive."
  }
}

variable "agent_self_log_max_bytes" {
  description = "Per-file size bound used by the host log rotation policy for Ops Agent self-logs."
  type        = number
  default     = 268435456

  validation {
    condition     = var.agent_self_log_max_bytes > 0
    error_message = "agent_self_log_max_bytes must be positive."
  }
}

variable "syslog_max_bytes" {
  description = "Size bound used by the host log rotation policy for retained syslog files."
  type        = number
  default     = 268435456

  validation {
    condition     = var.syslog_max_bytes > 0
    error_message = "syslog_max_bytes must be positive."
  }
}

variable "storage_scan_timeout_seconds" {
  description = "Maximum wall-clock budget for one bounded buffer/self-log/syslog accounting or remediation pass."
  type        = number
  default     = 5

  validation {
    condition     = var.storage_scan_timeout_seconds >= 1
    error_message = "storage_scan_timeout_seconds must be at least one second."
  }
}

variable "storage_scan_max_entries" {
  description = "Maximum number of filesystem entries (including directories) visited in one bounded storage accounting or remediation pass."
  type        = number
  default     = 32

  validation {
    condition     = var.storage_scan_max_entries >= 1
    error_message = "storage_scan_max_entries must be at least one."
  }
}

variable "package_operation_timeout_seconds" {
  description = "Wall-clock bound for each staged or active Ops Agent package operation, including rollback."
  type        = number
  default     = 120

  validation {
    condition     = var.package_operation_timeout_seconds >= 30
    error_message = "package_operation_timeout_seconds must be at least 30 seconds."
  }
}

variable "heartbeat_interval_seconds" {
  description = "Per-host heartbeat period; reconciliation performs no fleet-sized heartbeat loop."
  type        = number
  default     = 60

  validation {
    condition     = var.heartbeat_interval_seconds >= 30
    error_message = "heartbeat_interval_seconds must be at least 30 seconds."
  }
}

variable "agent_memory_limit_mb" {
  description = "Bounded Ops Agent memory budget in MiB."
  type        = number
  default     = 512

  validation {
    condition     = var.agent_memory_limit_mb > 0
    error_message = "agent_memory_limit_mb must be positive."
  }
}

variable "agent_cpu_limit_millicores" {
  description = "Bounded Ops Agent CPU budget in millicores."
  type        = number
  default     = 1000

  validation {
    condition     = var.agent_cpu_limit_millicores > 0
    error_message = "agent_cpu_limit_millicores must be positive."
  }
}

variable "ops_agent_package_version" {
  description = "Pinned Ops Agent package version selected after staging verification; must include the supported built-in buffer cap introduced in 2.28."
  type        = string
  default     = "2.52.0"

  validation {
    condition     = can(regex("^2\\.(2[89]|[3-9][0-9]|[1-9][0-9]{2,})", var.ops_agent_package_version))
    error_message = "ops_agent_package_version must be Ops Agent 2.28.0 or newer so the documented built-in disk buffer cap is present."
  }
}
