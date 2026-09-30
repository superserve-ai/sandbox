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
  default     = "2026-09-30"
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
  description = "Separate Ops Agent disk-buffer budget; it is accounted for independently of journald."
  type        = number
  default     = 1073741824

  validation {
    condition     = var.agent_buffer_bytes > 0
    error_message = "agent_buffer_bytes must be positive."
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
  description = "Pinned Ops Agent package version selected after staging verification."
  type        = string
  default     = "2.52.0"
}
