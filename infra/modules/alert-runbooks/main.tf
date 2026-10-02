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
  description = "Page IDs by alert procedure, shared across environments."
  type        = map(string)
  nullable    = false
  default = {
    lifecycle_latency = "3e9743ab8733810d8195c4a3965b75d2"
    lifecycle_failure = "3e9743ab8733815c9b18d72dc1fe40c9"
    backup_pipeline   = "3e9743ab873381c48526c4e8b92fb345"
    backup_coverage   = "3e9743ab87338170b642ecc059e9b44d"
    host_disk         = "3e9743ab873381faa16bd77f24762816"
    host_cpu          = "3e9743ab873381baa110d755a0d9e8d7"
    host_maintenance  = "3e9743ab873381048279ce342d9373d5"
    vmd_launch        = "3e9743ab873381d999c8c439702a91e8"
    vmd_network       = "3e9743ab87338129b5f7fddcb51b638c"
  }

  validation {
    condition = alltrue([
      for key in ["lifecycle_latency", "lifecycle_failure", "backup_pipeline", "backup_coverage", "host_disk", "host_cpu", "host_maintenance", "vmd_launch", "vmd_network"] : contains(keys(var.runbook_ids), key)
    ])
    error_message = "Configure a verified page ID for each of the nine alert procedures before deploying."
  }

  validation {
    condition = alltrue([
      for id in values(var.runbook_ids) : can(regex("^[A-Za-z0-9_-]+$", id))
    ])
    error_message = "Runbook IDs must be nonempty page IDs containing only letters, digits, underscores, or hyphens."
  }
}

output "urls" {
  sensitive = true
  value = sensitive({
    for name, id in var.runbook_ids : name => "${replace(var.runbook_base_url, "/[/]+$/", "")}/${id}"
  })
}
