variable "host_logging_legacy_transition" {
  type    = string
  default = "preserve"
}
variable "host_logging_legacy_migration" {
  type = object({
    initialize_instance_ids = optional(set(string), [])
    baseline_user_config    = string
    overlap_deadline        = string
    verified_instance_ids   = set(string)
    drained_instance_ids    = set(string)
  })
  default = null
}
