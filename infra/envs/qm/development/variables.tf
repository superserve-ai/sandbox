variable "db_cells" {
  description = "Region to persisted cell ID to private SQL endpoint, from the database infrastructure owner."
  type        = map(map(object({ private_ip = string })))
  default     = {}
  validation {
    condition     = alltrue([for region in keys(var.db_cells) : contains(keys(local.regions), region)])
    error_message = "Cells must use a supported paired deployment region."
  }
}
variable "control_db_cidrs" {
  description = "Central database private endpoints/ranges, published by the single central control database owner."
  type        = set(string)
  default     = []
}
