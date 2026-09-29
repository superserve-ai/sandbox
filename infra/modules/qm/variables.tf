variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "subnet_cidr" {
  type = string
  validation {
    condition     = can(cidrnetmask(var.subnet_cidr)) && can(regex("/20$", var.subnet_cidr))
    error_message = "Tenant subnets must be IPv4 /20 ranges with the documented revision budget."
  }
}

variable "db_cells" {
  description = "Allocator-owned cell IDs and private SQL IPv4 endpoints, supplied by the database infrastructure owner."
  type = map(object({
    private_ip = string
  }))
  default = {}
  validation {
    condition = alltrue([for id, cell in var.db_cells :
      can(regex("^[a-z][a-z0-9-]{0,29}[a-z0-9]$", id)) &&
      can(cidrnetmask("${cell.private_ip}/32")) &&
      (startswith(cell.private_ip, "10.") || startswith(cell.private_ip, "192.168.") ||
      can(regex("^172\\.(1[6-9]|2[0-9]|3[01])\\.", cell.private_ip)))
    ])
    error_message = "Cell IDs must be stable lowercase identifiers, and SQL endpoints must be RFC1918 IPv4 addresses."
  }
  validation {
    condition     = length(distinct([for cell in values(var.db_cells) : cell.private_ip])) == length(var.db_cells)
    error_message = "Each cell must have a distinct private endpoint."
  }
}

variable "control_db_cidrs" {
  description = "Control database private endpoints/ranges. A higher-priority deny overrides even an accidental cell allow."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for cidr in var.control_db_cidrs : can(cidrnetmask(cidr))])
    error_message = "Control database ranges must be IPv4 CIDRs."
  }
}
