variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "region" {
  description = "Primary region."
  type        = string
}

variable "network_name" {
  description = "Target VPC name."
  type        = string
}

variable "subnet_name" {
  description = "Primary subnet name."
  type        = string
}

variable "subnet_cidr" {
  description = "Primary subnet CIDR."
  type        = string
}

variable "create_network" {
  description = "Whether this module should create the VPC. Set false to reference an existing VPC by name."
  type        = bool
  default     = true
}

variable "create_vpc_connector" {
  description = "Whether the module should manage a Serverless VPC Access connector."
  type        = bool
  default     = true
}

variable "create_vpc_connector_subnet" {
  description = "Whether the module should manage the subnet used by a Serverless VPC connector or Cloud Run Direct VPC egress. Defaults to true when creating a subnet-mode connector."
  type        = bool
  default     = null
}

variable "vpc_connector_name" {
  description = "Serverless VPC Access connector name."
  type        = string
  default     = null
}

variable "vpc_connector_subnet" {
  description = "Connector or Direct VPC subnet name."
  type        = string
  default     = null
}

variable "vpc_connector_subnet_ip" {
  description = "Connector or Direct VPC subnet CIDR."
  type        = string
  default     = null
}

variable "vpc_connector_mode" {
  description = "How to configure the VPC connector: subnet or ip_cidr_range."
  type        = string
  default     = "subnet"

  validation {
    condition     = contains(["subnet", "ip_cidr_range"], var.vpc_connector_mode)
    error_message = "vpc_connector_mode must be either subnet or ip_cidr_range."
  }
}

variable "vpc_connector_ip_cidr_range" {
  description = "CIDR range for VPC connector when vpc_connector_mode is ip_cidr_range."
  type        = string
  default     = null
}

variable "firewall_rules" {
  description = "Firewall rule definitions keyed by logical name."
  type = map(object({
    name          = optional(string)
    direction     = string
    priority      = optional(number, 1000)
    source_ranges = optional(list(string), [])
    target_tags   = optional(list(string), [])
    allow = optional(list(object({
      protocol = string
      ports    = optional(list(string), [])
    })), [])
    deny = optional(list(object({
      protocol = string
      ports    = optional(list(string), [])
    })), [])
    description = optional(string, null)
  }))
  default = {}
}

variable "enable_iap_ssh" {
  description = "Whether to manage the restricted IAP SSH allow rule."
  type        = bool
  default     = false
}

variable "manage_public_ssh_deny" {
  description = "Whether to deny public TCP/UDP port 22 ingress for the tagged instances."
  type        = bool
  default     = false
}

variable "iap_ssh_target_tags" {
  description = "Network tags identifying instances protected by the SSH controls. Required when either SSH control is enabled."
  type        = list(string)
  default     = []

  validation {
    condition     = (!var.enable_iap_ssh && !var.manage_public_ssh_deny) || length(var.iap_ssh_target_tags) > 0
    error_message = "iap_ssh_target_tags must contain at least one tag when SSH controls are enabled."
  }
}

variable "labels" {
  description = "Labels to apply to managed resources."
  type        = map(string)
  default     = {}
}
variable "vpc_connector_min_instances" {
  type    = number
  default = 2
}

variable "vpc_connector_max_instances" {
  type    = number
  default = 3
}

variable "vpc_connector_machine_type" {
  type    = string
  default = "e2-micro"
}
