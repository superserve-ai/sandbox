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

variable "name" {
  description = "Logical load balancer name."
  type        = string
}

variable "global_addresses" {
  description = "Global address definitions keyed by logical name."
  type = map(object({
    name = string
  }))
  default = {}
}

variable "forwarding_rules" {
  description = "Forwarding rule definitions keyed by logical name."
  type = map(object({
    name                  = string
    port                  = string
    target_type           = string
    address_key           = string
    protocol              = optional(string, "TCP")
    load_balancing_scheme = optional(string, "EXTERNAL_MANAGED")
  }))
  default = {}
}

variable "backend_services" {
  description = "Backend service definitions keyed by logical name."
  type = map(object({
    name                        = string
    protocol                    = string
    port_name                   = string
    health_check                = optional(string, null)
    backend_type                = string
    backend_ref                 = string
    timeout_sec                 = optional(number, 30)
    connection_draining_timeout = optional(number, 0)
  }))
  default = {}
}

variable "instance_group" {
  description = "Optional unmanaged instance group configuration."
  type = object({
    name        = string
    zone        = string
    named_ports = map(number)
    instances   = optional(list(string), [])
  })
  default = null
}

variable "health_checks" {
  description = "Health check definitions keyed by logical name."
  type = map(object({
    name         = string
    protocol     = string
    port         = optional(number)
    request_path = optional(string)
  }))
  default = {}
}

variable "certificates" {
  description = "Certificate Manager certificate definitions keyed by logical name."
  type = map(object({
    name                   = string
    domains                = list(string)
    dns_authorization_keys = optional(list(string), [])
  }))
  default = {}
}

variable "certificate_map_entries" {
  description = "Certificate map entries keyed by logical name."
  type = map(object({
    name            = string
    hostname        = string
    certificate_key = string
  }))
  default = {}
}

variable "dns_authorizations" {
  description = "DNS authorization definitions keyed by logical name."
  type = map(object({
    name   = string
    domain = string
  }))
  default = {}
}

variable "certificate_map_name" {
  description = "Certificate map name."
  type        = string
  default     = null
}

variable "labels" {
  description = "Labels to apply to supported resources."
  type        = map(string)
  default     = {}
}
