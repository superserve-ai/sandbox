variable "project_id" { type = string }
variable "region" { type = string }
variable "name" {
  type        = string
  description = "Distinct CA pool name for this environment/cell."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,50}$", var.name))
    error_message = "Use a lowercase pool name between 3 and 51 characters."
  }
}
variable "issuer_account_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.issuer_account_id))
    error_message = "Use a valid 6–30 character service account ID."
  }
}
variable "spiffe_uri" {
  type        = string
  description = "Existing exact peer identity; independent of credential provider."
  validation {
    condition     = can(regex("^spiffe://[a-zA-Z0-9.-]+/ns/vmd/sa/vmd-peer-proxy$", var.spiffe_uri))
    error_message = "Preserve the existing cell vmd-peer-proxy SPIFFE contract."
  }
}
variable "leaf_lifetime_seconds" {
  type    = number
  default = 2592000
  validation {
    condition     = var.leaf_lifetime_seconds > 3600 && floor(var.leaf_lifetime_seconds) == var.leaf_lifetime_seconds
    error_message = "Leaf lifetime must be an integer greater than one hour."
  }
}
variable "ca_lifetime_seconds" {
  type    = number
  default = 157680000
  validation {
    condition     = var.ca_lifetime_seconds > 3600 && floor(var.ca_lifetime_seconds) == var.ca_lifetime_seconds
    error_message = "CA lifetime must be an integer greater than one hour."
  }
}
variable "operator_members" {
  type        = set(string)
  default     = []
  description = "Explicit reviewed user/group principals allowed to impersonate only this issuer. Empty grants nothing."
  validation {
    condition     = alltrue([for member in var.operator_members : can(regex("^(user|group):[^ @]+@[^ @]+$", member))])
    error_message = "Only explicit user:email or group:email members are supported; never grant host accounts impersonation."
  }
}
