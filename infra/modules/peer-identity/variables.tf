variable "project_id" {
  description = "Project that owns the cell and its managed trust domain."
  type        = string
}

variable "region" {
  description = "Region containing the hosts and issuing CA pool."
  type        = string
}

variable "cell" {
  description = "Unique cell suffix; staging and production must use separate trust domains."
  type        = string
}

variable "instance_name" {
  description = "Existing cold-standby VM name."
  type        = string
}

variable "instance_id" {
  description = "Immutable Compute Engine instance ID authorized for peer issuance."
  type        = string
}

variable "zone" {
  description = "Zone of the authorized instance."
  type        = string
}

variable "internal_ip" {
  description = "Existing private address to verify during bootstrap."
  type        = string
}

variable "host_id" {
  description = "Stable host-directory row ID, which may differ from the VM name."
  type        = string
}

variable "runtime_email" {
  description = "Dedicated per-cell VMD runtime service account."
  type        = string
}

variable "identity_at_creation" {
  description = "Create the trust domain before the VM and only attest/verify afterward."
  type        = bool
  default     = false
}
