variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "region" {
  description = "Region for the host."
  type        = string
}

variable "zone" {
  description = "Zone for the host."
  type        = string
}

variable "instance_name" {
  description = "VM instance name."
  type        = string
}

variable "machine_type" {
  description = "Compute Engine machine type."
  type        = string
}

variable "subnet" {
  description = "Subnetwork self link or name."
  type        = string
}

variable "internal_ip" {
  description = "Reserved internal IP address."
  type        = string
  default     = null
}

variable "tags" {
  description = "Network tags."
  type        = list(string)
  default     = []
}

variable "labels" {
  description = "Instance labels."
  type        = map(string)
  default     = {}
}

variable "service_account_email" {
  description = "Attached service account email."
  type        = string
}

variable "boot_disk_image" {
  description = "Boot disk image."
  type        = string
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB."
  type        = number
  default     = 200
}

variable "metadata" {
  description = "Instance metadata."
  type        = map(string)
  default     = {}
}

variable "can_ip_forward" {
  type    = bool
  default = false
}

variable "on_host_maintenance" {
  description = "Host maintenance policy. Bare-metal machine types must use TERMINATE."
  type        = string
  default     = "MIGRATE"

  validation {
    condition     = contains(["MIGRATE", "TERMINATE"], var.on_host_maintenance)
    error_message = "on_host_maintenance must be MIGRATE or TERMINATE."
  }
}
