variable "project_id" {
  description = "GCP project ID."
  type        = string
  default     = "rayai-prod"
}

variable "environment" {
  description = "Logical environment name."
  type        = string
  default     = "production"
}

variable "region" {
  description = "Target GCP region."
  type        = string
  default     = "us-east4"
}

variable "zone" {
  description = "Primary zone for the deployment. Must match the reservation's zone exactly."
  type        = string
  default     = "us-east4-c"
}

variable "resource_suffix" {
  description = "Project-global naming suffix."
  type        = string
  default     = "use4"
}

variable "service_account_suffix" {
  description = "Service-account naming suffix. Override if a shorter suffix is needed to satisfy GCP account_id limits."
  type        = string
  default     = null
}

variable "subnet_cidr" {
  description = "Primary subnet CIDR. 10.0/10.1 are taken by usc1/usw2."
  type        = string
  default     = "10.2.0.0/24"
}

variable "connector_subnet_cidr" {
  description = "CIDR to allow through the vmd/OTLP firewall rules. Placeholder until the us-east4 Cloud Run rollout defines its actual connector/direct-egress subnet — narrow this once that lands instead of leaving it at the primary subnet's range."
  type        = string
  default     = "10.2.0.0/24"
}

variable "host_internal_ip" {
  description = "Reserved internal IP for the vmd host."
  type        = string
  default     = "10.2.0.2"
}

variable "machine_type" {
  description = "Sandbox/VMD host machine type."
  type        = string
  default     = "c4-highmem-288-lssd-metal"
}

variable "boot_disk_type" {
  description = "Boot disk type. C4 metal has no Persistent Disk support, so this must be a Hyperdisk type."
  type        = string
  default     = "hyperdisk-balanced"
}

variable "reservation_name" {
  description = "SPECIFIC_RESERVATION to consume for the vmd host. Must be in the same zone as var.zone."
  type        = string
  default     = "reservation-us-east-c4-288-lssd-metal"
}

variable "create_network" {
  type    = bool
  default = false
}

variable "network_name" {
  type    = string
  default = "superserve-production-vpc"
}
