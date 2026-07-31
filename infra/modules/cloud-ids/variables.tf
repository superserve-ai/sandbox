variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "Region that owns the packet mirroring policy."
  type        = string
}

variable "zone" {
  description = "Zonal Cloud IDS endpoint location."
  type        = string
}

variable "network_self_link" {
  description = "VPC self link used by the IDS endpoint and packet mirroring policy."
  type        = string
}

variable "endpoint_name" {
  description = "Cloud IDS endpoint name."
  type        = string
}

variable "mirrored_subnet_self_links" {
  description = "Subnet self links mirrored into Cloud IDS."
  type        = list(string)
}

variable "notification_channel_ids" {
  description = "Existing Cloud Monitoring notification channel resource names."
  type        = list(string)
  default     = []
}

variable "endpoint_severity" {
  description = "Minimum Cloud IDS severity to report."
  type        = string
  default     = "INFORMATIONAL"
}

variable "endpoint_description" {
  description = "Optional Cloud IDS endpoint description."
  type        = string
  default     = null
}

variable "labels" {
  description = "Labels to apply to supported resources."
  type        = map(string)
  default     = {}
}
