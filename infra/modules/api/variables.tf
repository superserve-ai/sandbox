variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "region" {
  description = "Cloud Run region."
  type        = string
}

variable "service_name" {
  description = "Cloud Run service name."
  type        = string
}

variable "service_account_email" {
  description = "Runtime service account email."
  type        = string
}

variable "image" {
  description = "Container image reference."
  type        = string
}

variable "ingress" {
  description = "Ingress setting."
  type        = string
  default     = "INGRESS_TRAFFIC_ALL"
}

variable "min_instances" {
  description = "Minimum instance count."
  type        = number
  default     = 0
}

variable "max_instances" {
  description = "Maximum instance count."
  type        = number
  default     = 10
}

variable "env" {
  description = "Plaintext environment variables."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Secret-backed environment variables keyed by env var name."
  type = map(object({
    secret  = string
    version = optional(string, "latest")
  }))
  default = {}
}

variable "vpc_connector" {
  description = "Optional Serverless VPC Access connector resource name."
  type        = string
  default     = null
}

variable "vpc_egress" {
  description = "Cloud Run VPC egress mode."
  type        = string
  default     = "ALL_TRAFFIC"
}

variable "labels" {
  description = "Labels to apply to the service."
  type        = map(string)
  default     = {}
}

variable "vpc_network" {
  type    = string
  default = null
}

variable "vpc_subnetwork" {
  type    = string
  default = null
}

variable "vpc_tags" {
  type    = list(string)
  default = []
}

variable "cpu_limit" {
  type    = string
  default = "1"
}

variable "memory_limit" {
  type    = string
  default = "512Mi"
}

variable "startup_cpu_boost" {
  type    = bool
  default = false
}

variable "cpu_idle" {
  type    = bool
  default = false
}
