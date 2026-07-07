variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Logical environment name."
  type        = string
}

variable "address_name" {
  description = "Global static IP address name."
  type        = string
}

variable "cloud_run_backends" {
  description = "Regional Cloud Run backends keyed by routing label, for example usc or usw."
  type = map(object({
    region               = string
    service_name         = string
    neg_name             = string
    backend_service_name = string
  }))
}

variable "default_backend_key" {
  description = "Backend key used when no host-specific route matches."
  type        = string
}

variable "host_routes" {
  description = "Hostname to backend key routing map. This makes usc/usw routing an explicit Terraform change."
  type        = map(string)
  default     = {}
}

variable "backend_timeout_sec" {
  description = "Backend timeout for proxied Cloud Run requests."
  type        = number
  default     = 30
}

variable "https_url_map_name" {
  description = "HTTPS URL map name."
  type        = string
}

variable "http_redirect_url_map_name" {
  description = "HTTP redirect URL map name."
  type        = string
}

variable "https_proxy_name" {
  description = "Target HTTPS proxy name."
  type        = string
}

variable "http_proxy_name" {
  description = "Target HTTP proxy name."
  type        = string
}

variable "https_forwarding_rule_name" {
  description = "HTTPS global forwarding rule name."
  type        = string
}

variable "http_forwarding_rule_name" {
  description = "HTTP global forwarding rule name."
  type        = string
}

variable "managed_ssl_certificates" {
  description = "Google-managed SSL certificates keyed by logical name."
  type = map(object({
    name    = string
    domains = list(string)
  }))
  default = {}
}
