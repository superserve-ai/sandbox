variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "Region of the backing Cloud Run service (serverless NEG region)."
  type        = string
}

variable "cloud_run_service" {
  description = "Name of the Cloud Run service to front."
  type        = string
}

variable "domain" {
  description = "Public hostname served by this load balancer."
  type        = string
}

variable "neg_name" {
  description = "Serverless network endpoint group name."
  type        = string
}

variable "backend_service_name" {
  description = "Backend service name."
  type        = string
}

variable "url_map_name" {
  description = "URL map name."
  type        = string
}

variable "dns_authorization_name" {
  description = "Certificate Manager DNS authorization name."
  type        = string
}

variable "certificate_name" {
  description = "Certificate Manager managed certificate name."
  type        = string
}

variable "certificate_map_name" {
  description = "Certificate Manager certificate map name."
  type        = string
}

variable "certificate_map_entry_name" {
  description = "Certificate Manager certificate map entry name."
  type        = string
}

variable "address_name" {
  description = "Global static IP address name."
  type        = string
}

variable "https_proxy_name" {
  description = "Target HTTPS proxy name."
  type        = string
}

variable "forwarding_rule_name" {
  description = "Global forwarding rule name."
  type        = string
}

variable "backend_timeout_sec" {
  description = "Backend timeout for proxied Cloud Run requests."
  type        = number
  default     = 30
}
