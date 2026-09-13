output "api_contract" {
  description = "Rendered staging API contract."
  value       = module.api.contract
}

output "network_contract" {
  description = "Rendered staging network contract."
  value       = module.network.contract
}

output "deployment_config" {
  description = "Deployment identity for this environment."
  value = {
    environment     = var.environment
    region          = var.region
    zone            = var.zone
    resource_suffix = coalesce(var.resource_suffix, var.environment)
  }
}

output "supabase" {
  description = "Supabase configuration for this deployment."
  sensitive   = true
  value = {
    url                      = var.supabase_url
    database_url_secret_name = coalesce(var.database_url_secret_name, "database-url-${coalesce(var.resource_suffix, var.environment)}")
  }
}

output "qm_contract" {
  description = "Rendered QM shared-infrastructure contract; null while enable_qm is false."
  value       = one(module.qm[*].contract)
}

output "qm_dns_authorization" {
  description = "DNS record to publish for the QM wildcard certificate; null while enable_qm is false."
  value       = one(module.qm[*].dns_authorization)
}
