output "api_contract" {
  description = "Rendered staging API contract."
  value       = module.api.contract
}

output "controlplane_identity_contract" {
  description = "Per-cell Cloud Run identity, backup read boundary, secret dependencies, and migration ownership."
  value       = local.controlplane_identity_contract
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
