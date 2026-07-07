output "network_contract" {
  description = "Rendered new-region network contract."
  value       = module.network.contract
}

output "sandbox_host_contract" {
  description = "Rendered new-region sandbox host contract."
  value       = module.sandbox_host.contract
}

output "deployment_config" {
  description = "Deployment identity for this environment."
  value = {
    environment            = var.environment
    region                 = var.region
    zone                   = var.zone
    resource_suffix        = coalesce(var.resource_suffix, var.environment)
    service_account_suffix = coalesce(var.service_account_suffix, coalesce(var.resource_suffix, var.environment))
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
