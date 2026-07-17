output "network_contract" {
  description = "Rendered us-east4 network contract."
  value       = module.network.contract
}

output "sandbox_host_contract" {
  description = "Rendered us-east4 sandbox host contract."
  value       = module.sandbox_host.contract
}

output "deployment_config" {
  description = "Deployment identity for this environment."
  value = {
    environment            = var.environment
    region                 = var.region
    zone                   = var.zone
    resource_suffix        = local.resource_suffix
    service_account_suffix = local.service_account_suffix
  }
}
