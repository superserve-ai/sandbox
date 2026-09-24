output "network_contract" {
  description = "Rendered us-east4 network contract."
  value       = module.network.contract
}

output "sandbox_host_contract" {
  description = "Rendered us-east4 sandbox host contract."
  value       = module.sandbox_host_c.contract
}

output "controlplane_identity_contract" {
  description = "Per-cell Cloud Run identity, backup read boundary, secret dependencies, and migration ownership."
  value       = local.controlplane_identity_contract
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
