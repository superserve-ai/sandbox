# This state owns the staging proxy frontends and the generation backend
# topology. The serving host is the already-running host from the inventory;
# Applied frontend references remain on the legacy backend until the operator
# has switched and checked every imported frontend in the maintenance window.
variable "proxy_generation_cells" {
  type = map(object({
    zone            = string
    instance        = string
    ip              = string
    network         = string
    subnetwork      = string
    target_tags     = list(string)
    service_account = string
    routes = map(object({
      protocol = string
      listener = string
      probe    = string
      probe_ip = optional(string)
    }))
  }))

  validation {
    condition = length(var.proxy_generation_cells) > 0 && alltrue([
      for cell in values(var.proxy_generation_cells) : alltrue([
        for route in ["public-http", "public-tcp", "redirect"] : contains(keys(cell.routes), route)
      ])
    ])
    error_message = "Each environment must declare a generation cell with public HTTP, public TCP, and redirect frontend routes."
  }
}

module "proxy_generations" {
  for_each        = var.proxy_generation_cells
  source          = "../../../modules/proxy-lb"
  project_id      = local.project_id
  environment     = local.environment
  region          = local.region
  name            = "proxy-${each.key}"
  generation_cell = each.value
}

output "proxy_generation_bootstrap" {
  description = "Module-only manifest available after generation preparation, before frontend import or cutover."
  value       = { for key, cell in module.proxy_generations : key => cell.generation_rollout }
}

locals {
  # The rollout gate is derived from the adopted frontend resources below,
  # rather than accepting the input acknowledgement as proof of a cutover.
  # Keeping this comparison in Terraform makes the manifest describe the
  # references that were actually applied to the URL map and target proxies.
  staging_frontend_migration_complete = alltrue([
    for route, backend in {
      "public-http" = module.proxy_generations["staging"].generation_backend_services["public-http"]
      "public-tcp"  = module.proxy_generations["staging"].generation_backend_services["public-tcp"]
      redirect      = module.proxy_generations["staging"].generation_backend_services.redirect
      } : length(local.staging_proxy_frontend_backend_references[route]) > 0 && alltrue([
        for reference in local.staging_proxy_frontend_backend_references[route] : reference == backend
    ])
  ])
}

output "proxy_generation_rollout" {
  description = "Host manifests consumed by Deploy Proxy: bootstrap an upgraded generation, migrate frontends with Terraform, then resume after applied references are verified."
  value = { for key, cell in module.proxy_generations : key => merge(cell.generation_rollout, {
    serving_host                = cell.generation_rollout.serving_host
    migration_complete          = local.staging_frontend_migration_complete
    frontend_backend_references = local.staging_proxy_frontend_backend_references
    frontend_resources          = local.staging_proxy_frontend_resources
  }) }
}
