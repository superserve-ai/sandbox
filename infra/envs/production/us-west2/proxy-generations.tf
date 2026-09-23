# This state owns the west cell's generation backends. The global HTTPS
# frontend remains in the east owning state and references these explicit
# backend names after the serialized migration.
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
        # The west cell is served by the adopted regional HTTPS URL map.  Its
        # SSL/TCP and redirect frontends remain owned by the east state and do
        # not select this cell, so only the URL-map route belongs in this
        # cell's membership and readiness manifest.
        for route in ["public-http"] : contains(keys(cell.routes), route)
      ])
    ])
    error_message = "The west environment must declare a generation cell with the adopted public HTTP URL-map route."
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

# The global frontend resources remain owned by the east state. Read their
# applied backend references through the owning state's output so the west
# rollout manifest is evidence of the applied URL-map migration, rather than
# a copied acknowledgement or name.
data "terraform_remote_state" "use4" {
  backend = "gcs"

  config = {
    bucket = "superserve-terraform-state-prod"
    prefix = "production/us-east4"
  }
}

locals {
  # The global frontends are owned by the east state. Their backend identity is
  # a stable cross-state contract; the east state applies the actual URL-map
  # cutover and publishes the same identity in its rollout manifest.
  usw2_proxy_http_backend = "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/backendServices/proxy-usw2-public-http-generations"
  # The east output is absent until the owning state has applied this
  # migration-aware configuration. Keep planning and manifest generation
  # deterministic before that apply, but fail the migration gate closed.
  usw2_proxy_frontend_backend_references = try(
    data.terraform_remote_state.use4.outputs.proxy_west_frontend_backend_references,
    { "public-http" = [] }
  )

  # The adopted URL map and its HTTPS frontend are owned by the east state;
  # keep their stable resource identities in the west manifest so the
  # controller can distinguish an applied cross-state route from a bare
  # backend name.
  usw2_proxy_frontend_resources = {
    "public-http" = [
      "url-map:sandbox-proxy-url-map-usw2",
      "url-map:sandbox-dataplane",
      "target-https-proxy:dp-https",
      "target-https-proxy:sandbox-proxy-https-target-usw2",
      "forwarding-rule:sandbox-proxy-https-fwd-usw2",
    ]
  }

  # This state publishes the west backend references consumed by the owning
  # global frontend state.  The derived value is intentionally based on that
  # explicit reference inventory, not the caller's acknowledgement flag.
  usw2_frontend_migration_complete = alltrue([
    for route, backend in {
      "public-http" = module.proxy_generations["usw2"].generation_backend_services["public-http"]
      } : length(local.usw2_proxy_frontend_backend_references[route]) > 0 && alltrue([
        for reference in local.usw2_proxy_frontend_backend_references[route] : reference == backend
    ])
  ])
}

output "proxy_generation_rollout" {
  description = "Host manifests consumed by Deploy Proxy: bootstrap an upgraded generation, migrate frontends with Terraform, then resume after applied references are verified."
  value = { for key, cell in module.proxy_generations : key => merge(cell.generation_rollout, {
    serving_host                = cell.generation_rollout.serving_host
    migration_complete          = local.usw2_frontend_migration_complete
    frontend_backend_references = local.usw2_proxy_frontend_backend_references
    frontend_resources          = local.usw2_proxy_frontend_resources
  }) }
}
