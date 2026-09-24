# Parallel backends avoid the instance-group / NEG backend-type migration seam.
# Endpoint membership is intentionally absent: the host rollout controller owns it.
variable "generation_cell" {
  type = object({
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
  })
  default = null
  validation {
    condition = var.generation_cell == null ? true : alltrue([
      for route in values(var.generation_cell.routes) : contains(["TCP", "HTTP", "HTTPS", "HTTP2"], route.protocol) && contains(["public", "redirect"], route.listener)
    ])
    error_message = "Generation routes require a supported backend protocol and public or redirect listener."
  }
}

variable "staging_project_wide_generation_endpoints" {
  description = "Explicit staging exception: allow runtime NEG read/attach/detach throughout the project. Production cannot opt in."
  type        = bool
  default     = false
  validation {
    condition     = !var.staging_project_wide_generation_endpoints || var.environment == "staging"
    error_message = "Project-wide generation endpoint access is restricted to staging."
  }
}

locals {
  generation_routes = var.generation_cell == null ? {} : var.generation_cell.routes
  generation_http_routes = {
    for key, route in local.generation_routes : key => route
    if contains(["HTTP", "HTTPS", "HTTP2"], route.protocol)
  }
  generation_tcp_routes = {
    for key, route in local.generation_routes : key => route
    if route.protocol == "TCP"
  }
}

resource "google_compute_network_endpoint_group" "generation" {
  for_each              = local.generation_routes
  project               = var.project_id
  name                  = "${var.name}-${each.key}-generations"
  zone                  = var.generation_cell.zone
  network               = var.generation_cell.network
  subnetwork            = var.generation_cell.subnetwork
  network_endpoint_type = "GCE_VM_IP_PORT"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_health_check" "generation_http" {
  for_each            = local.generation_http_routes
  project             = var.project_id
  name                = "${var.name}-${each.key}-generations"
  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 2

  http_health_check {
    port_specification = "USE_SERVING_PORT"
    host               = "proxy-readiness.invalid"
    request_path       = "/health"
    # Keep HTTP-family LB health tied to proxy/VMD readiness, not just a 200.
    response = "\"resolver_ready\":true"
  }
}

resource "google_compute_health_check" "generation_tcp" {
  for_each            = local.generation_tcp_routes
  project             = var.project_id
  name                = "${var.name}-${each.key}-generations"
  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 2

  tcp_health_check {
    # TCP health can establish the listener only; resolver readiness is
    # gated by the candidate local/public readiness checks.
    port_specification = "USE_SERVING_PORT"
  }
}

resource "google_compute_backend_service" "generation" {
  for_each                        = local.generation_routes
  project                         = var.project_id
  name                            = "${var.name}-${each.key}-generations"
  protocol                        = each.value.protocol
  load_balancing_scheme           = "EXTERNAL_MANAGED"
  timeout_sec                     = each.value.listener == "public" ? 86400 : 30
  connection_draining_timeout_sec = 3600
  health_checks = [
    each.value.protocol == "TCP" ? google_compute_health_check.generation_tcp[each.key].id : google_compute_health_check.generation_http[each.key].id,
  ]
  backend {
    group                        = google_compute_network_endpoint_group.generation[each.key].id
    balancing_mode               = each.value.protocol == "TCP" ? "CONNECTION" : "RATE"
    max_connections_per_endpoint = each.value.protocol == "TCP" ? 10000 : null
    max_rate_per_endpoint        = each.value.protocol == "TCP" ? null : 10000
  }
  log_config {
    enable      = true
    sample_rate = 1
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_firewall" "generation" {
  count         = var.generation_cell == null ? 0 : 1
  project       = var.project_id
  name          = "${var.name}-generation-lb"
  network       = var.generation_cell.network
  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
  target_tags   = var.generation_cell.target_tags
  allow {
    protocol = "tcp"
    # Bootstrap adopts the legacy proxy before the frontend migration, so
    # health checks must be able to reach its public and redirect listeners.
    # Keep the source ranges restricted to Google's LB health-check networks;
    # peer and local-target ports remain private to the host.
    ports = ["5007", "5008", "5100", "5101", "5110", "5111"]
  }
}

resource "google_project_iam_custom_role" "generation" {
  count   = var.generation_cell == null ? 0 : 1
  project = var.project_id
  role_id = "${replace(var.name, "-", "_")}_proxy_endpoints"
  title   = "Proxy endpoint membership"
  permissions = [
    # Listing endpoints is authorized by the group's get permission.
    "compute.networkEndpointGroups.get",
    "compute.networkEndpointGroups.attachNetworkEndpoints",
    "compute.networkEndpointGroups.detachNetworkEndpoints",
  ]
}

resource "google_project_iam_member" "generation" {
  count   = var.generation_cell == null ? 0 : 1
  project = var.project_id
  role    = google_project_iam_custom_role.generation[0].name
  member  = "serviceAccount:${var.generation_cell.service_account}"

  # NEG resource.type/name attributes are unsupported and fail closed. Keep
  # that hold outside the explicit staging exception until cell isolation is
  # implemented with supported IAM attributes and validated in the cloud.
  dynamic "condition" {
    for_each = var.staging_project_wide_generation_endpoints ? [] : [1]
    content {
      title       = "Cell-owned proxy generation NEGs"
      description = "Restrict NEG membership operations to this cell's generation NEGs."
      expression  = "resource.type == 'compute.googleapis.com/NetworkEndpointGroup' && resource.name.startsWith('projects/${var.project_id}/zones/${var.generation_cell.zone}/networkEndpointGroups/${var.name}-')"
    }
  }
}

resource "google_project_iam_custom_role" "generation_support" {
  count   = var.generation_cell == null ? 0 : 1
  project = var.project_id
  role_id = "${replace(var.name, "-", "_")}_proxy_endpoint_support"
  title   = "Proxy endpoint controller support"
  permissions = [
    "compute.instances.use",
    # Backend get also authorizes the getHealth API method.
    "compute.backendServices.get",
    "compute.zoneOperations.get",
  ]
}

resource "google_project_iam_member" "generation_support" {
  count   = var.generation_cell == null ? 0 : 1
  project = var.project_id
  role    = google_project_iam_custom_role.generation_support[0].name
  member  = "serviceAccount:${var.generation_cell.service_account}"
}

resource "google_storage_bucket" "generation_ownership" {
  count                       = var.generation_cell == null ? 0 : 1
  project                     = var.project_id
  name                        = "${var.project_id}-${var.name}-ownership"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  # Ownership must not expire while an interrupted controller can still run.
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "generation_ownership" {
  count  = var.generation_cell == null ? 0 : 1
  bucket = google_storage_bucket.generation_ownership[0].name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${var.generation_cell.service_account}"
}

output "generation_rollout" {
  description = "Install for bootstrap before frontend migration; resume only after applied frontend references match every declared route."
  value = var.generation_cell == null ? null : {
    project  = var.project_id
    zone     = var.generation_cell.zone
    instance = var.generation_cell.instance
    ip       = var.generation_cell.ip
    # Keep the statically managed serving identity explicit. Manual standby
    # deployments reuse these cell routes while substituting their discovered
    # host identity in deploy-proxy.py.
    serving_host = {
      project  = var.project_id
      zone     = var.generation_cell.zone
      instance = var.generation_cell.instance
      ip       = var.generation_cell.ip
    }
    ownership_bucket = google_storage_bucket.generation_ownership[0].name
    routes = [for key, route in local.generation_routes : {
      name              = key
      neg               = google_compute_network_endpoint_group.generation[key].name
      backend           = google_compute_backend_service.generation[key].name
      backend_self_link = google_compute_backend_service.generation[key].self_link
      listener          = route.listener
      probe             = route.probe
      probe_ip          = route.probe_ip
    }]
  }
}
