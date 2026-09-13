# Wildcard edge for tenant hostnames. Mirrors cloud-run-cert-lb (serverless
# NEG -> backend -> URL map -> HTTPS proxy with a Certificate Manager map) but
# the URL map's per-tenant host rules and their serverless NEGs are added by
# the provisioner at runtime, so Terraform owns only the default route and
# ignores host_rule/path_matcher drift. cloud-run-lb's :80 -> :443 redirect is
# kept so a bare http://<slug>.<domain> still lands somewhere useful.

# A single DNS authorization for <domain> covers both <domain> and *.<domain>
# in a managed certificate, so tenant hostnames need no per-tenant issuance.
resource "google_certificate_manager_dns_authorization" "this" {
  project  = var.project_id
  location = "global"
  name     = "${local.name}-dnsauth"
  domain   = var.domain
  labels   = var.labels

  # The first resource to consume var.domain, so an unset domain stops here
  # with a readable message instead of a null interpolation failure inside the
  # certificate. A precondition rather than a variable validation because the
  # root's qm_domain is legitimately null while enable_qm is false, and
  # preconditions are only evaluated for module instances that exist.
  lifecycle {
    precondition {
      condition     = var.domain != null && var.domain != ""
      error_message = "domain must be set when the qm module is enabled: tenant hostnames, the wildcard certificate, and the redirect service are all derived from it."
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_certificate_manager_certificate" "wildcard" {
  project  = var.project_id
  location = "global"
  name     = "${local.name}-wildcard"
  labels   = var.labels

  managed {
    domains            = [var.domain, "*.${var.domain}"]
    dns_authorizations = [google_certificate_manager_dns_authorization.this.id]
  }
}

resource "google_certificate_manager_certificate_map" "this" {
  project = var.project_id
  name    = local.name
  labels  = var.labels

  depends_on = [google_project_service.required]
}

resource "google_certificate_manager_certificate_map_entry" "wildcard" {
  project      = var.project_id
  name         = "${local.name}-wildcard"
  map          = google_certificate_manager_certificate_map.this.name
  hostname     = "*.${var.domain}"
  certificates = [google_certificate_manager_certificate.wildcard.id]
  labels       = var.labels
}

resource "google_certificate_manager_certificate_map_entry" "apex" {
  project      = var.project_id
  name         = "${local.name}-apex"
  map          = google_certificate_manager_certificate_map.this.name
  hostname     = var.domain
  certificates = [google_certificate_manager_certificate.wildcard.id]
  labels       = var.labels
}

resource "google_compute_global_address" "edge" {
  project = var.project_id
  name    = "${local.name}-edge"
  labels  = var.labels
}

resource "google_compute_region_network_endpoint_group" "redirect" {
  project               = var.project_id
  name                  = "${local.name}-redirect"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.redirect.name
  }
}

resource "google_compute_backend_service" "redirect" {
  project               = var.project_id
  name                  = "${local.name}-redirect"
  protocol              = "HTTP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = var.backend_timeout_sec

  backend {
    group = google_compute_region_network_endpoint_group.redirect.id
  }
}

# Default route only. Tenant host rules (<slug>.<domain> -> that tenant's
# backend service) are appended by the provisioner with
# compute.loadBalancerAdmin; a Terraform apply must never strip them.
resource "google_compute_url_map" "https" {
  project         = var.project_id
  name            = "${local.name}-https"
  default_service = google_compute_backend_service.redirect.id

  lifecycle {
    ignore_changes = [
      host_rule,
      path_matcher,
    ]
  }
}

resource "google_compute_url_map" "http_redirect" {
  project = var.project_id
  name    = "${local.name}-http-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_https_proxy" "this" {
  project = var.project_id
  name    = "${local.name}-https"
  url_map = google_compute_url_map.https.id
  # Same versioned resource URL form cloud-run-cert-lb uses; the API stores
  # the map reference that way and a bare .id would plan a perpetual diff.
  certificate_map = "https://certificatemanager.googleapis.com/v1/${google_certificate_manager_certificate_map.this.id}"
}

resource "google_compute_target_http_proxy" "redirect" {
  project = var.project_id
  name    = "${local.name}-http"
  url_map = google_compute_url_map.http_redirect.id
}

resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = "${local.name}-https"
  ip_address            = google_compute_global_address.edge.address
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  network_tier          = "PREMIUM"
  target                = google_compute_target_https_proxy.this.id
  labels                = var.labels
}

resource "google_compute_global_forwarding_rule" "http" {
  project               = var.project_id
  name                  = "${local.name}-http"
  ip_address            = google_compute_global_address.edge.address
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  network_tier          = "PREMIUM"
  target                = google_compute_target_http_proxy.redirect.id
  labels                = var.labels
}

# Cloud DNS, only when the environment's zone lives in this project and is
# passed in. The authorization CNAME must resolve before Certificate Manager
# will issue, which is why the README applies the edge in two steps when DNS
# is managed elsewhere.
locals {
  manage_dns               = var.dns_managed_zone != null
  dns_authorization_record = try(google_certificate_manager_dns_authorization.this.dns_resource_record[0], null)
}

resource "google_dns_record_set" "dns_authorization" {
  count = local.manage_dns ? 1 : 0

  project      = var.project_id
  managed_zone = var.dns_managed_zone
  name         = local.dns_authorization_record.name
  type         = local.dns_authorization_record.type
  ttl          = var.dns_ttl
  rrdatas      = [local.dns_authorization_record.data]
}

resource "google_dns_record_set" "apex" {
  count = local.manage_dns ? 1 : 0

  project      = var.project_id
  managed_zone = var.dns_managed_zone
  name         = "${var.domain}."
  type         = "A"
  ttl          = var.dns_ttl
  rrdatas      = [google_compute_global_address.edge.address]
}

resource "google_dns_record_set" "wildcard" {
  count = local.manage_dns ? 1 : 0

  project      = var.project_id
  managed_zone = var.dns_managed_zone
  name         = "*.${var.domain}."
  type         = "A"
  ttl          = var.dns_ttl
  rrdatas      = [google_compute_global_address.edge.address]
}
