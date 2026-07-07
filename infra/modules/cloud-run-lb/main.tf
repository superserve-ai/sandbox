terraform {
  required_version = ">= 1.5.0"
}

locals {
  certificate_self_links = [
    for cert in google_compute_managed_ssl_certificate.certificates :
    cert.self_link
  ]
}

resource "google_compute_global_address" "this" {
  project = var.project_id
  name    = var.address_name
}

resource "google_compute_region_network_endpoint_group" "cloud_run" {
  for_each = var.cloud_run_backends

  project               = var.project_id
  name                  = each.value.neg_name
  region                = each.value.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = each.value.service_name
  }
}

resource "google_compute_backend_service" "cloud_run" {
  for_each = var.cloud_run_backends

  project               = var.project_id
  name                  = each.value.backend_service_name
  protocol              = "HTTP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = var.backend_timeout_sec

  backend {
    group = google_compute_region_network_endpoint_group.cloud_run[each.key].id
  }
}

resource "google_compute_url_map" "https" {
  project = var.project_id
  name    = var.https_url_map_name

  default_service = google_compute_backend_service.cloud_run[var.default_backend_key].id

  dynamic "host_rule" {
    for_each = var.host_routes

    content {
      hosts        = [host_rule.key]
      path_matcher = replace(host_rule.key, ".", "-")
    }
  }

  dynamic "path_matcher" {
    for_each = var.host_routes

    content {
      name            = replace(path_matcher.key, ".", "-")
      default_service = google_compute_backend_service.cloud_run[path_matcher.value].id
    }
  }
}

resource "google_compute_url_map" "http_redirect" {
  project = var.project_id
  name    = var.http_redirect_url_map_name

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_managed_ssl_certificate" "certificates" {
  for_each = var.managed_ssl_certificates

  project = var.project_id
  name    = each.value.name

  managed {
    domains = each.value.domains
  }
}

resource "google_compute_target_https_proxy" "this" {
  project          = var.project_id
  name             = var.https_proxy_name
  url_map          = google_compute_url_map.https.id
  ssl_certificates = local.certificate_self_links
}

resource "google_compute_target_http_proxy" "redirect" {
  project = var.project_id
  name    = var.http_proxy_name
  url_map = google_compute_url_map.http_redirect.id
}

resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = var.https_forwarding_rule_name
  ip_address            = google_compute_global_address.this.address
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  network_tier          = "PREMIUM"
  target                = google_compute_target_https_proxy.this.id
}

resource "google_compute_global_forwarding_rule" "http" {
  project               = var.project_id
  name                  = var.http_forwarding_rule_name
  ip_address            = google_compute_global_address.this.address
  port_range            = "80"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  network_tier          = "PREMIUM"
  target                = google_compute_target_http_proxy.redirect.id
}

locals {
  contract = {
    project_id      = var.project_id
    environment     = var.environment
    address         = google_compute_global_address.this.address
    default_backend = var.default_backend_key
    host_routes     = var.host_routes
    certificates    = { for key, cert in google_compute_managed_ssl_certificate.certificates : key => cert.name }
    backends        = { for key, backend in google_compute_backend_service.cloud_run : key => backend.id }
  }
}
