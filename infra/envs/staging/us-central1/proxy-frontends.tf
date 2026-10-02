variable "proxy_generation_frontends_enabled" {
  description = "Use generation backends only after the explicit frontend migration."
  type        = bool
  default     = false
}

# The staging state owns the existing public proxy frontends.  Importing these
# resources makes the first migration an explicit backend-reference change;
# addresses, certificate maps, TLS termination, and the HTTP redirect remain
# unchanged while the controller owns NEG endpoint membership.

locals {
  staging_proxy_http_backend = var.proxy_generation_frontends_enabled ? module.proxy_generations["staging"].generation_backend_services["public-http"] : "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/backendServices/sandbox-proxy-backend-https"
  staging_proxy_tcp_backend  = var.proxy_generation_frontends_enabled ? module.proxy_generations["staging"].generation_backend_services["public-tcp"] : "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/backendServices/sandbox-proxy-backend"
  staging_redirect_backend   = var.proxy_generation_frontends_enabled ? module.proxy_generations["staging"].generation_backend_services.redirect : "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/backendServices/sandbox-proxy-redirect-backend"

  # These values are read back from the adopted frontend resources, rather
  # than copied from the migration input.  The rollout controller compares
  # them with every route in the generation manifest before retiring legacy
  # membership.
  staging_proxy_frontend_backend_references = {
    "public-http" = [google_compute_url_map.proxy.default_service]
    "public-tcp"  = [google_compute_target_ssl_proxy.proxy.backend_service]
    redirect      = [google_compute_target_tcp_proxy.redirect.backend_service]
  }

  staging_proxy_frontend_resources = {
    "public-http" = [
      "url-map:${google_compute_url_map.proxy.name}",
      "target-https-proxy:${google_compute_target_https_proxy.proxy.name}",
      "forwarding-rule:${google_compute_global_forwarding_rule.proxy["https"].name}",
    ]
    "public-tcp" = [
      "target-ssl-proxy:${google_compute_target_ssl_proxy.proxy.name}",
      "forwarding-rule:${google_compute_global_forwarding_rule.proxy["ssl"].name}",
    ]
    redirect = [
      "target-tcp-proxy:${google_compute_target_tcp_proxy.redirect.name}",
      "forwarding-rule:${google_compute_global_forwarding_rule.proxy["redirect"].name}",
    ]
  }
}

resource "google_compute_url_map" "proxy" {
  name            = "sandbox-proxy-url-map"
  project         = local.project_id
  default_service = local.staging_proxy_http_backend

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_target_https_proxy" "proxy" {
  name    = "sandbox-proxy-https-target"
  project = local.project_id
  url_map = google_compute_url_map.proxy.id
  # Preserve the imported API spelling so adoption does not reattach the map.
  certificate_map = "https://certificatemanager.googleapis.com/v1/projects/${local.project_id}/locations/global/certificateMaps/sandbox-proxy-cert-map"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_target_ssl_proxy" "proxy" {
  name            = "sandbox-proxy-ssl"
  project         = local.project_id
  backend_service = local.staging_proxy_tcp_backend
  certificate_map = "https://certificatemanager.googleapis.com/v1/projects/${local.project_id}/locations/global/certificateMaps/sandbox-proxy-cert-map"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_target_tcp_proxy" "redirect" {
  name            = "sandbox-proxy-tcp"
  project         = local.project_id
  backend_service = local.staging_redirect_backend
  proxy_header    = "NONE"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_global_forwarding_rule" "proxy" {
  for_each = {
    https = {
      name    = "sandbox-proxy-https-fwd-test"
      address = "8.232.119.0"
      port    = "443"
      target  = google_compute_target_https_proxy.proxy.self_link
    }
    ssl = {
      name    = "sandbox-proxy-https-fwd"
      address = "35.241.4.94"
      port    = "443"
      target  = google_compute_target_ssl_proxy.proxy.self_link
    }
    redirect = {
      name    = "sandbox-proxy-http-fwd"
      address = "35.241.4.94"
      port    = "80"
      target  = google_compute_target_tcp_proxy.redirect.self_link
    }
  }

  name                  = each.value.name
  project               = local.project_id
  ip_address            = each.value.address
  port_range            = each.value.port
  load_balancing_scheme = "EXTERNAL_MANAGED"
  target                = each.value.target

  lifecycle {
    prevent_destroy = true
  }
}

import {
  to = google_compute_url_map.proxy
  id = "projects/rayai-dev/global/urlMaps/sandbox-proxy-url-map"
}

import {
  to = google_compute_target_https_proxy.proxy
  id = "projects/rayai-dev/global/targetHttpsProxies/sandbox-proxy-https-target"
}

import {
  to = google_compute_target_ssl_proxy.proxy
  id = "projects/rayai-dev/global/targetSslProxies/sandbox-proxy-ssl"
}

import {
  to = google_compute_target_tcp_proxy.redirect
  id = "projects/rayai-dev/global/targetTcpProxies/sandbox-proxy-tcp"
}

import {
  to = google_compute_global_forwarding_rule.proxy["https"]
  id = "projects/rayai-dev/global/forwardingRules/sandbox-proxy-https-fwd-test"
}

import {
  to = google_compute_global_forwarding_rule.proxy["ssl"]
  id = "projects/rayai-dev/global/forwardingRules/sandbox-proxy-https-fwd"
}

import {
  to = google_compute_global_forwarding_rule.proxy["redirect"]
  id = "projects/rayai-dev/global/forwardingRules/sandbox-proxy-http-fwd"
}
