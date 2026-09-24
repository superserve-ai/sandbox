# Global proxy frontends are owned by the use-cell state.  The URL maps retain
# all observed host rules while switching only the proxy backend references;
# this is also the dependency-checked reassignment of the retired central
# destinations to the us-east4 generation.

locals {
  use4_proxy_http_backend = module.proxy_generations["use4"].generation_backend_services["public-http"]
  use4_proxy_tcp_backend  = module.proxy_generations["use4"].generation_backend_services["public-tcp"]
  use4_redirect_backend   = module.proxy_generations["use4"].generation_backend_services.redirect
  usw2_proxy_http_backend = "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/backendServices/proxy-usw2-public-http-generations"

  # This is the complete host/path inventory adopted from the production URL
  # map describe output.  Keep the simple proxy maps explicit too: an empty
  # rule collection is part of their contract, rather than an omitted field
  # that Terraform could interpret as permission to replace unmanaged rules.
  use4_proxy_url_map_inventory = {
    "sandbox-proxy-url-map" = {
      default_service = local.use4_proxy_http_backend
      host_rules      = []
      path_matchers   = []
    }
    "sandbox-proxy-url-map-usw2" = {
      default_service = local.usw2_proxy_http_backend
      host_rules      = []
      path_matchers   = []
    }
  }

  use4_proxy_dataplane_inventory = {
    host_rules = [
      {
        hosts        = ["*.usw-sandbox.superserve.ai", "usw-sandbox.superserve.ai"]
        path_matcher = "usw"
      },
      {
        hosts = [
          "*.sandbox.superserve.ai",
          "*.use-sandbox.superserve.ai",
          "sandbox.superserve.ai",
          "use-sandbox.superserve.ai",
        ]
        path_matcher = "use"
      },
      {
        hosts        = ["api-usw.superserve.ai"]
        path_matcher = "api-usw"
      },
    ]
    path_matchers = [
      {
        name            = "usw"
        default_service = local.usw2_proxy_http_backend
      },
      {
        name            = "use"
        default_service = local.use4_proxy_http_backend
      },
      {
        name            = "api-usw"
        default_service = "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/backendServices/dp-api-usw"
      },
    ]
  }

  # A malformed or partial inventory must stop the apply before any imported
  # URL map can be updated.  Backend cutover is only safe after every host
  # rule resolves to a declared path matcher and every matcher is represented.
  use4_proxy_routing_inventory_complete = (
    length(local.use4_proxy_dataplane_inventory.host_rules) == 3 &&
    length(local.use4_proxy_dataplane_inventory.path_matchers) == 3 &&
    toset([for rule in local.use4_proxy_dataplane_inventory.host_rules : rule.path_matcher]) ==
    toset([for matcher in local.use4_proxy_dataplane_inventory.path_matchers : matcher.name]) &&
    alltrue([
      for url_map in values(local.use4_proxy_url_map_inventory) :
      length(url_map.host_rules) == 0 && length(url_map.path_matchers) == 0
    ])
  )

  # Read the backend references from the adopted frontend resources.  The
  # dataplane has both a default and an east-cell path matcher; both are part
  # of the public HTTP route and must point at the same generation backend.
  use4_proxy_frontend_backend_references = {
    "public-http" = concat(
      [
        google_compute_url_map.proxy_frontends["sandbox-proxy-url-map"].default_service,
        google_compute_url_map.proxy_dataplane.default_service,
      ],
      [for matcher in google_compute_url_map.proxy_dataplane.path_matcher : matcher.default_service if matcher.name == "use"]
    )
    "public-tcp" = [google_compute_target_ssl_proxy.proxy.backend_service]
    redirect     = [google_compute_target_tcp_proxy.redirect.backend_service]
  }

  # The west generation state consumes the applied references for its route
  # through the read-only remote-state output below. Keep this derived from
  # the adopted URL-map resources so the west rollout cannot self-authorize
  # against a copied backend name.
  usw2_proxy_frontend_backend_references = {
    "public-http" = [
      google_compute_url_map.proxy_frontends["sandbox-proxy-url-map-usw2"].default_service,
      [for matcher in google_compute_url_map.proxy_dataplane.path_matcher : matcher.default_service if matcher.name == "usw"][0],
    ]
  }

  use4_proxy_frontend_resources = {
    "public-http" = [
      "url-map:${google_compute_url_map.proxy_frontends["sandbox-proxy-url-map"].name}",
      "url-map:${google_compute_url_map.proxy_dataplane.name}",
      "target-https-proxy:${google_compute_target_https_proxy.adopted["dp-https"].name}",
      "target-https-proxy:${google_compute_target_https_proxy.adopted["sandbox-proxy-https-target"].name}",
      "forwarding-rule:${google_compute_global_forwarding_rule.proxy_frontends["dataplane"].name}",
      "forwarding-rule:${google_compute_global_forwarding_rule.proxy_frontends["east_https"].name}",
    ]
    "public-tcp" = [
      "target-ssl-proxy:${google_compute_target_ssl_proxy.proxy.name}",
      "forwarding-rule:${google_compute_global_forwarding_rule.proxy_frontends["ssl"].name}",
    ]
    redirect = [
      "target-tcp-proxy:${google_compute_target_tcp_proxy.redirect.name}",
      "forwarding-rule:${google_compute_global_forwarding_rule.proxy_frontends["redirect"].name}",
    ]
  }
}

resource "google_compute_url_map" "proxy_frontends" {
  for_each = local.use4_proxy_url_map_inventory

  name            = each.key
  project         = local.project_id
  default_service = each.value.default_service

  dynamic "host_rule" {
    for_each = each.value.host_rules
    content {
      hosts        = host_rule.value.hosts
      path_matcher = host_rule.value.path_matcher
    }
  }

  dynamic "path_matcher" {
    for_each = each.value.path_matchers
    content {
      name            = path_matcher.value.name
      default_service = path_matcher.value.default_service
    }
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = local.use4_proxy_routing_inventory_complete
      error_message = "Refusing proxy frontend migration: the adopted production URL-map routing inventory is incomplete."
    }
  }
}

resource "google_compute_url_map" "proxy_dataplane" {
  name            = "sandbox-dataplane"
  project         = local.project_id
  default_service = local.use4_proxy_http_backend

  dynamic "host_rule" {
    for_each = local.use4_proxy_dataplane_inventory.host_rules
    content {
      hosts        = host_rule.value.hosts
      path_matcher = host_rule.value.path_matcher
    }
  }

  dynamic "path_matcher" {
    for_each = local.use4_proxy_dataplane_inventory.path_matchers
    content {
      name            = path_matcher.value.name
      default_service = path_matcher.value.default_service
    }
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = local.use4_proxy_routing_inventory_complete
      error_message = "Refusing proxy frontend migration: the adopted production URL-map routing inventory is incomplete."
    }
  }
}

resource "google_compute_target_ssl_proxy" "proxy" {
  name            = "sandbox-proxy-ssl"
  project         = local.project_id
  backend_service = local.use4_proxy_tcp_backend
  certificate_map = "projects/${local.project_id}/locations/global/certificateMaps/sandbox-proxy-cert-map"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_target_tcp_proxy" "redirect" {
  name            = "sandbox-proxy-tcp"
  project         = local.project_id
  backend_service = local.use4_redirect_backend
  proxy_header    = "NONE"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_global_forwarding_rule" "proxy_frontends" {
  for_each = {
    dataplane = {
      name   = "dp-fr"
      ip     = "136.68.212.233"
      port   = "443"
      target = google_compute_target_https_proxy.adopted["dp-https"].self_link
    }
    ssl = {
      name   = "sandbox-proxy-https-fwd"
      ip     = "34.102.191.241"
      port   = "443"
      target = google_compute_target_ssl_proxy.proxy.self_link
    }
    redirect = {
      name   = "sandbox-proxy-http-fwd"
      ip     = "34.102.191.241"
      port   = "80"
      target = google_compute_target_tcp_proxy.redirect.self_link
    }
    east_https = {
      name   = "sandbox-proxy-https-fwd-new"
      ip     = "34.8.17.193"
      port   = "443"
      target = google_compute_target_https_proxy.adopted["sandbox-proxy-https-target"].self_link
    }
    west_https = {
      name   = "sandbox-proxy-https-fwd-usw2"
      ip     = "34.120.241.214"
      port   = "443"
      target = google_compute_target_https_proxy.adopted["sandbox-proxy-https-target-usw2"].self_link
    }
  }

  name                  = each.value.name
  project               = local.project_id
  ip_address            = each.value.ip
  port_range            = each.value.port
  load_balancing_scheme = "EXTERNAL_MANAGED"
  target                = each.value.target

  lifecycle {
    prevent_destroy = true
  }
}

import {
  to = google_compute_url_map.proxy_frontends["sandbox-proxy-url-map"]
  id = "projects/rayai-prod/global/urlMaps/sandbox-proxy-url-map"
}

import {
  to = google_compute_url_map.proxy_frontends["sandbox-proxy-url-map-usw2"]
  id = "projects/rayai-prod/global/urlMaps/sandbox-proxy-url-map-usw2"
}

import {
  to = google_compute_url_map.proxy_dataplane
  id = "projects/rayai-prod/global/urlMaps/sandbox-dataplane"
}

import {
  to = google_compute_target_ssl_proxy.proxy
  id = "projects/rayai-prod/global/targetSslProxies/sandbox-proxy-ssl"
}

import {
  to = google_compute_target_tcp_proxy.redirect
  id = "projects/rayai-prod/global/targetTcpProxies/sandbox-proxy-tcp"
}

import {
  to = google_compute_global_forwarding_rule.proxy_frontends["dataplane"]
  id = "projects/rayai-prod/global/forwardingRules/dp-fr"
}

import {
  to = google_compute_global_forwarding_rule.proxy_frontends["ssl"]
  id = "projects/rayai-prod/global/forwardingRules/sandbox-proxy-https-fwd"
}

import {
  to = google_compute_global_forwarding_rule.proxy_frontends["redirect"]
  id = "projects/rayai-prod/global/forwardingRules/sandbox-proxy-http-fwd"
}

import {
  to = google_compute_global_forwarding_rule.proxy_frontends["east_https"]
  id = "projects/rayai-prod/global/forwardingRules/sandbox-proxy-https-fwd-new"
}

import {
  to = google_compute_global_forwarding_rule.proxy_frontends["west_https"]
  id = "projects/rayai-prod/global/forwardingRules/sandbox-proxy-https-fwd-usw2"
}
