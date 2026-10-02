# Global HTTPS proxies share the policy in this state, alongside the API LB.
# The proxy URL maps and forwarding rules are adopted in proxy-frontends.tf so
# this state can perform the reviewed backend cutover without changing TLS.
resource "google_compute_ssl_policy" "https" {
  project         = local.project_id
  name            = "superserve-https-tls12"
  min_tls_version = "TLS_1_2"
  profile         = "MODERN"
}

locals {
  adopted_https_proxies = {
    "dp-https" = {
      url_map          = "sandbox-dataplane"
      certificate_map  = "dp-certs"
      ssl_certificates = []
    }
    "sandbox-proxy-https-target" = {
      url_map          = "sandbox-proxy-url-map"
      certificate_map  = "sandbox-proxy-cert-map"
      ssl_certificates = []
    }
    "sandbox-proxy-https-target-usw2" = {
      url_map          = "sandbox-proxy-url-map-usw2"
      certificate_map  = "sandbox-proxy-cert-map-usw2"
      ssl_certificates = []
    }
    "superserve-api-https-proxy" = {
      url_map         = "superserve-api-url-map"
      certificate_map = null
      ssl_certificates = [
        "superserve-api-canary-cert",
        "superserve-api-regional-cert",
      ]
    }
  }
}

resource "google_compute_target_https_proxy" "adopted" {
  for_each = local.adopted_https_proxies

  project = local.project_id
  name    = each.key
  # The proxy frontends are adopted in proxy-frontends.tf. Keeping the URL-map
  # reference in this owning state makes the backend cutover explicit while
  # retaining the existing certificate map and TLS policy.
  url_map         = each.value.url_map == "sandbox-dataplane" ? google_compute_url_map.proxy_dataplane.id : try(google_compute_url_map.proxy_frontends[each.value.url_map].id, "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/urlMaps/${each.value.url_map}")
  ssl_policy      = google_compute_ssl_policy.https.id
  certificate_map = each.value.certificate_map == null ? null : "https://certificatemanager.googleapis.com/v1/projects/${local.project_id}/locations/global/certificateMaps/${each.value.certificate_map}"
  ssl_certificates = [
    for name in each.value.ssl_certificates :
    "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/sslCertificates/${name}"
  ]

  lifecycle {
    prevent_destroy = true
  }
}

import {
  to = google_compute_target_https_proxy.adopted["dp-https"]
  id = "projects/rayai-prod/global/targetHttpsProxies/dp-https"
}

import {
  to = google_compute_target_https_proxy.adopted["sandbox-proxy-https-target"]
  id = "projects/rayai-prod/global/targetHttpsProxies/sandbox-proxy-https-target"
}

import {
  to = google_compute_target_https_proxy.adopted["sandbox-proxy-https-target-usw2"]
  id = "projects/rayai-prod/global/targetHttpsProxies/sandbox-proxy-https-target-usw2"
}

import {
  to = google_compute_target_https_proxy.adopted["superserve-api-https-proxy"]
  id = "projects/rayai-prod/global/targetHttpsProxies/superserve-api-https-proxy"
}
