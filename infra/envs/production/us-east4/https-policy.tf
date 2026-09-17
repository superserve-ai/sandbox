# Global HTTPS proxies share the policy in this state, alongside the API LB.
# Adopt only the proxies; existing URL maps, certificates, and forwarding rules
# retain their current ownership and configuration.
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

  project         = local.project_id
  name            = each.key
  url_map         = "https://www.googleapis.com/compute/v1/projects/${local.project_id}/global/urlMaps/${each.value.url_map}"
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
