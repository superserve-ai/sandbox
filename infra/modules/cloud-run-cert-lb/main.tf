# Global external HTTPS load balancer fronting a single regional Cloud Run
# service, terminating TLS with a Certificate-Manager managed certificate via a
# certificate map (not classic google_compute_managed_ssl_certificate).
#
# Shape borrows from two existing modules:
#   - cloud-run-lb  : serverless NEG -> backend service -> url map
#   - proxy-lb      : Certificate Manager dns_authorization/certificate/map
#
# Unlike cloud-run-lb this is HTTPS-only (no :80 redirect) and uses a cert map
# on the target proxy instead of ssl_certificates, matching the live api.
# superserve.ai LB that was stood up imperatively during the host migration.
terraform {
  required_version = ">= 1.5.0"
}

resource "google_compute_region_network_endpoint_group" "cloud_run" {
  project               = var.project_id
  name                  = var.neg_name
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = var.cloud_run_service
  }
}

resource "google_compute_backend_service" "cloud_run" {
  project  = var.project_id
  name     = var.backend_service_name
  protocol = "HTTP"
  # Match the live backend created imperatively during the migration (classic
  # external scheme, no connection draining) so the import plan is a no-op.
  # Moving to EXTERNAL_MANAGED / draining would be a separate, reviewed change.
  load_balancing_scheme           = "EXTERNAL_MANAGED"
  connection_draining_timeout_sec = 0
  timeout_sec                     = var.backend_timeout_sec

  backend {
    group = google_compute_region_network_endpoint_group.cloud_run.id
  }
}

resource "google_compute_url_map" "this" {
  project         = var.project_id
  name            = var.url_map_name
  default_service = google_compute_backend_service.cloud_run.id
}

resource "google_certificate_manager_dns_authorization" "this" {
  project  = var.project_id
  location = "global"
  name     = var.dns_authorization_name
  domain   = var.domain
}

resource "google_certificate_manager_certificate" "this" {
  project  = var.project_id
  location = "global"
  name     = var.certificate_name

  managed {
    domains            = [var.domain]
    dns_authorizations = [google_certificate_manager_dns_authorization.this.id]
  }
}

resource "google_certificate_manager_certificate_map" "this" {
  project = var.project_id
  name    = var.certificate_map_name
}

resource "google_certificate_manager_certificate_map_entry" "this" {
  project      = var.project_id
  name         = var.certificate_map_entry_name
  map          = google_certificate_manager_certificate_map.this.name
  hostname     = var.domain
  certificates = [google_certificate_manager_certificate.this.id]
}

# Reserved global external IP. Created without an explicit address, so GCP
# assigned one (live value 34.49.216.194); the address is computed on import.
resource "google_compute_global_address" "this" {
  project = var.project_id
  name    = var.address_name
}

resource "google_compute_target_https_proxy" "this" {
  project = var.project_id
  name    = var.https_proxy_name
  url_map = google_compute_url_map.this.id
  # A target HTTPS proxy stores certificate_map as the versioned Certificate
  # Manager resource URL, not the bare `projects/.../certificateMaps/...` that
  # `.id` returns. Match that exact form so the post-import plan is a no-op.
  certificate_map = "https://certificatemanager.googleapis.com/v1/${google_certificate_manager_certificate_map.this.id}"
}

resource "google_compute_global_forwarding_rule" "this" {
  project    = var.project_id
  name       = var.forwarding_rule_name
  ip_address = google_compute_global_address.this.address
  port_range = "443"
  # Live forwarding rule is EXTERNAL (the backend is EXTERNAL_MANAGED); match
  # each resource's live scheme exactly so the import plan is a no-op.
  load_balancing_scheme = "EXTERNAL"
  network_tier          = "PREMIUM"
  target                = google_compute_target_https_proxy.this.id
}
