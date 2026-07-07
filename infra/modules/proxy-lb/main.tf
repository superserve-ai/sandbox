terraform {
  required_version = ">= 1.5.0"
}

resource "google_compute_global_address" "addresses" {
  for_each = var.global_addresses

  project = var.project_id
  name    = each.value.name
}

resource "google_compute_instance_group" "unmanaged" {
  count = var.instance_group == null ? 0 : 1

  project   = var.project_id
  name      = var.instance_group.name
  zone      = var.instance_group.zone
  instances = try(var.instance_group.instances, [])

  dynamic "named_port" {
    for_each = var.instance_group.named_ports

    content {
      name = named_port.key
      port = named_port.value
    }
  }
}

resource "google_compute_health_check" "checks" {
  for_each = var.health_checks

  project             = var.project_id
  name                = each.value.name
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  dynamic "http_health_check" {
    for_each = upper(each.value.protocol) == "HTTP" ? [1] : []

    content {
      port         = each.value.port
      request_path = try(each.value.request_path, "/")
    }
  }

  dynamic "tcp_health_check" {
    for_each = upper(each.value.protocol) == "TCP" ? [1] : []

    content {
      port = each.value.port
    }
  }
}

resource "google_compute_backend_service" "services" {
  for_each = var.backend_services

  project                         = var.project_id
  name                            = each.value.name
  protocol                        = each.value.protocol
  load_balancing_scheme           = "EXTERNAL_MANAGED"
  port_name                       = each.value.port_name
  timeout_sec                     = each.value.timeout_sec
  connection_draining_timeout_sec = each.value.connection_draining_timeout
  health_checks = each.value.health_check == null ? [] : [
    google_compute_health_check.checks[each.value.health_check].id,
  ]

  dynamic "backend" {
    for_each = each.value.backend_type == "instance_group" ? [1] : []

    content {
      group = google_compute_instance_group.unmanaged[0].self_link
    }
  }
}

resource "google_certificate_manager_dns_authorization" "dns_authorizations" {
  for_each = var.dns_authorizations

  project  = var.project_id
  location = "global"
  name     = each.value.name
  domain   = each.value.domain
}

resource "google_certificate_manager_certificate" "certificates" {
  for_each = var.certificates

  project  = var.project_id
  location = "global"
  name     = each.value.name

  managed {
    domains = each.value.domains
    dns_authorizations = [
      for key in each.value.dns_authorization_keys :
      google_certificate_manager_dns_authorization.dns_authorizations[key].id
    ]
  }
}

resource "google_certificate_manager_certificate_map" "this" {
  count = var.certificate_map_name == null ? 0 : 1

  project = var.project_id
  name    = "projects/${var.project_id}/locations/global/certificateMaps/${var.certificate_map_name}"
}

resource "google_certificate_manager_certificate_map_entry" "entries" {
  for_each = var.certificate_map_name == null ? {} : var.certificate_map_entries

  project      = var.project_id
  name         = "projects/${var.project_id}/locations/global/certificateMaps/${var.certificate_map_name}/certificateMapEntries/${each.value.name}"
  map          = google_certificate_manager_certificate_map.this[0].name
  hostname     = each.value.hostname
  certificates = [google_certificate_manager_certificate.certificates[each.value.certificate_key].id]
}

resource "google_compute_target_tcp_proxy" "tcp" {
  for_each = {
    for key, rule in var.forwarding_rules : key => rule
    if rule.target_type == "target_tcp_proxy"
  }

  project         = var.project_id
  name            = each.value.name
  backend_service = google_compute_backend_service.services[each.key].self_link
  proxy_header    = "NONE"
}

resource "google_compute_target_ssl_proxy" "ssl" {
  for_each = {
    for key, rule in var.forwarding_rules : key => rule
    if rule.target_type == "target_ssl_proxy"
  }

  project         = var.project_id
  name            = each.value.name
  backend_service = google_compute_backend_service.services[each.key].self_link
  proxy_header    = "NONE"
  certificate_map = var.certificate_map_name == null ? null : google_certificate_manager_certificate_map.this[0].id
}

resource "google_compute_global_forwarding_rule" "rules" {
  for_each = var.forwarding_rules

  project               = var.project_id
  name                  = each.value.name
  ip_address            = google_compute_global_address.addresses[each.value.address_key].address
  port_range            = each.value.port
  load_balancing_scheme = each.value.load_balancing_scheme
  target                = each.value.target_type == "target_tcp_proxy" ? google_compute_target_tcp_proxy.tcp[each.key].self_link : google_compute_target_ssl_proxy.ssl[each.key].self_link
}

locals {
  proxy_lb_contract = {
    project_id           = var.project_id
    environment          = var.environment
    region               = var.region
    name                 = var.name
    global_addresses     = { for key, addr in google_compute_global_address.addresses : key => addr.address }
    forwarding_rules     = { for key, rule in google_compute_global_forwarding_rule.rules : key => rule.name }
    backend_services     = { for key, svc in google_compute_backend_service.services : key => svc.self_link }
    instance_group       = try(google_compute_instance_group.unmanaged[0].self_link, null)
    health_checks        = { for key, check in google_compute_health_check.checks : key => check.self_link }
    certificates         = { for key, cert in google_certificate_manager_certificate.certificates : key => cert.id }
    dns_authorizations   = { for key, auth in google_certificate_manager_dns_authorization.dns_authorizations : key => auth.id }
    certificate_map_name = try(google_certificate_manager_certificate_map.this[0].id, null)
    labels               = var.labels
  }
}
