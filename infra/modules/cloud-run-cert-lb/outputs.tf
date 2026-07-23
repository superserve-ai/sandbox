output "address" {
  description = "Global load balancer IPv4 address."
  value       = google_compute_global_address.this.address
}

output "certificate_map_id" {
  description = "Certificate Manager certificate map resource ID."
  value       = google_certificate_manager_certificate_map.this.id
}

output "dns_authorization" {
  description = "DNS authorization record the domain must be delegated to for cert issuance."
  value = {
    name        = google_certificate_manager_dns_authorization.this.name
    record_data = try(google_certificate_manager_dns_authorization.this.dns_resource_record[0], null)
  }
}
