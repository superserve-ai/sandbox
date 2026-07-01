output "contract" {
  description = "Rendered Cloud Run load balancer contract."
  value       = local.contract
}

output "address" {
  description = "Global load balancer IPv4 address."
  value       = google_compute_global_address.this.address
}

output "host_routes" {
  description = "Hostname to backend key route map."
  value       = var.host_routes
}
