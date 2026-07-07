output "contract" {
  description = "Planned sandbox host module inputs."
  value       = local.sandbox_host_contract
}

output "instance_name" {
  description = "Requested instance name."
  value       = google_compute_instance.this.name
}

output "instance_self_link" {
  description = "Instance self link."
  value       = google_compute_instance.this.self_link
}

output "internal_ip" {
  description = "Instance internal IP."
  value       = try(google_compute_instance.this.network_interface[0].network_ip, null)
}
