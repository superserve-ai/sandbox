output "contract" {
  description = "Planned network module inputs."
  value       = local.network_contract
}

output "network_name" {
  description = "Requested VPC name."
  value       = local.network_name
}

output "vpc_connector_name" {
  description = "Requested VPC connector name."
  value       = try(google_vpc_access_connector.this[0].name, null)
}

output "network_self_link" {
  description = "VPC self link."
  value       = local.network_self_link
}

output "subnetwork_self_link" {
  description = "Primary subnetwork self link."
  value       = google_compute_subnetwork.primary.self_link
}

output "subnetwork_name" {
  description = "Primary subnetwork name."
  value       = google_compute_subnetwork.primary.name
}

output "vpc_connector_id" {
  description = "VPC connector resource ID."
  value       = try(google_vpc_access_connector.this[0].id, null)
}

output "vpc_connector_subnetwork_name" {
  description = "Managed connector/direct-VPC subnetwork name, when this module manages one."
  value       = try(google_compute_subnetwork.connector[0].name, null)
}

output "vpc_connector_subnetwork_self_link" {
  description = "Managed connector/direct-VPC subnetwork self link, when this module manages one."
  value       = try(google_compute_subnetwork.connector[0].self_link, null)
}
