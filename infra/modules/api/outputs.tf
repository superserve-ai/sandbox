output "contract" {
  description = "Planned API module inputs."
  value       = local.api_contract
}

output "service_name" {
  description = "Requested Cloud Run service name."
  value       = google_cloud_run_v2_service.this.name
}

output "service_uri" {
  description = "Planned Cloud Run service URI."
  value       = google_cloud_run_v2_service.this.uri
}
