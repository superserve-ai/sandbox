output "endpoint_name" {
  description = "Cloud IDS endpoint name."
  value       = google_cloud_ids_endpoint.this.name
}

output "endpoint_forwarding_rule" {
  description = "Cloud IDS endpoint forwarding rule."
  value       = google_cloud_ids_endpoint.this.endpoint_forwarding_rule
}

output "packet_mirroring_name" {
  description = "Packet mirroring policy name."
  value       = google_compute_packet_mirroring.this.name
}

output "alert_policy_name" {
  description = "Cloud IDS alert policy name."
  value       = google_monitoring_alert_policy.ids_threats.name
}
