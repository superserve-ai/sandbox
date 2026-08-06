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
  description = "Compatibility alias for the pre-split singular Cloud IDS policy name; points at the HIGH and CRITICAL policy."
  value       = google_monitoring_alert_policy.ids_high_critical.name
}

output "alert_policy_names" {
  description = "Cloud IDS alert policy names keyed by severity band."
  value = {
    medium        = google_monitoring_alert_policy.ids_medium.name
    high_critical = google_monitoring_alert_policy.ids_high_critical.name
  }
}
