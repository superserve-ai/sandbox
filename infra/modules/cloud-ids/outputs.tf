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
  description = "Compatibility alias for the singular Cloud IDS policy name; points at the routine triage policy."
  value       = google_monitoring_alert_policy.ids_triage.name
}

output "alert_policy_names" {
  description = "Compatibility severity-band aliases; both refer to the same routine triage policy."
  value = {
    medium        = google_monitoring_alert_policy.ids_triage.name
    high_critical = google_monitoring_alert_policy.ids_triage.name
  }
}
