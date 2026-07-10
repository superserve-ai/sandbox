output "contract" {
  description = "Planned observability module inputs."
  value       = local.observability_contract
}

output "uptime_check_names" {
  description = "Requested uptime check names."
  value       = [for check in values(var.uptime_checks) : check.display_name]
}

output "dashboard_names" {
  description = "Created dashboard display names."
  value       = [for dashboard in values(var.dashboards) : dashboard.display_name]
}
