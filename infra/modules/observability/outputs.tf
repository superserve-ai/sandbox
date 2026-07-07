output "contract" {
  description = "Planned observability module inputs."
  value       = local.observability_contract
}

output "uptime_check_names" {
  description = "Requested uptime check names."
  value       = [for check in values(var.uptime_checks) : check.display_name]
}
