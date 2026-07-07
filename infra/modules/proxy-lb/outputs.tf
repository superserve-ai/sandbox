output "contract" {
  description = "Planned proxy LB module inputs."
  value       = local.proxy_lb_contract
}

output "forwarding_rule_names" {
  description = "Requested forwarding rule names."
  value       = [for rule in values(google_compute_global_forwarding_rule.rules) : rule.name]
}

output "global_addresses" {
  description = "Global IP addresses keyed by logical name."
  value       = { for key, addr in google_compute_global_address.addresses : key => addr.address }
}
