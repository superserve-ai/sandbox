output "contract" {
  description = "Planned IAM module inputs."
  value       = local.iam_contract
}

output "service_account_ids" {
  description = "Requested service account IDs."
  value       = [for sa in values(var.service_accounts) : sa.account_id]
}

output "service_account_emails" {
  description = "Created service account emails keyed by logical name."
  value       = { for key, sa in google_service_account.service_accounts : key => sa.email }
}
