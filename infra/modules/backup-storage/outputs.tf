output "contract" {
  description = "Planned backup storage module inputs."
  value       = local.backup_storage_contract
}

output "bucket_name" {
  description = "Backup bucket name."
  value       = google_storage_bucket.backup.name
}

output "bucket_url" {
  description = "Backup bucket URL."
  value       = google_storage_bucket.backup.url
}

output "gc_service_account_email" {
  description = "Email of the dedicated GC service account."
  value       = google_service_account.gc.email
}
