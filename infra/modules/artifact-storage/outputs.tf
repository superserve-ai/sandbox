output "contract" {
  description = "Planned artifact and storage module inputs."
  value       = local.artifact_storage_contract
}

output "bucket_names" {
  description = "Requested bucket names."
  value       = [for bucket in values(google_storage_bucket.buckets) : bucket.name]
}
