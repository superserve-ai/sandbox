resource "google_service_account" "vmd_runtime" {
  project      = local.project_id
  account_id   = "vmd-runtime-production-usw2"
  display_name = "VMD runtime production-usw2"
}

resource "google_project_iam_member" "vmd_telemetry" {
  for_each = toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
  project  = local.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.vmd_runtime.email}"
}

# Only the dedicated cell identity can read for restore. The shared runtime
# retains its existing write-only grant; no runtime receives delete access.
resource "google_storage_bucket_iam_member" "vmd_backup" {
  for_each = toset(["roles/storage.objectCreator", "roles/storage.objectViewer"])
  bucket   = module.backup_storage.bucket_name
  role     = each.value
  member   = "serviceAccount:${google_service_account.vmd_runtime.email}"
}

module "peer_identity" {
  source        = "../../../modules/peer-identity"
  project_id    = local.project_id
  region        = local.region
  cell          = "production-usw2"
  instance_name = module.sandbox_host_b.instance_name
  instance_id   = module.sandbox_host_b.instance_id
  internal_ip   = module.sandbox_host_b.internal_ip
  zone          = local.zone
  host_id       = "usw2-2"
  runtime_email = google_service_account.vmd_runtime.email
}

output "host2_peer_bootstrap" {
  description = "Terraform-owned input to deploy/bootstrap-host2.py; contains no private keys."
  value       = module.peer_identity.bootstrap
}

resource "google_service_account_iam_member" "vmd_deploy_act_as" {
  service_account_id = google_service_account.vmd_runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_service_account.github_actions.email}"
}
