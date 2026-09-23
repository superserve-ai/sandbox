# The legacy staging VMD still uses superserve-api while it drains. Keep that
# identity's host grants intact and give Cloud Run its own runtime principal.
resource "google_service_account" "controlplane_runtime" {
  project      = local.project_id
  account_id   = "superserve-cp-staging"
  display_name = "Superserve staging control plane"
  description  = "Cloud Run control plane for the staging cell; never attach to a VMD host."
}

resource "google_project_iam_member" "controlplane_metric_writer" {
  project = local.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.controlplane_runtime.email}"
}

# The image-only deploy workflow authenticates as the environment's GitHub
# Actions identity. Scope act-as to this runtime identity instead of granting
# a project-wide service-account user role.
resource "google_service_account_iam_member" "controlplane_deploy_act_as" {
  service_account_id = google_service_account.controlplane_runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${module.iam.service_account_emails["superserve_github_actions"]}"
}

# The rollout verifier impersonates the runtime identity for permission probes.
# Keep credential minting scoped to this serving identity; act-as alone cannot
# execute those probes.
resource "google_service_account_iam_member" "controlplane_deploy_token_creator" {
  service_account_id = google_service_account.controlplane_runtime.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${module.iam.service_account_emails["superserve_github_actions"]}"
}

locals {
  controlplane_secret_ids = toset([
    coalesce(var.sandbox_access_token_seed_secret_name, "sandbox-access-token-seed-${local.resource_suffix}"),
    coalesce(var.secrets_signing_key_secret_name, "secretsproxy-signing-key-${local.resource_suffix}"),
    coalesce(var.database_url_secret_name, "database-url-${local.resource_suffix}"),
    coalesce(var.internal_api_token_secret_name, "internal-api-token-${local.resource_suffix}"),
    coalesce(var.system_team_id_secret_name, "system-team-id-${local.resource_suffix}"),
    google_secret_manager_secret.stripe_secret_key.secret_id,
    google_secret_manager_secret.stripe_webhook_secret.secret_id,
    google_secret_manager_secret.stripe_meter_error_webhook_secret.secret_id,
  ])
}

resource "google_secret_manager_secret_iam_member" "controlplane_runtime" {
  for_each = local.controlplane_secret_ids

  project   = local.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.controlplane_runtime.email}"
}

locals {
  controlplane_identity_contract = {
    environment             = local.environment
    region                  = local.region
    runtime_service_account = google_service_account.controlplane_runtime.email
    legacy_runtime_account  = module.iam.service_account_emails["superserve_api"]
    deployment_identity     = module.iam.service_account_emails["superserve_github_actions"]
    deployment_permissions  = ["iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken"]
    backup_bucket           = module.backup_storage.bucket_name
    backup_object_prefix    = module.backup_storage.contract.reader_object_prefix
    backup_object_prefixes  = module.backup_storage.contract.reader_object_prefixes
    backup_permissions      = ["storage.objects.get", "storage.objects.list"]
    secret_ids              = sort(tolist(local.controlplane_secret_ids))
    kms_key_resource        = null
    kms_grant_owner         = "central KMS policy owner (out-of-band)"
    host_identity_unchanged = module.iam.service_account_emails["superserve_api"]
    host_identities_unchanged = [
      module.iam.service_account_emails["superserve_api"],
      google_service_account.vmd_runtime.email,
    ]
  }
}
