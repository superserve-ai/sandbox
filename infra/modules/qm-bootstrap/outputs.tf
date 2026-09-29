output "contract" {
  value = {
    version               = 1
    project_id            = google_project.qm.project_id
    project_number        = google_project.qm.number
    paired_project_id     = var.paired_project_id
    paired_project_number = var.paired_project_number
    regions               = var.regions
    identities            = { for name, account in google_service_account.platform : name => account.email }
    protected_tag = {
      key   = google_tags_tag_key.protected.id
      value = google_tags_tag_value.protected.id
    }
    # Retain the original output as a compatibility alias for infrastructure
    # consumers; application deployment must use the keyed map below.
    workload_identity_provider = google_iam_workload_identity_pool_provider.github.name
    workload_identity_providers = {
      terraform     = google_iam_workload_identity_pool_provider.github.name
      deploy_qm_api = google_iam_workload_identity_pool_provider.github_application.name
    }
    github_environments = { for name in ["qm-infra", "qm-api-deployer", "qm-provisioner-deployer"] :
      name => "${var.project_id}-${name}"
    }
    routine_state = {
      bucket = google_storage_bucket.routine_state.name
      prefix = "network"
    }
    registry = {
      project    = var.paired_project_id
      location   = var.registry.location
      repository = var.registry.repository
      pull_role  = "roles/artifactregistry.reader"
      pull_members = [
        "serviceAccount:${google_project_service_identity.agent["run.googleapis.com"].email}",
        "serviceAccount:${google_service_account.platform["qm-api-deployer"].email}",
        "serviceAccount:${google_service_account.platform["qm-provisioner-deployer"].email}",
        "serviceAccount:${google_service_account.platform["qm-provisioner"].email}",
      ]
    }
    platform_secret_ids = { for id, secret in google_secret_manager_secret.platform : id => secret.id }
    services            = local.platform_services
    runtime = {
      image_format           = "${var.registry.location}-docker.pkg.dev/${var.paired_project_id}/${var.registry.repository}/IMAGE@sha256:DIGEST"
      api_identity           = google_service_account.platform["qm-api"].email
      provisioner_identity   = google_service_account.platform["qm-provisioner"].email
      tenant_account_prefix  = "qm-tenant-"
      tenant_secret_prefix   = "qm-tenant-"
      tenant_bucket_prefix   = "${var.project_id}-tenant-"
      control_database_owner = "central-control-infrastructure"
      placement_authority    = "persisted tenant_id/db_cell_id allocation"
    }
    provisioning_enabled    = var.provisioning_enabled
    platform_services_ready = var.platform_services_ready
  }
}
