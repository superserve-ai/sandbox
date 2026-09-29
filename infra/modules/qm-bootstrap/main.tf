terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "= 8.2.0"
    }
  }
}

locals {
  identities = toset(["qm-infra", "qm-api-deployer", "qm-provisioner-deployer", "qm-api", "qm-provisioner"])
  services = toset([
    "cloudresourcemanager.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com",
    "sts.googleapis.com", "serviceusage.googleapis.com", "compute.googleapis.com",
    "run.googleapis.com", "sqladmin.googleapis.com", "servicenetworking.googleapis.com",
    "secretmanager.googleapis.com", "storage.googleapis.com", "logging.googleapis.com",
    "monitoring.googleapis.com", "dns.googleapis.com",
  ])
  service_agents = toset(["run.googleapis.com"])
  platform_services = { for pair in setproduct(var.regions, ["qm-api", "qm-provisioner"]) :
    "${pair[0]}/${pair[1]}" => { region = pair[0], name = pair[1] }
  }
  platform_secrets = {
    qm-platform-api-control-db         = "qm-api"
    qm-platform-api-auth               = "qm-api"
    qm-platform-provisioner-control-db = "qm-provisioner"
  }
}

resource "google_project" "qm" {
  project_id          = var.project_id
  name                = var.project_id
  folder_id           = var.folder_id
  billing_account     = var.billing_account
  auto_create_network = false
  deletion_policy     = "PREVENT"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_service" "enabled" {
  for_each           = local.services
  project            = google_project.qm.project_id
  service            = each.key
  disable_on_destroy = false
}

resource "google_project_service_identity" "agent" {
  provider   = google-beta
  for_each   = local.service_agents
  project    = google_project.qm.project_id
  service    = each.key
  depends_on = [google_project_service.enabled]
}

resource "google_service_account" "platform" {
  for_each     = local.identities
  project      = google_project.qm.project_id
  account_id   = each.key
  display_name = each.key
  depends_on   = [google_project_service.enabled]
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_tags_tag_key" "protected" {
  parent     = "projects/${google_project.qm.number}"
  short_name = "qm-protected"
  depends_on = [google_project_service.enabled]
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_tags_tag_value" "protected" {
  parent     = google_tags_tag_key.protected.id
  short_name = "platform"
  lifecycle {
    prevent_destroy = true
  }
}

// Service agents are Google-owned and do not inherit this project's tags.
resource "google_tags_tag_key" "account_scope" {
  parent     = "projects/${google_project.qm.number}"
  short_name = "qm-account-scope"
  depends_on = [google_project_service.enabled]
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_tags_tag_value" "account_scope" {
  parent     = google_tags_tag_key.account_scope.id
  short_name = "tenant-project"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_tags_tag_binding" "account_scope" {
  parent    = "//cloudresourcemanager.googleapis.com/projects/${google_project.qm.number}"
  tag_value = google_tags_tag_value.account_scope.id
  lifecycle {
    prevent_destroy = true
  }
}

locals {
  protected_accounts = merge(
    { for name, account in google_service_account.platform : name => account.email },
    {
      compute = "${google_project.qm.number}-compute@developer.gserviceaccount.com"
    }
  )
}

resource "google_tags_tag_binding" "account" {
  for_each   = local.protected_accounts
  parent     = "//iam.googleapis.com/projects/${google_project.qm.project_id}/serviceAccounts/${each.value}"
  tag_value  = google_tags_tag_value.protected.id
  depends_on = [google_project_service.enabled]
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_tags_location_tag_binding" "service" {
  for_each  = var.platform_services_ready ? local.platform_services : {}
  parent    = "//run.googleapis.com/projects/${google_project.qm.project_id}/locations/${each.value.region}/services/${each.value.name}"
  location  = each.value.region
  tag_value = google_tags_tag_value.protected.id
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket" "routine_state" {
  project                     = google_project.qm.project_id
  name                        = "${var.project_id}-terraform"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  depends_on                  = [google_project_service.enabled]
  versioning {
    enabled = true
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "routine_state" {
  bucket = google_storage_bucket.routine_state.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.platform["qm-infra"].email}"
}

resource "google_secret_manager_secret" "platform" {
  for_each  = merge(local.platform_secrets, { for id in var.cell_admin_secret_ids : id => "qm-provisioner" })
  project   = google_project.qm.project_id
  secret_id = each.key
  replication {
    auto {}
  }
  depends_on = [google_project_service.enabled]
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_secret_manager_secret_iam_member" "runtime" {
  for_each  = google_secret_manager_secret.platform
  project   = google_project.qm.project_id
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.platform[merge(local.platform_secrets, { for id in var.cell_admin_secret_ids : id => "qm-provisioner" })[each.key]].email}"
}

resource "google_project_default_service_accounts" "deprivilege" {
  project        = google_project.qm.project_id
  action         = "DEPRIVILEGE"
  restore_policy = "NONE"
  depends_on     = [google_project_service.enabled]
}

resource "google_artifact_registry_repository_iam_member" "pull" {
  for_each = merge(
    { run_agent = google_project_service_identity.agent["run.googleapis.com"].email },
    { for name in ["qm-api-deployer", "qm-provisioner-deployer", "qm-provisioner"] : name => google_service_account.platform[name].email }
  )
  project    = var.paired_project_id
  location   = var.registry.location
  repository = var.registry.repository
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${each.value}"
}
