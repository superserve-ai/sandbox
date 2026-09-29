locals {
  roles = {
    network = [
      "compute.networks.create", "compute.networks.get", "compute.networks.updatePolicy", "compute.networks.delete",
      "compute.networks.use",
      "compute.subnetworks.create", "compute.subnetworks.get", "compute.subnetworks.update", "compute.subnetworks.delete",
      "compute.subnetworks.setPrivateIpGoogleAccess", "compute.subnetworks.use",
      "compute.firewalls.create", "compute.firewalls.get", "compute.firewalls.update", "compute.firewalls.delete",
      "compute.routers.create", "compute.routers.get", "compute.routers.update", "compute.routers.delete",
      "compute.globalOperations.get", "compute.regionOperations.get", "resourcemanager.projects.get", "serviceusage.services.use",
    ]
    tenant_create = [
      "iam.serviceAccounts.create", "run.services.create", "secretmanager.secrets.create", "storage.buckets.create",
      "resourcemanager.projects.get", "serviceusage.services.use", "run.operations.get",
    ]
    tenant_accounts = [
      "iam.serviceAccounts.get", "iam.serviceAccounts.delete", "iam.serviceAccounts.update", "iam.serviceAccounts.actAs",
    ]
    tenant_services = [
      "run.services.get", "run.services.update", "run.services.delete", "run.services.getIamPolicy", "run.services.setIamPolicy",
    ]
    tenant_secrets = [
      "secretmanager.secrets.get", "secretmanager.secrets.update", "secretmanager.secrets.delete",
      "secretmanager.secrets.getIamPolicy", "secretmanager.secrets.setIamPolicy",
      "secretmanager.versions.add", "secretmanager.versions.get", "secretmanager.versions.list",
      "secretmanager.versions.access", "secretmanager.versions.enable", "secretmanager.versions.disable", "secretmanager.versions.destroy",
    ]
    tenant_buckets = [
      "storage.buckets.get", "storage.buckets.update", "storage.buckets.delete", "storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy",
      "storage.objects.get", "storage.objects.list", "storage.objects.create", "storage.objects.delete",
    ]
    deploy_observe = ["run.operations.get", "resourcemanager.projects.get", "serviceusage.services.use"]
    tenant_network = ["compute.subnetworks.use", "compute.subnetworks.get"]
    deploy_service = ["run.services.get", "run.services.update"]
  }
}

resource "google_project_iam_custom_role" "bounded" {
  for_each    = local.roles
  project     = google_project.qm.project_id
  role_id     = "qm_${each.key}"
  title       = "QM ${replace(each.key, "_", " ")}"
  permissions = each.value
  depends_on  = [google_project_service.enabled]
}

resource "google_project_iam_member" "network" {
  project = google_project.qm.project_id
  role    = google_project_iam_custom_role.bounded["network"].name
  member  = "serviceAccount:${google_service_account.platform["qm-infra"].email}"
}

resource "google_project_iam_member" "tenant_create" {
  count   = var.provisioning_enabled ? 1 : 0
  project = google_project.qm.project_id
  role    = google_project_iam_custom_role.bounded["tenant_create"].name
  member  = "serviceAccount:${google_service_account.platform["qm-provisioner"].email}"
  lifecycle {
    precondition {
      condition     = var.platform_services_ready
      error_message = "Create and protect every platform service before enabling tenant provisioning."
    }
  }
  depends_on = [google_tags_tag_binding.account_scope, google_tags_tag_binding.account, google_tags_location_tag_binding.service, google_project_default_service_accounts.deprivilege]
}

resource "google_project_iam_member" "tenant_untagged" {
  for_each = var.provisioning_enabled ? toset(["tenant_accounts", "tenant_services"]) : toset([])
  project  = google_project.qm.project_id
  role     = google_project_iam_custom_role.bounded[each.key].name
  member   = "serviceAccount:${google_service_account.platform["qm-provisioner"].email}"
  condition {
    title = each.key == "tenant_accounts" ? "local-unprotected-accounts" : "exclude-protected-platform"
    expression = each.key == "tenant_accounts" ? join(" && ", [
      "resource.matchTagId('${google_tags_tag_key.account_scope.id}', '${google_tags_tag_value.account_scope.id}')",
      "!resource.matchTagId('${google_tags_tag_key.protected.id}', '${google_tags_tag_value.protected.id}')",
    ]) : "!resource.matchTagId('${google_tags_tag_key.protected.id}', '${google_tags_tag_value.protected.id}')"
  }
  depends_on = [google_project_iam_member.tenant_create]
}

resource "google_project_iam_member" "tenant_secrets" {
  count   = var.provisioning_enabled ? 1 : 0
  project = google_project.qm.project_id
  role    = google_project_iam_custom_role.bounded["tenant_secrets"].name
  member  = "serviceAccount:${google_service_account.platform["qm-provisioner"].email}"
  condition {
    title      = "tenant-secret-namespace"
    expression = "resource.name.startsWith('projects/${google_project.qm.number}/secrets/qm-tenant-')"
  }
}

resource "google_project_iam_member" "tenant_buckets" {
  count   = var.provisioning_enabled ? 1 : 0
  project = google_project.qm.project_id
  role    = google_project_iam_custom_role.bounded["tenant_buckets"].name
  member  = "serviceAccount:${google_service_account.platform["qm-provisioner"].email}"
  condition {
    title      = "tenant-bucket-namespace"
    expression = "resource.name.startsWith('projects/_/buckets/${var.project_id}-tenant-')"
  }
}

resource "google_service_account_iam_member" "deploy_act_as" {
  for_each           = toset(["qm-api", "qm-provisioner"])
  service_account_id = google_service_account.platform[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.platform["${each.key}-deployer"].email}"
}

resource "google_cloud_run_v2_service_iam_member" "deploy" {
  for_each = var.platform_services_ready ? local.platform_services : {}
  project  = google_project.qm.project_id
  location = each.value.region
  name     = each.value.name
  role     = google_project_iam_custom_role.bounded["deploy_service"].name
  member   = "serviceAccount:${google_service_account.platform["${each.value.name}-deployer"].email}"
}

resource "google_project_iam_member" "deploy_operations" {
  for_each = toset(["qm-api-deployer", "qm-provisioner-deployer"])
  project  = google_project.qm.project_id
  role     = google_project_iam_custom_role.bounded["deploy_observe"].name
  member   = "serviceAccount:${google_service_account.platform[each.key].email}"
}

resource "google_compute_subnetwork_iam_member" "tenant_network" {
  for_each   = var.platform_services_ready ? var.regions : toset([])
  project    = google_project.qm.project_id
  region     = each.key
  subnetwork = "qm-tenant-${each.key}"
  role       = google_project_iam_custom_role.bounded["tenant_network"].name
  member     = "serviceAccount:${google_service_account.platform["qm-provisioner"].email}"
}
