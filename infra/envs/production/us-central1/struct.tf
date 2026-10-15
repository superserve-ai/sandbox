locals {
  struct_roles = toset([
    "roles/cloudasset.viewer",
    "roles/cloudsql.viewer",
    "roles/compute.viewer",
    "roles/container.clusterViewer",
    "roles/logging.configWriter",
    "roles/logging.privateLogViewer",
    "roles/logging.viewAccessor",
    "roles/logging.viewer",
    "roles/monitoring.alertPolicyEditor",
    "roles/monitoring.notificationChannelEditor",
    "roles/monitoring.viewer",
    "roles/run.viewer",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

module "struct_iam" {
  source = "../../../modules/iam"

  project_id  = local.project_id
  environment = local.environment
  service_accounts = {
    struct = {
      account_id   = "struct"
      display_name = "Struct"
    }
  }
  project_bindings = {
    for role in local.struct_roles : role => {
      role    = role
      members = ["serviceAccount:struct@${local.project_id}.iam.gserviceaccount.com"]
    }
  }
  labels = local.common_labels
}
