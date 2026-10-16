locals {
  telemetry_integration_roles = toset([
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

module "telemetry_integration_iam" {
  source = "../../../modules/iam"

  project_id  = local.project_id
  environment = local.environment
  service_accounts = {
    telemetry_integration = {
      account_id   = "telemetry-integration"
      display_name = "Telemetry Integration"
      description  = "External telemetry analysis and alert management."
    }
  }
  project_bindings = {
    for role in local.telemetry_integration_roles : role => {
      role    = role
      members = ["serviceAccount:telemetry-integration@${local.project_id}.iam.gserviceaccount.com"]
    }
  }
  labels = local.common_labels
}
