module "billing_alerts" {
  source = "../../../modules/billing-alerts"

  project_id               = local.project_id
  environment              = local.environment
  labels                   = local.common_labels
  notification_channel_ids = var.notification_channel_ids
  cells = {
    staging = {
      metric_location         = "us-central1-a"
      cloud_run_service       = "superserve-api"
      cloud_run_region        = "us-central1"
      coverage_checks_enabled = false
    }
  }
}
