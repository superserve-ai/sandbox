# Fleet-wide lifecycle paging is owned by this static us-central1 root alongside
# the production fleet dashboards. us-central1 identifies the Terraform state
# owner only; the underlying Managed Prometheus metrics span the project. The
# policies are intentionally not instantiated in each regional root, because
# duplicating them would create duplicate incidents.
module "sandbox_lifecycle_alerts" {
  source = "../../../modules/observability"

  project_id               = local.project_id
  environment              = local.environment
  notification_channel_ids = var.notification_channel_ids
  labels                   = local.common_labels

  lifecycle_latency_alerts = {
    create = {
      latency_seconds = 15
      quantile        = 0.33
    }
    resume = {
      latency_seconds = 15
      quantile        = 0.33
    }
    pause = {
      latency_seconds = 15
      quantile        = 0.33
    }
    delete = {
      latency_seconds = 15
      quantile        = 0.33
    }
  }

  failed_sandbox_alert_enabled = true
}
