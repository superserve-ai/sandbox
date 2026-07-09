terraform {
  required_version = ">= 1.5.0"
}

resource "google_monitoring_dashboard" "dashboards" {
  for_each = var.dashboards

  project        = var.project_id
  dashboard_json = each.value.definition
}

locals {
  observability_contract = {
    project_id         = var.project_id
    environment        = var.environment
    notification_email = var.notification_email
    log_buckets        = var.log_buckets
    uptime_checks      = var.uptime_checks
    alert_policies     = var.alert_policies
    dashboards         = var.dashboards
    labels             = var.labels
  }
}
